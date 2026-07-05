<#
.SYNOPSIS
    Shared helpers for CAPVisualizer: authentication, throttling-aware Graph
    reads, name resolution, hashing.

.NOTES
    CAPVisualizer is READ-ONLY: it never modifies tenant data. No create,
    update, or delete calls are made. The only POST used is the read-only
    directoryObjects/getByIds name-lookup (optional, opt-in). It depends only on
    the Microsoft.Graph.Authentication module and uses Invoke-MgGraphRequest for
    all reads, keeping the dependency and permission footprint minimal.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Read-only Graph base. Beta is only used where a feature is beta-only.
$script:CapGraphV1   = 'https://graph.microsoft.com/v1.0'
$script:CapGraphBeta = 'https://graph.microsoft.com/beta'

function Write-CapLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'OK')][string]$Level = 'INFO'
    )
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $color = switch ($Level) {
        'OK'    { 'Green' }
        'WARN'  { 'Yellow' }
        'ERROR' { 'Red' }
        default { 'Cyan' }
    }
    Write-Host "[$ts] [$Level] $Message" -ForegroundColor $color
}

function Open-CapBrowser {
<#
.SYNOPSIS
    Best-effort, cross-platform "open this URL in the default browser". Never
    throws: if no opener is available the caller can still copy the URL from the
    terminal.
#>
    param([Parameter(Mandatory)][string]$Url)
    try {
        if ($IsWindows) {
            Start-Process $Url | Out-Null
        }
        elseif ($IsMacOS) {
            & '/usr/bin/open' $Url 2>$null
        }
        elseif ($IsLinux) {
            if (Get-Command xdg-open -ErrorAction SilentlyContinue) { & xdg-open $Url 2>$null }
        }
        else {
            Start-Process $Url | Out-Null
        }
    }
    catch {
        Write-CapLog "Could not auto-open the browser ($($_.Exception.Message)). Copy the URL above." 'WARN'
    }
}

function Connect-CapGraph {
<#
.SYNOPSIS
    Connect to Microsoft Graph read-only, either interactively (delegated) or
    with an app registration (certificate or client secret) for unattended runs.

.PARAMETER Scopes
    Delegated scopes to request for interactive sign-in. Defaults to the minimal
    read-only Policy.Read.All.

.PARAMETER TenantId
    Tenant id (GUID or domain). Required for app-based auth.

.PARAMETER ClientId
    App registration (client) id for app-based auth.

.PARAMETER CertificateThumbprint
    Thumbprint of a certificate in the local store for app-based auth.

.PARAMETER ClientSecret
    Client secret (SecureString) for app-based auth. Certificate is preferred.

.PARAMETER UseWebBrowser
    Interactive sign-in only. Use the classic system-browser (authorization code)
    flow instead of the default device-code flow. The device-code flow prints a
    copy/paste sign-in URL and code in the terminal AND auto-opens the browser.
#>
    [CmdletBinding(DefaultParameterSetName = 'Interactive')]
    param(
        [Parameter(ParameterSetName = 'Interactive')]
        [string[]]$Scopes = @('Policy.Read.All'),

        [Parameter(ParameterSetName = 'Interactive')]
        [switch]$UseWebBrowser,

        [Parameter(Mandatory, ParameterSetName = 'AppCert')]
        [Parameter(Mandatory, ParameterSetName = 'AppSecret')]
        [string]$TenantId,

        [Parameter(Mandatory, ParameterSetName = 'AppCert')]
        [Parameter(Mandatory, ParameterSetName = 'AppSecret')]
        [string]$ClientId,

        [Parameter(Mandatory, ParameterSetName = 'AppCert')]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory, ParameterSetName = 'AppSecret')]
        [System.Security.SecureString]$ClientSecret
    )

    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw "Microsoft.Graph.Authentication module is not installed. Run scripts/Test-Prerequisites.ps1."
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    switch ($PSCmdlet.ParameterSetName) {
        'AppCert' {
            Write-CapLog "Connecting to Graph (app + certificate) tenant $TenantId" 'INFO'
            Connect-MgGraph -TenantId $TenantId -ClientId $ClientId `
                -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
        }
        'AppSecret' {
            Write-CapLog "Connecting to Graph (app + secret) tenant $TenantId" 'INFO'
            $cred = [System.Management.Automation.PSCredential]::new($ClientId, $ClientSecret)
            Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $cred -NoWelcome -ErrorAction Stop
        }
        default {
            Write-CapLog "Connecting to Graph (interactive) scopes: $($Scopes -join ', ')" 'INFO'
            if ($UseWebBrowser) {
                Connect-MgGraph -Scopes $Scopes -NoWelcome -ErrorAction Stop
            }
            else {
                # Device-code flow: prints a copy/paste sign-in URL + code in the
                # terminal, and we also auto-open the browser to that page.
                $deviceUrl = 'https://microsoft.com/devicelogin'
                Write-CapLog "Device-code sign-in. Sign-in URL (copy/paste if the browser does not open): $deviceUrl" 'INFO'
                Write-CapLog "The one-time code is printed below; enter it on that page." 'INFO'
                Open-CapBrowser -Url $deviceUrl
                Connect-MgGraph -Scopes $Scopes -UseDeviceAuthentication -NoWelcome -ErrorAction Stop
            }
        }
    }

    $ctx = Get-MgContext
    if (-not $ctx) { throw "Failed to establish a Microsoft Graph context." }
    Write-CapLog "Connected. Tenant: $($ctx.TenantId)  Account/App: $($ctx.Account ?? $ctx.ClientId)" 'OK'
    return $ctx
}

function Invoke-CapGraphGet {
<#
.SYNOPSIS
    READ-ONLY GET against Microsoft Graph with automatic paging and
    throttling-aware retry (honours Retry-After, exponential backoff).

.PARAMETER Uri
    Absolute Graph URI or a path relative to the v1.0 (or beta) root.

.PARAMETER Beta
    Resolve a relative path against the beta endpoint instead of v1.0.

.OUTPUTS
    For collections, the flattened array of 'value' items across all pages.
    For single objects, the object itself.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [switch]$Beta,
        [int]$MaxRetries = 6
    )

    if ($Uri -notmatch '^https?://') {
        $root = if ($Beta) { $script:CapGraphBeta } else { $script:CapGraphV1 }
        $Uri = "$root/$($Uri.TrimStart('/'))"
    }

    $results = [System.Collections.Generic.List[object]]::new()
    $isCollection = $false
    $next = $Uri

    while ($next) {
        $attempt = 0
        $response = $null
        while ($true) {
            try {
                $response = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject -ErrorAction Stop
                break
            }
            catch {
                $status = $null
                try { $status = [int]$_.Exception.Response.StatusCode } catch { }
                if (($status -eq 429 -or $status -ge 500) -and $attempt -lt $MaxRetries) {
                    $retryAfter = 0
                    try { $retryAfter = [int]$_.Exception.Response.Headers.RetryAfter.Delta.TotalSeconds } catch { }
                    if ($retryAfter -le 0) { $retryAfter = [math]::Min([math]::Pow(2, $attempt), 60) }
                    Write-CapLog "Graph throttled/transient ($status). Retry $($attempt + 1)/$MaxRetries after ${retryAfter}s." 'WARN'
                    Start-Sleep -Seconds $retryAfter
                    $attempt++
                    continue
                }
                throw
            }
        }

        if ($null -ne $response -and ($response.PSObject.Properties.Name -contains 'value')) {
            $isCollection = $true
            foreach ($item in $response.value) { $results.Add($item) }
            $nextProp = $response.PSObject.Properties['@odata.nextLink']
            $next = if ($nextProp) { $nextProp.Value } else { $null }
        }
        else {
            return $response
        }
    }

    if ($isCollection) { return $results.ToArray() }
    return @()
}

function ConvertTo-CapHashtable {
<#
.SYNOPSIS
    Deep-convert a PSObject graph into ordered hashtables/arrays for stable
    JSON serialization (preserves nesting, drops odata annotations if asked).
#>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]$InputObject,
        [switch]$StripODataAnnotations
    )
    process {
        if ($null -eq $InputObject) { return $null }
        if ($InputObject -is [string] -or $InputObject.GetType().IsPrimitive -or
            $InputObject -is [datetime] -or $InputObject -is [bool]) {
            return $InputObject
        }
        if ($InputObject -is [System.Collections.IDictionary]) {
            $ht = [ordered]@{}
            foreach ($k in $InputObject.Keys) {
                if ($StripODataAnnotations -and "$k" -like '@odata*') { continue }
                $ht["$k"] = ConvertTo-CapHashtable -InputObject $InputObject[$k] -StripODataAnnotations:$StripODataAnnotations
            }
            return $ht
        }
        if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
            return @($InputObject | ForEach-Object { ConvertTo-CapHashtable -InputObject $_ -StripODataAnnotations:$StripODataAnnotations })
        }
        if ($InputObject.PSObject) {
            $ht = [ordered]@{}
            foreach ($p in $InputObject.PSObject.Properties) {
                if ($StripODataAnnotations -and $p.Name -like '@odata*') { continue }
                $ht[$p.Name] = ConvertTo-CapHashtable -InputObject $p.Value -StripODataAnnotations:$StripODataAnnotations
            }
            return $ht
        }
        return $InputObject
    }
}

function Get-CapFileSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Save-CapJson {
<#
.SYNOPSIS
    Serialize an object to UTF-8 JSON (no BOM) at depth suitable for CA policies.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$InputObject,
        [Parameter(Mandatory)][string]$Path,
        [int]$Depth = 30
    )
    $json = $InputObject | ConvertTo-Json -Depth $Depth
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    [System.IO.File]::WriteAllText($Path, $json, [System.Text.UTF8Encoding]::new($false))
}

function Get-CapDirectoryNameMap {
<#
.SYNOPSIS
    OPTIONAL. Resolve directory object GUIDs (users, groups, service principals,
    directory roles) to friendly display names. Requires additional read-only
    scopes (Directory.Read.All or the narrower per-type scopes) and is only
    called when the caller opts in via -ResolveNames on the orchestrator.

.PARAMETER Ids
    Distinct set of object ids to resolve.

.OUTPUTS
    Hashtable of id -> display name (best effort; unresolved ids are omitted).
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$Ids)

    $map = @{}
    $distinct = @($Ids | Where-Object { $_ -and ($_ -match '^[0-9a-fA-F-]{36}$') } | Sort-Object -Unique)
    if (-not $distinct.Count) { return $map }

    # getByIds resolves mixed directory object types in batches of up to 1000.
    $batchSize = 900
    for ($i = 0; $i -lt $distinct.Count; $i += $batchSize) {
        $batch = @($distinct[$i..([math]::Min($i + $batchSize - 1, $distinct.Count - 1))])
        $body = @{ ids = @($batch); types = @('user', 'group', 'servicePrincipal', 'directoryRole', 'application') }
        try {
            $resp = Invoke-MgGraphRequest -Method POST -Uri "$script:CapGraphV1/directoryObjects/getByIds" `
                -Body ($body | ConvertTo-Json) -OutputType PSObject -ErrorAction Stop
            foreach ($o in $resp.value) {
                $idProp   = $o.PSObject.Properties['id']
                $dnProp   = $o.PSObject.Properties['displayName']
                $upnProp  = $o.PSObject.Properties['userPrincipalName']
                $id   = if ($idProp) { $idProp.Value } else { $null }
                $name = if ($dnProp -and $dnProp.Value) { $dnProp.Value } elseif ($upnProp) { $upnProp.Value } else { $null }
                if ($id -and $name) { $map[$id] = $name }
            }
        }
        catch {
            Write-CapLog "Name resolution batch failed (continuing without names): $($_.Exception.Message)" 'WARN'
        }
    }
    return $map
}

function Get-CapRoleTemplateMap {
<#
.SYNOPSIS
    OPTIONAL. Map directory role template ids (used by CA includeRoles /
    excludeRoles) to role display names. Requires a read-only directory scope
    (Directory.Read.All or RoleManagement.Read.Directory).
#>
    [CmdletBinding()]
    param()
    $map = @{}
    try {
        $templates = @(Invoke-CapGraphGet -Uri 'directoryRoleTemplates')
        foreach ($t in $templates) {
            $idP = $t.PSObject.Properties['id']; $dnP = $t.PSObject.Properties['displayName']
            if ($idP -and $dnP -and $dnP.Value) { $map[$idP.Value] = $dnP.Value }
        }
    }
    catch { Write-CapLog "Role template resolution failed (continuing): $($_.Exception.Message)" 'WARN' }
    return $map
}

function Get-CapServicePrincipalMap {
<#
.SYNOPSIS
    OPTIONAL. Map application (client) appId GUIDs (used by CA
    includeApplications / excludeApplications) to service principal display
    names. Requires a read-only directory scope (Directory.Read.All or
    Application.Read.All).

.PARAMETER AppIds
    Distinct appId GUIDs referenced by the policy set.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$AppIds)

    $map = @{}
    $distinct = @($AppIds | Where-Object { $_ -and ($_ -match '^[0-9a-fA-F-]{36}$') } | Sort-Object -Unique)
    if (-not $distinct.Count) { return $map }

    # Query by appId in small batches to keep the URL length bounded. Uses
    # chained 'eq ... or' which works without ConsistencyLevel headers.
    $batchSize = 15
    for ($i = 0; $i -lt $distinct.Count; $i += $batchSize) {
        $batch = @($distinct[$i..([math]::Min($i + $batchSize - 1, $distinct.Count - 1))])
        $filter = ($batch | ForEach-Object { "appId eq '$_'" }) -join ' or '
        $uri = "servicePrincipals?`$select=appId,displayName&`$filter=$([uri]::EscapeDataString($filter))"
        try {
            $sps = @(Invoke-CapGraphGet -Uri $uri)
            foreach ($sp in $sps) {
                $aP = $sp.PSObject.Properties['appId']; $dP = $sp.PSObject.Properties['displayName']
                if ($aP -and $dP -and $dP.Value) { $map[$aP.Value] = $dP.Value }
            }
        }
        catch { Write-CapLog "Service principal resolution batch failed (continuing): $($_.Exception.Message)" 'WARN' }
    }
    return $map
}

function Get-CapWellKnownAppMap {
<#
.SYNOPSIS
    Static fallback names for well-known first-party Microsoft app ids that may
    be referenced by CA policies but not present as tenant service principals.
#>
    return @{
        '00000002-0000-0ff1-ce00-000000000000' = 'Office 365 Exchange Online'
        '00000003-0000-0ff1-ce00-000000000000' = 'Office 365 SharePoint Online'
        '00000003-0000-0000-c000-000000000000' = 'Microsoft Graph'
        '00000004-0000-0ff1-ce00-000000000000' = 'Skype for Business Online'
        '00000005-0000-0ff1-ce00-000000000000' = 'Microsoft Yammer'
        '00000006-0000-0ff1-ce00-000000000000' = 'Microsoft Office 365 Portal'
        '00000007-0000-0ff1-ce00-000000000000' = 'Microsoft Exchange Online Protection'
        '00000009-0000-0000-c000-000000000000' = 'Power BI Service'
        '0000000c-0000-0000-c000-000000000000' = 'Microsoft App Access Panel'
        '797f4846-ba00-4fd7-ba43-dac1f8f63013' = 'Windows Azure Service Management API'
        'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' = 'Microsoft Azure Portal'
        '04b07795-8ddb-461a-bbee-02f9e1bf7b46' = 'Microsoft Azure CLI'
        '05a65629-4c1b-48c1-a78b-804c4abdd4af' = 'Microsoft Azure CLI (legacy)'
        '1950a258-227b-4e31-a9cf-717495945fc2' = 'Microsoft Azure PowerShell'
        '1fec8e78-bce4-4aaf-ab1b-5451cc387264' = 'Microsoft Teams'
        'd3590ed6-52b3-4102-aeff-aad2292ab01c' = 'Microsoft Office'
        '871c010f-5e61-4fb1-83ac-98610a7e9110' = 'Microsoft Power BI'
        '00000007-0000-0000-c000-000000000000' = 'Microsoft Dataverse'
        '3090ab82-f1c1-4cdf-af2c-5d7a6f3e2cc7' = 'Microsoft Defender for Cloud Apps'
        '74bcdadc-2fdc-4bb3-8459-76d06952a0e9' = 'Microsoft Intune Web Company Portal'
        '89bee1f7-5e6e-4d8a-9f3d-ecd601259da7' = 'Office 365 (portal.office.com)'
    }
}

Export-ModuleMember -Function Write-CapLog, Connect-CapGraph, Invoke-CapGraphGet, `
    ConvertTo-CapHashtable, Get-CapFileSha256, Save-CapJson, Get-CapDirectoryNameMap, `
    Get-CapRoleTemplateMap, Get-CapServicePrincipalMap, Get-CapWellKnownAppMap
