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
#>
    [CmdletBinding(DefaultParameterSetName = 'Interactive')]
    param(
        [Parameter(ParameterSetName = 'Interactive')]
        [string[]]$Scopes = @('Policy.Read.All'),

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
            Connect-MgGraph -Scopes $Scopes -NoWelcome -ErrorAction Stop
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
            $next = $response.'@odata.nextLink'
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
        if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
            return @($InputObject | ForEach-Object { ConvertTo-CapHashtable -InputObject $_ -StripODataAnnotations:$StripODataAnnotations })
        }
        if ($InputObject -is [System.Collections.IDictionary]) {
            $ht = [ordered]@{}
            foreach ($k in $InputObject.Keys) {
                if ($StripODataAnnotations -and "$k" -like '@odata*') { continue }
                $ht["$k"] = ConvertTo-CapHashtable -InputObject $InputObject[$k] -StripODataAnnotations:$StripODataAnnotations
            }
            return $ht
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
    $distinct = $Ids | Where-Object { $_ -and ($_ -match '^[0-9a-fA-F-]{36}$') } | Sort-Object -Unique
    if (-not $distinct) { return $map }

    # getByIds resolves mixed directory object types in batches of up to 1000.
    $batchSize = 900
    for ($i = 0; $i -lt $distinct.Count; $i += $batchSize) {
        $batch = $distinct[$i..([math]::Min($i + $batchSize - 1, $distinct.Count - 1))]
        $body = @{ ids = @($batch); types = @('user', 'group', 'servicePrincipal', 'directoryRole', 'application') }
        try {
            $resp = Invoke-MgGraphRequest -Method POST -Uri "$script:CapGraphV1/directoryObjects/getByIds" `
                -Body ($body | ConvertTo-Json) -OutputType PSObject -ErrorAction Stop
            foreach ($o in $resp.value) {
                $name = $o.displayName
                if (-not $name) { $name = $o.userPrincipalName }
                if ($o.id -and $name) { $map[$o.id] = $name }
            }
        }
        catch {
            Write-CapLog "Name resolution batch failed (continuing without names): $($_.Exception.Message)" 'WARN'
        }
    }
    return $map
}

Export-ModuleMember -Function Write-CapLog, Connect-CapGraph, Invoke-CapGraphGet, `
    ConvertTo-CapHashtable, Get-CapFileSha256, Save-CapJson, Get-CapDirectoryNameMap
