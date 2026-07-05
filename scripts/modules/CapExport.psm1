<#
.SYNOPSIS
    CAPVisualizer export module. Reads all Conditional Access policies and the
    dependent objects they reference (named locations, authentication strengths,
    authentication context class references) from Microsoft Graph, read-only.

.NOTES
    Requires an active Graph context (see CapCommon\Connect-CapGraph) with at
    least the read-only Policy.Read.All scope.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-CapExport {
<#
.SYNOPSIS
    Fetch CA policies plus dependencies and return a single export object.

.OUTPUTS
    [ordered] hashtable with keys: metadata, policies, namedLocations,
    authenticationStrengths, authenticationContexts.
#>
    [CmdletBinding()]
    param()

    Write-CapLog "Reading Conditional Access policies..." 'INFO'
    $policies = @(Invoke-CapGraphGet -Uri 'identity/conditionalAccess/policies')
    Write-CapLog "Found $($policies.Count) CA policies." 'OK'

    Write-CapLog "Reading named locations..." 'INFO'
    $namedLocations = @(Invoke-CapGraphGet -Uri 'identity/conditionalAccess/namedLocations')

    Write-CapLog "Reading authentication strength policies..." 'INFO'
    $authStrengths = @()
    try { $authStrengths = @(Invoke-CapGraphGet -Uri 'policies/authenticationStrengthPolicies') }
    catch { Write-CapLog "Auth strengths unavailable (continuing): $($_.Exception.Message)" 'WARN' }

    Write-CapLog "Reading authentication context references..." 'INFO'
    $authContexts = @()
    try { $authContexts = @(Invoke-CapGraphGet -Uri 'identity/conditionalAccess/authenticationContextClassReferences') }
    catch { Write-CapLog "Auth contexts unavailable (continuing): $($_.Exception.Message)" 'WARN' }

    $ctx = Get-MgContext
    $export = [ordered]@{
        metadata = [ordered]@{
            tool           = 'CAPVisualizer'
            schemaVersion  = '1.0'
            generatedUtc   = (Get-Date).ToUniversalTime().ToString('o')
            tenantId       = $ctx.TenantId
            account        = ($ctx.Account ?? $ctx.ClientId)
            authType       = $ctx.AuthType
            scopes         = @($ctx.Scopes)
            policyCount    = $policies.Count
        }
        policies                 = @($policies    | ForEach-Object { ConvertTo-CapHashtable -InputObject $_ })
        namedLocations           = @($namedLocations | ForEach-Object { ConvertTo-CapHashtable -InputObject $_ })
        authenticationStrengths  = @($authStrengths  | ForEach-Object { ConvertTo-CapHashtable -InputObject $_ })
        authenticationContexts   = @($authContexts   | ForEach-Object { ConvertTo-CapHashtable -InputObject $_ })
    }
    return $export
}

function Get-CapReferences {
<#
.SYNOPSIS
    Collect the distinct object references in a policy set, categorized by the
    lookup each needs: directory object ids (users/groups), role template ids
    (roles), and application appIds (apps).

.OUTPUTS
    [ordered] hashtable with keys UserGroupIds, RoleTemplateIds, AppIds.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Export)

    function _K { param($o, [string]$k) if ($null -eq $o) { return $null }; if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($k)) { return $o[$k] } else { return $null } }; $p = $o.PSObject.Properties[$k]; if ($p) { return $p.Value } else { return $null } }

    $userGroup = [System.Collections.Generic.HashSet[string]]::new()
    $roles     = [System.Collections.Generic.HashSet[string]]::new()
    $apps      = [System.Collections.Generic.HashSet[string]]::new()

    foreach ($p in $Export.policies) {
        $cond = _K $p 'conditions'
        $users = _K $cond 'users'
        foreach ($bucket in 'includeUsers','excludeUsers','includeGroups','excludeGroups') {
            foreach ($v in @(_K $users $bucket)) { if ("$v" -match '^[0-9a-fA-F-]{36}$') { [void]$userGroup.Add("$v") } }
        }
        foreach ($bucket in 'includeRoles','excludeRoles') {
            foreach ($v in @(_K $users $bucket)) { if ("$v" -match '^[0-9a-fA-F-]{36}$') { [void]$roles.Add("$v") } }
        }
        $appsCond = _K $cond 'applications'
        foreach ($bucket in 'includeApplications','excludeApplications') {
            foreach ($v in @(_K $appsCond $bucket)) { if ("$v" -match '^[0-9a-fA-F-]{36}$') { [void]$apps.Add("$v") } }
        }
        $clientApps = _K $cond 'clientApplications'
        foreach ($bucket in 'includeServicePrincipals','excludeServicePrincipals') {
            foreach ($v in @(_K $clientApps $bucket)) { if ("$v" -match '^[0-9a-fA-F-]{36}$') { [void]$apps.Add("$v") } }
        }
    }

    return [ordered]@{
        UserGroupIds    = @($userGroup)
        RoleTemplateIds = @($roles)
        AppIds          = @($apps)
    }
}

function Import-CapExportJson {
<#
.SYNOPSIS
    Load an existing JSON file and normalize it into the same export shape that
    Get-CapExport returns, WITHOUT any network calls. Enables fully-offline
    "render from JSON" runs (no Graph permissions required).

.DESCRIPTION
    Accepts, in order of preference:
      * A CAPVisualizer snapshot folder (uses its raw/export.json).
      * A CAPVisualizer export.json (has .metadata + .policies; may embed
        .nameMap / .namedLocations for offline name resolution).
      * A raw Microsoft Graph response: either a bare array of policy objects or
        an object with a .value array (e.g. output of
        `Get-MgIdentityConditionalAccessPolicy` / a Graph GET on
        identity/conditionalAccess/policies). Names will show as GUIDs unless the
        file also carries a nameMap.

.OUTPUTS
    [ordered] hashtable: metadata, policies, namedLocations,
    authenticationStrengths, authenticationContexts, nameMap.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $file = $Path
    if (Test-Path -LiteralPath $Path -PathType Container) {
        $candidate = Join-Path $Path 'raw/export.json'
        if (Test-Path -LiteralPath $candidate) { $file = $candidate }
        else { throw "Folder '$Path' does not contain raw/export.json." }
    }
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "JSON file not found: $file" }

    Write-CapLog "Loading policies from JSON: $file" 'INFO'
    $raw = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json -Depth 40 -AsHashtable

    function _K { param($o, [string]$k) if ($null -eq $o) { return $null }; if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($k)) { return $o[$k] } else { return $null } }; $p = $o.PSObject.Properties[$k]; if ($p) { return $p.Value } else { return $null } }

    $policies = $null
    $meta = $null
    $namedLocations = @()
    $authStrengths = @()
    $authContexts = @()
    $nameMap = @{}

    if ($raw -is [System.Collections.IDictionary] -and $raw.Contains('policies')) {
        # CAPVisualizer export.json
        $policies       = @(_K $raw 'policies')
        $meta           = _K $raw 'metadata'
        $namedLocations = @(_K $raw 'namedLocations')
        $authStrengths  = @(_K $raw 'authenticationStrengths')
        $authContexts   = @(_K $raw 'authenticationContexts')
        $nm = _K $raw 'nameMap'
        if ($nm -is [System.Collections.IDictionary]) { foreach ($k in $nm.Keys) { $nameMap["$k"] = $nm[$k] } }
    }
    elseif ($raw -is [System.Collections.IDictionary] -and $raw.Contains('value')) {
        # Raw Graph collection response { value: [ ... ] }
        $policies = @(_K $raw 'value')
    }
    elseif ($raw -is [System.Collections.IEnumerable] -and $raw -isnot [string]) {
        # Bare array of policy objects
        $policies = @($raw)
    }
    else {
        # Single policy object
        $policies = @($raw)
    }

    if (-not $policies -or @($policies).Count -eq 0) {
        throw "No conditional access policies found in '$file'. Expected a CAPVisualizer export.json, a Graph { value: [...] } response, or an array of policy objects."
    }

    $meta = [ordered]@{
        tool          = 'CAPVisualizer'
        schemaVersion = if ($meta) { _K $meta 'schemaVersion' } else { '1.0' }
        generatedUtc  = if ($meta -and (_K $meta 'generatedUtc')) { _K $meta 'generatedUtc' } else { (Get-Date).ToUniversalTime().ToString('o') }
        tenantId      = if ($meta -and (_K $meta 'tenantId')) { _K $meta 'tenantId' } else { 'unknown (offline JSON)' }
        account       = if ($meta) { _K $meta 'account' } else { $null }
        authType      = 'offline-json'
        source        = $file
        policyCount   = @($policies).Count
    }

    Write-CapLog "Loaded $(@($policies).Count) policies offline (nameMap entries: $($nameMap.Count))." 'OK'

    return [ordered]@{
        metadata                = $meta
        policies                = @($policies | ForEach-Object { ConvertTo-CapHashtable -InputObject $_ })
        namedLocations          = @($namedLocations | ForEach-Object { ConvertTo-CapHashtable -InputObject $_ })
        authenticationStrengths = @($authStrengths | ForEach-Object { ConvertTo-CapHashtable -InputObject $_ })
        authenticationContexts  = @($authContexts | ForEach-Object { ConvertTo-CapHashtable -InputObject $_ })
        nameMap                 = $nameMap
    }
}

Export-ModuleMember -Function Get-CapExport, Get-CapReferences, Import-CapExportJson
