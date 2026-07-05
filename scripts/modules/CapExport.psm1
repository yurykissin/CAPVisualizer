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

function Get-CapReferencedIds {
<#
.SYNOPSIS
    Collect the distinct directory object ids referenced by a policy set's
    user/group/role assignments (for optional friendly-name resolution).
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Export)

    function _K { param($o, [string]$k) if ($null -eq $o) { return $null }; if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($k)) { return $o[$k] } else { return $null } }; $p = $o.PSObject.Properties[$k]; if ($p) { return $p.Value } else { return $null } }

    $ids = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($p in $Export.policies) {
        $cond = _K $p 'conditions'
        $users = _K $cond 'users'
        foreach ($bucket in 'includeUsers','excludeUsers','includeGroups','excludeGroups','includeRoles','excludeRoles') {
            $vals = _K $users $bucket
            if ($vals) { foreach ($v in $vals) { if ("$v" -match '^[0-9a-fA-F-]{36}$') { [void]$ids.Add("$v") } } }
        }
        $apps = _K $cond 'applications'
        foreach ($bucket in 'includeApplications','excludeApplications') {
            $vals = _K $apps $bucket
            if ($vals) { foreach ($v in $vals) { if ("$v" -match '^[0-9a-fA-F-]{36}$') { [void]$ids.Add("$v") } } }
        }
    }
    return @($ids)
}

Export-ModuleMember -Function Get-CapExport, Get-CapReferencedIds
