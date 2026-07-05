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
    }

    return [ordered]@{
        UserGroupIds    = @($userGroup)
        RoleTemplateIds = @($roles)
        AppIds          = @($apps)
    }
}

Export-ModuleMember -Function Get-CapExport, Get-CapReferences
