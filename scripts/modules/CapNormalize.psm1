<#
.SYNOPSIS
    CAPVisualizer normalization layer (Phase 1). Converts a raw Conditional
    Access policy into a canonical, match-ready shape that downstream engines
    (scope, what-if, gap analysis, audit, compliance) can evaluate deterministically
    offline.

.DESCRIPTION
    Entra ID normalizes policy conditions before evaluation: app groupings expand
    to concrete appIds, "all" platforms minus excludes resolve to a concrete set,
    an absent clientAppTypes defaults to "all", and special values (All/None/
    AllTrusted) are not literal strings. Skipping this step produces false
    negatives in offline analysis. This module makes that normalization explicit.

    Pure functions only - no Graph calls, no side effects. Safe to run fully
    offline. Authored independently from public Microsoft documentation of the
    Conditional Access schema; no third-party tool code or logic is reused.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---- Canonical vocabularies -------------------------------------------------

$script:CapAllPlatforms   = @('windows', 'macOS', 'iOS', 'android', 'linux', 'windowsPhone')
$script:CapAllClientApps  = @('browser', 'mobileAppsAndDesktopClients', 'exchangeActiveSync', 'other')
$script:CapLegacyClientApps = @('exchangeActiveSync', 'other')

function _NGet {
    # Property accessor that works for both hashtables and PSObjects.
    param($o, [string]$k)
    if ($null -eq $o) { return $null }
    if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($k)) { return $o[$k] } else { return $null } }
    $p = $o.PSObject.Properties[$k]
    if ($p) { return $p.Value } else { return $null }
}

function _NArr {
    # Normalize any value into a string array (null/scalar-safe).
    param($v)
    if ($null -eq $v) { return @() }
    if ($v -is [string]) { return @($v) }
    if ($v -is [System.Collections.IEnumerable]) { return @($v | ForEach-Object { "$_" } | Where-Object { $_ -ne '' }) }
    return @("$v")
}

function Get-CapAppGroupingMap {
<#
.SYNOPSIS
    Load the static app-grouping reference (Office365 / MicrosoftAdminPortals ->
    member appIds). Returns an empty map if the reference file is absent so
    callers degrade gracefully.

.PARAMETER ReferencePath
    Path to app-groupings.json. Defaults to the packaged assets/reference copy.
#>
    [CmdletBinding()]
    param([string]$ReferencePath)

    if (-not $ReferencePath) {
        $ReferencePath = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'assets/reference/app-groupings.json'
    }
    $map = @{}
    if (-not (Test-Path -LiteralPath $ReferencePath)) { return $map }
    try {
        $ref = Get-Content -LiteralPath $ReferencePath -Raw | ConvertFrom-Json -Depth 20 -AsHashtable
        $groupings = _NGet $ref 'groupings'
        if ($groupings -is [System.Collections.IDictionary]) {
            foreach ($key in $groupings.Keys) {
                $members = _NGet $groupings[$key] 'members'
                $ids = @(@($members) | ForEach-Object { _NGet $_ 'appId' } | Where-Object { $_ } | Sort-Object -Unique)
                $map["$key"] = $ids
            }
        }
    }
    catch { }
    return $map
}

function Expand-CapAppGrouping {
<#
.SYNOPSIS
    Expand a set of raw application condition values into concrete appIds plus the
    special/grouping tokens that were present. Returns a canonical descriptor.
#>
    [CmdletBinding()]
    param(
        [string[]]$Values,
        [hashtable]$GroupingMap = @{}
    )
    $values = _NArr $Values
    $includeAll = $false
    $none       = $false
    $groupings  = [System.Collections.Generic.List[string]]::new()
    $appIds     = [System.Collections.Generic.HashSet[string]]::new()

    foreach ($v in $values) {
        switch -Regex ($v) {
            '^All$'   { $includeAll = $true; continue }
            '^None$'  { $none = $true; continue }
            default {
                if ($GroupingMap.ContainsKey($v)) {
                    [void]$groupings.Add($v)
                    foreach ($id in $GroupingMap[$v]) { [void]$appIds.Add("$id") }
                }
                else {
                    [void]$appIds.Add($v)
                }
            }
        }
    }
    return [ordered]@{
        includeAll = $includeAll
        none       = $none
        groupings  = @($groupings)
        appIds     = @($appIds)
    }
}

function Get-CapCanonicalPlatforms {
<#
.SYNOPSIS
    Resolve a platforms condition into the effective included platform set
    (include "all" minus excludes). Returns $null when the policy places no
    platform constraint (applies to every platform).
#>
    [CmdletBinding()]
    param($PlatformsCondition)

    if ($null -eq $PlatformsCondition) { return $null }
    $inc = @(_NArr (_NGet $PlatformsCondition 'includePlatforms'))
    $exc = @(_NArr (_NGet $PlatformsCondition 'excludePlatforms'))
    if ($inc.Count -eq 0) { return $null }

    $included = if ($inc -contains 'all') { @($script:CapAllPlatforms) } else { @($inc) }
    $effective = @($included | Where-Object { $exc -notcontains $_ })
    return [ordered]@{
        isAll     = [bool]($inc -contains 'all')
        include   = @($included)
        exclude   = @($exc)
        effective = @($effective)
    }
}

function Get-CapCanonicalClientApps {
<#
.SYNOPSIS
    Resolve a clientAppTypes condition into its canonical set. An absent or empty
    condition defaults to "all" (Entra's behaviour). Flags whether legacy
    authentication (exchangeActiveSync / other) is in scope.
#>
    [CmdletBinding()]
    param([string[]]$ClientAppTypes)

    $vals = @(_NArr $ClientAppTypes)
    $isAll = ($vals.Count -eq 0) -or ($vals -contains 'all')
    $effective = if ($isAll) { @($script:CapAllClientApps) } else { @($vals) }
    $includesLegacy = [bool](@($effective | Where-Object { $script:CapLegacyClientApps -contains $_ }).Count)
    $includesModern = [bool](@($effective | Where-Object { @('browser', 'mobileAppsAndDesktopClients') -contains $_ }).Count)
    return [ordered]@{
        isAll          = $isAll
        effective      = @($effective)
        includesLegacy = $includesLegacy
        includesModern = $includesModern
    }
}

function Get-CapCanonicalLocations {
<#
.SYNOPSIS
    Resolve a locations condition into canonical include/exclude descriptors.
    Handles the All / AllTrusted special values.
#>
    [CmdletBinding()]
    param($LocationsCondition)

    if ($null -eq $LocationsCondition) { return $null }
    $inc = @(_NArr (_NGet $LocationsCondition 'includeLocations'))
    $exc = @(_NArr (_NGet $LocationsCondition 'excludeLocations'))
    if ($inc.Count -eq 0 -and $exc.Count -eq 0) { return $null }
    return [ordered]@{
        includeAll        = [bool]($inc -contains 'All')
        includeAllTrusted = [bool]($inc -contains 'AllTrusted')
        includeIds        = @($inc | Where-Object { $_ -ne 'All' -and $_ -ne 'AllTrusted' })
        excludeAll        = [bool]($exc -contains 'All')
        excludeAllTrusted = [bool]($exc -contains 'AllTrusted')
        excludeIds        = @($exc | Where-Object { $_ -ne 'All' -and $_ -ne 'AllTrusted' })
    }
}

function ConvertTo-CapNormalizedPolicy {
<#
.SYNOPSIS
    Convert one raw CA policy into the canonical, match-ready normalized shape.

.PARAMETER Policy
    A raw policy object (hashtable or PSObject), as found in export.policies.

.PARAMETER AppGroupingMap
    Output of Get-CapAppGroupingMap (grouping token -> member appIds). Optional.

.OUTPUTS
    Ordered hashtable with id/displayName/state/enforced and a fully canonical
    conditions/grant/session block plus signalsRequired (the sign-in signals whose
    values this policy's applicability depends on).
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Policy,
        [hashtable]$AppGroupingMap = @{}
    )

    $state = "$(_NGet $Policy 'state')"
    $enforced = ($state -eq 'enabled')
    $reportOnly = ($state -eq 'enabledForReportingButNotEnforced')

    $cond      = _NGet $Policy 'conditions'
    $users     = _NGet $cond 'users'
    $apps      = _NGet $cond 'applications'
    $clientApp = _NGet $cond 'clientApplications'

    # Users / principals
    $incUsers  = _NArr (_NGet $users 'includeUsers')
    $excUsers  = _NArr (_NGet $users 'excludeUsers')
    $usersBlock = [ordered]@{
        includeAll    = [bool]($incUsers -contains 'All')
        includeNone   = [bool]($incUsers -contains 'None')
        includeGuests = [bool]($incUsers -contains 'GuestsOrExternalUsers')
        includeUsers  = @($incUsers  | Where-Object { $_ -notin @('All', 'None', 'GuestsOrExternalUsers') })
        includeGroups = _NArr (_NGet $users 'includeGroups')
        includeRoles  = _NArr (_NGet $users 'includeRoles')
        includeGuestTypes = _NArr (_NGet (_NGet $users 'includeGuestsOrExternalUsers') 'guestOrExternalUserTypes')
        excludeGuests = [bool]($excUsers -contains 'GuestsOrExternalUsers')
        excludeUsers  = @($excUsers  | Where-Object { $_ -notin @('All', 'None', 'GuestsOrExternalUsers') })
        excludeGroups = _NArr (_NGet $users 'excludeGroups')
        excludeRoles  = _NArr (_NGet $users 'excludeRoles')
        excludeGuestTypes = _NArr (_NGet (_NGet $users 'excludeGuestsOrExternalUsers') 'guestOrExternalUserTypes')
    }

    # Applications / resources
    $appInc = Expand-CapAppGrouping -Values (_NArr (_NGet $apps 'includeApplications')) -GroupingMap $AppGroupingMap
    $appExc = Expand-CapAppGrouping -Values (_NArr (_NGet $apps 'excludeApplications')) -GroupingMap $AppGroupingMap
    $appsBlock = [ordered]@{
        includeAll        = $appInc.includeAll
        includeNone       = $appInc.none
        includeAppIds     = @($appInc.appIds)
        includeGroupings  = @($appInc.groupings)
        excludeAppIds     = @($appExc.appIds)
        excludeGroupings  = @($appExc.groupings)
        userActions       = _NArr (_NGet $apps 'includeUserActions')
        authContexts      = _NArr (_NGet $apps 'includeAuthenticationContextClassReferences')
    }

    # Conditions
    $platforms   = Get-CapCanonicalPlatforms (_NGet $cond 'platforms')
    $clientApps  = Get-CapCanonicalClientApps (_NArr (_NGet $cond 'clientAppTypes'))
    $locations   = Get-CapCanonicalLocations (_NGet $cond 'locations')
    $signInRisk  = @(_NArr (_NGet $cond 'signInRiskLevels'))
    $userRisk    = @(_NArr (_NGet $cond 'userRiskLevels'))
    $spRisk      = @(_NArr (_NGet $cond 'servicePrincipalRiskLevels'))
    $insiderRisk = @(_NArr (_NGet $cond 'insiderRiskLevels'))
    $agentRisk   = @(_NArr (_NGet $cond 'agentRiskLevels'))
    $authFlows   = @(_NArr (_NGet (_NGet $cond 'authenticationFlows') 'transferMethods'))

    $rawDeviceFilter = _NGet $cond 'devices'
    $deviceFilterObj = _NGet $rawDeviceFilter 'deviceFilter'
    $deviceFilter = $null
    if ($deviceFilterObj) {
        $deviceFilter = [ordered]@{
            mode = "$(_NGet $deviceFilterObj 'mode')"
            rule = "$(_NGet $deviceFilterObj 'rule')"
        }
    }

    # Grant controls
    $grant = _NGet $Policy 'grantControls'
    $builtIn = _NArr (_NGet $grant 'builtInControls')
    $authStrength = _NGet $grant 'authenticationStrength'
    $grantBlock = [ordered]@{
        operator        = "$(_NGet $grant 'operator')"
        controls        = @($builtIn)
        block           = [bool]($builtIn -contains 'block')
        requireMfa      = [bool]($builtIn -contains 'mfa' -or $authStrength)
        requireCompliant= [bool]($builtIn -contains 'compliantDevice')
        requireHybrid   = [bool]($builtIn -contains 'domainJoinedDevice')
        authStrengthId  = if ($authStrength) { "$(_NGet $authStrength 'id')" } else { $null }
        hasControls     = [bool](@($builtIn).Count -or $authStrength)
    }

    # Session controls (presence flags; details preserved by CapReport already)
    $session = _NGet $Policy 'sessionControls'

    # Which sign-in signals gate this policy's applicability (used to classify
    # definitive vs signal-dependent in the what-if engine).
    $signals = [System.Collections.Generic.List[string]]::new()
    if ($signInRisk.Count) { [void]$signals.Add('signInRisk') }
    if ($userRisk.Count)   { [void]$signals.Add('userRisk') }
    if ($spRisk.Count)     { [void]$signals.Add('servicePrincipalRisk') }
    if ($insiderRisk.Count) { [void]$signals.Add('insiderRisk') }
    if ($agentRisk.Count)  { [void]$signals.Add('agentRisk') }
    if ($authFlows.Count)  { [void]$signals.Add('authFlow') }
    if ($null -ne $locations) { [void]$signals.Add('location') }
    if ($null -ne $deviceFilter) { [void]$signals.Add('deviceState') }

    return [ordered]@{
        id           = "$(_NGet $Policy 'id')"
        displayName  = "$(_NGet $Policy 'displayName')"
        state        = $state
        enforced     = $enforced
        reportOnly   = $reportOnly
        conditions   = [ordered]@{
            users          = $usersBlock
            applications   = $appsBlock
            platforms      = $platforms
            clientApps     = $clientApps
            locations      = $locations
            signInRisk     = @($signInRisk)
            userRisk       = @($userRisk)
            servicePrincipalRisk = @($spRisk)
            insiderRisk    = @($insiderRisk)
            agentRisk      = @($agentRisk)
            authFlows      = @($authFlows)
            deviceFilter   = $deviceFilter
        }
        grant        = $grantBlock
        hasSession   = [bool]$session
        signalsRequired = @($signals)
    }
}

Export-ModuleMember -Function Get-CapAppGroupingMap, Expand-CapAppGrouping, `
    Get-CapCanonicalPlatforms, Get-CapCanonicalClientApps, Get-CapCanonicalLocations, `
    ConvertTo-CapNormalizedPolicy
