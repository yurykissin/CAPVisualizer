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

function _NCsvArr {
    # Graph returns several enum collections as a single comma-separated string
    # ("b2bDirectConnectUser,otherExternalUser,serviceProvider") rather than a
    # JSON array. Treating that as one opaque value makes every comparison and
    # fingerprint wrong, so split on commas as well as unrolling arrays.
    param($v)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($item in (_NArr $v)) {
        foreach ($part in ($item -split ',')) {
            $t = $part.Trim()
            if ($t) { [void]$out.Add($t) }
        }
    }
    return @($out)
}

function _NGuestBlock {
<#
.SYNOPSIS
    Read guest / external-user targeting from BOTH Graph shapes.

.DESCRIPTION
    Historically a policy targeted guests by putting the literal string
    'GuestsOrExternalUsers' inside includeUsers/excludeUsers. Current Graph
    instead uses a dedicated includeGuestsOrExternalUsers /
    excludeGuestsOrExternalUsers object carrying the guest types and the set of
    external tenants.

    Both are still valid input. Reading only the legacy form makes a modern
    policy look like it targets nobody, which downstream is indistinguishable
    from a broken policy and gets it recommended for deletion. Reading only the
    modern form would break older exports the same way. So: either shape sets
    the flag, and the richer modern detail is carried alongside it.

.OUTPUTS
    @{ present, types[], tenantMode, tenantIds[] }
    tenantMode is 'all', 'enumerated' or $null.
#>
    param($Users, [string]$Direction)

    $legacyKey = if ($Direction -eq 'include') { 'includeUsers' } else { 'excludeUsers' }
    $modernKey = if ($Direction -eq 'include') { 'includeGuestsOrExternalUsers' } else { 'excludeGuestsOrExternalUsers' }

    $legacy = [bool]((_NArr (_NGet $Users $legacyKey)) -contains 'GuestsOrExternalUsers')
    $modern = _NGet $Users $modernKey

    $types = @()
    $tenantMode = $null
    $tenantIds = @()
    if ($null -ne $modern) {
        $types = _NCsvArr (_NGet $modern 'guestOrExternalUserTypes')
        $ext = _NGet $modern 'externalTenants'
        if ($null -ne $ext) {
            $kind = "$(_NGet $ext 'membershipKind')".Trim()
            if ($kind) { $tenantMode = $kind }
            # 'members' is a one-element array unrolled to a scalar whenever the
            # policy names exactly one partner tenant, which is the common case.
            $tenantIds = _NCsvArr (_NGet $ext 'members')
        }
    }

    return [ordered]@{
        present    = [bool]($legacy -or ($null -ne $modern))
        types      = $types
        tenantMode = $tenantMode
        tenantIds  = @($tenantIds)
    }
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
    $incGuest  = _NGuestBlock -Users $users -Direction 'include'
    $excGuest  = _NGuestBlock -Users $users -Direction 'exclude'
    $usersBlock = [ordered]@{
        includeAll    = [bool]($incUsers -contains 'All')
        includeNone   = [bool]($incUsers -contains 'None')
        includeGuests = $incGuest.present
        includeUsers  = @($incUsers  | Where-Object { $_ -notin @('All', 'None', 'GuestsOrExternalUsers') })
        includeGroups = _NArr (_NGet $users 'includeGroups')
        includeRoles  = _NArr (_NGet $users 'includeRoles')
        includeGuestTypes = $incGuest.types
        includeGuestTenantMode = $incGuest.tenantMode
        includeGuestTenants    = @($incGuest.tenantIds)
        excludeGuests = $excGuest.present
        excludeUsers  = @($excUsers  | Where-Object { $_ -notin @('All', 'None', 'GuestsOrExternalUsers') })
        excludeGroups = _NArr (_NGet $users 'excludeGroups')
        excludeRoles  = _NArr (_NGet $users 'excludeRoles')
        excludeGuestTypes = $excGuest.types
        excludeGuestTenantMode = $excGuest.tenantMode
        excludeGuestTenants    = @($excGuest.tenantIds)
    }

    # Applications / resources
    $appInc = Expand-CapAppGrouping -Values (_NArr (_NGet $apps 'includeApplications')) -GroupingMap $AppGroupingMap
    $appExc = Expand-CapAppGrouping -Values (_NArr (_NGet $apps 'excludeApplications')) -GroupingMap $AppGroupingMap
    # A policy can target resources without naming a single application id:
    # by attribute filter, or by Global Secure Access traffic profile (which
    # Graph has carried under both 'networkAccess' and 'globalSecureAccess').
    # Reading only includeApplications makes those look like they target no
    # resource at all, which downstream reads as a policy that does nothing.
    $appFilterObj = _NGet $apps 'applicationFilter'
    $appFilter = $null
    if ($appFilterObj) {
        $appFilter = [ordered]@{
            mode = "$(_NGet $appFilterObj 'mode')"
            rule = "$(_NGet $appFilterObj 'rule')"
        }
    }
    $traffic = @(@(_NCsvArr (_NGet (_NGet $apps 'globalSecureAccess') 'includeTrafficProfiles')) +
                 @(_NCsvArr (_NGet (_NGet $apps 'networkAccess') 'includeTrafficProfiles'))) |
               Select-Object -Unique
    $appsBlock = [ordered]@{
        includeAll        = $appInc.includeAll
        includeNone       = $appInc.none
        includeAppIds     = @($appInc.appIds)
        includeGroupings  = @($appInc.groupings)
        excludeAppIds     = @($appExc.appIds)
        excludeGroupings  = @($appExc.groupings)
        userActions       = _NArr (_NGet $apps 'includeUserActions')
        authContexts      = _NArr (_NGet $apps 'includeAuthenticationContextClassReferences')
        appFilter         = $appFilter
        trafficProfiles   = @($traffic)
    }

    # Workload and agent identities. The report already surfaced these; the model
    # did not, so a policy scoped to service principals looked unscoped.
    $wl = [ordered]@{
        includeServicePrincipals = _NArr (_NGet $clientApp 'includeServicePrincipals')
        excludeServicePrincipals = _NArr (_NGet $clientApp 'excludeServicePrincipals')
        includeAgentIdServicePrincipals = _NArr (_NGet $clientApp 'includeAgentIdServicePrincipals')
        excludeAgentIdServicePrincipals = _NArr (_NGet $clientApp 'excludeAgentIdServicePrincipals')
        filter = $(
            $f = _NGet $clientApp 'servicePrincipalFilter'
            if ($f) { [ordered]@{ mode = "$(_NGet $f 'mode')"; rule = "$(_NGet $f 'rule')" } } else { $null }
        )
    }
    $wl['present'] = [bool](@($wl.includeServicePrincipals).Count -or @($wl.excludeServicePrincipals).Count -or
                            @($wl.includeAgentIdServicePrincipals).Count -or @($wl.excludeAgentIdServicePrincipals).Count -or
                            $wl.filter)

    # Conditions
    $platforms   = Get-CapCanonicalPlatforms (_NGet $cond 'platforms')
    $clientApps  = Get-CapCanonicalClientApps (_NArr (_NGet $cond 'clientAppTypes'))
    $locations   = Get-CapCanonicalLocations (_NGet $cond 'locations')
    $signInRisk  = @(_NArr (_NGet $cond 'signInRiskLevels'))
    $userRisk    = @(_NArr (_NGet $cond 'userRiskLevels'))
    $spRisk      = @(_NArr (_NGet $cond 'servicePrincipalRiskLevels'))
    $insiderRisk = @(_NArr (_NGet $cond 'insiderRiskLevels'))
    $agentRisk   = @(@(_NArr (_NGet $cond 'agentIdRiskLevels')) + @(_NArr (_NGet $cond 'agentRiskLevels')))
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
    # Device targeting predates deviceFilter. Older policies use the deprecated
    # top-level deviceStates block, and the devices block itself can carry
    # explicit device and device-state lists alongside the filter. Read all of
    # them so a policy scoped by any of these is not treated as unscoped.
    $legacyDeviceStates = _NGet $cond 'deviceStates'
    $devices = [ordered]@{
        filter               = $deviceFilter
        includeDevices       = _NArr (_NGet $rawDeviceFilter 'includeDevices')
        excludeDevices       = _NArr (_NGet $rawDeviceFilter 'excludeDevices')
        includeDeviceStates  = @(@(_NArr (_NGet $rawDeviceFilter 'includeDeviceStates')) +
                                 @(_NArr (_NGet $legacyDeviceStates 'includeStates'))) | Select-Object -Unique
        excludeDeviceStates  = @(@(_NArr (_NGet $rawDeviceFilter 'excludeDeviceStates')) +
                                 @(_NArr (_NGet $legacyDeviceStates 'excludeStates'))) | Select-Object -Unique
    }
    $devices['present'] = [bool]($deviceFilter -or @($devices.includeDevices).Count -or @($devices.excludeDevices).Count -or
                                 @($devices.includeDeviceStates).Count -or @($devices.excludeDeviceStates).Count)

    $times = _NGet $cond 'times'
    $agents = _NGet $cond 'agents'

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
            devices        = $devices
            workloadIdentities = $wl
            times          = $times
            agents         = $agents
        }
        grant        = $grantBlock
        hasSession   = [bool]$session
        signalsRequired = @($signals)
    }
}

$script:CapConsumedConditionPaths = @(
    # users
    'users.includeUsers', 'users.excludeUsers',
    'users.includeGroups', 'users.excludeGroups',
    'users.includeRoles', 'users.excludeRoles',
    'users.includeGuestsOrExternalUsers.guestOrExternalUserTypes',
    'users.includeGuestsOrExternalUsers.externalTenants.membershipKind',
    'users.includeGuestsOrExternalUsers.externalTenants.members',
    'users.excludeGuestsOrExternalUsers.guestOrExternalUserTypes',
    'users.excludeGuestsOrExternalUsers.externalTenants.membershipKind',
    'users.excludeGuestsOrExternalUsers.externalTenants.members',
    # applications / resources
    'applications.includeApplications', 'applications.excludeApplications',
    'applications.includeUserActions', 'applications.includeAuthenticationContextClassReferences',
    'applications.applicationFilter.mode', 'applications.applicationFilter.rule',
    'applications.globalSecureAccess.includeTrafficProfiles',
    'applications.networkAccess.includeTrafficProfiles',
    # workload and agent identities
    'clientApplications.includeServicePrincipals', 'clientApplications.excludeServicePrincipals',
    'clientApplications.includeAgentIdServicePrincipals', 'clientApplications.excludeAgentIdServicePrincipals',
    'clientApplications.servicePrincipalFilter.mode', 'clientApplications.servicePrincipalFilter.rule',
    # devices
    'devices.deviceFilter.mode', 'devices.deviceFilter.rule',
    'devices.includeDevices', 'devices.excludeDevices',
    'devices.includeDeviceStates', 'devices.excludeDeviceStates',
    'deviceStates.includeStates', 'deviceStates.excludeStates',
    # everything else
    'platforms.includePlatforms', 'platforms.excludePlatforms',
    'locations.includeLocations', 'locations.excludeLocations',
    'clientAppTypes',
    'signInRiskLevels', 'userRiskLevels', 'servicePrincipalRiskLevels',
    'insiderRiskLevels', 'agentIdRiskLevels', 'agentRiskLevels',
    'authenticationFlows.transferMethods',
    'times', 'agents'
)

function Get-CapConsumedConditionPaths {
    return @($script:CapConsumedConditionPaths)
}

function Test-CapShapeCoverage {
<#
.SYNOPSIS
    Report condition data present in an export that the normalizer does not read.

.DESCRIPTION
    Microsoft adds new shapes for existing conditions. When that happens, a tool
    that reads only the old shape does not fail: it reports the condition as
    absent. Absent targeting then reads as "this policy does nothing", which is
    how live, load-bearing policies get recommended for deletion.

    This walks the raw export, collects every condition value that is actually
    populated, and compares it against the declared consumed set. Anything
    populated and unread is returned so the caller can say so out loud instead
    of quietly producing a confident wrong answer.

.OUTPUTS
    Array of @{ path, policyIds[], count, sample }.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Policies)

    $consumed = @{}
    foreach ($p in $script:CapConsumedConditionPaths) { $consumed[$p] = $true }
    $unknown = @{}

    # Structural keys that carry no policy data of their own.
    $ignore = @('@odata.type', '@odata.context', '@odata.id')

    $walk = {
        param($node, [string]$path, [string]$policyId)
        if ($null -eq $node) { return }
        if ($node -is [System.Collections.IDictionary]) {
            foreach ($k in @($node.Keys)) {
                if ($k -in $ignore) { continue }
                & $walk $node[$k] $(if ($path) { "$path.$k" } else { "$k" }) $policyId
            }
            return
        }
        if ($node -is [System.Management.Automation.PSCustomObject]) {
            foreach ($prop in $node.PSObject.Properties) {
                if ($prop.Name -in $ignore) { continue }
                & $walk $prop.Value $(if ($path) { "$path.$($prop.Name)" } else { "$($prop.Name)" }) $policyId
            }
            return
        }
        if (($node -isnot [string]) -and ($node -is [System.Collections.IEnumerable])) {
            $any = $false
            foreach ($item in $node) { $any = $true; & $walk $item $path $policyId }
            if (-not $any) { return }
            return
        }
        # Leaf value. Empty string and empty collections are not "populated".
        $text = "$node"
        if ($text -eq '') { return }
        if ($consumed.ContainsKey($path)) { return }
        if (-not $unknown.ContainsKey($path)) {
            $unknown[$path] = [ordered]@{
                path      = $path
                policyIds = [System.Collections.Generic.List[string]]::new()
                sample    = $text
            }
        }
        if ($unknown[$path].policyIds -notcontains $policyId) { [void]$unknown[$path].policyIds.Add($policyId) }
    }

    foreach ($p in @($Policies)) {
        $cond = _NGet $p 'conditions'
        if ($null -eq $cond) { continue }
        & $walk $cond '' "$(_NGet $p 'id')"
    }

    return @($unknown.Values | ForEach-Object {
        [ordered]@{
            path      = $_.path
            policyIds = @($_.policyIds)
            count     = @($_.policyIds).Count
            sample    = $_.sample
        }
    } | Sort-Object -Property path)
}

Export-ModuleMember -Function Get-CapAppGroupingMap, Expand-CapAppGrouping, `
    Get-CapCanonicalPlatforms, Get-CapCanonicalClientApps, Get-CapCanonicalLocations, `
    ConvertTo-CapNormalizedPolicy, Test-CapShapeCoverage, Get-CapConsumedConditionPaths
