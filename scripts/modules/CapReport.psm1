<#
.SYNOPSIS
    CAPVisualizer report module. Turns a raw CA export into enriched JSON, flat
    CSV files, and a summary that includes hygiene/gap checks and a coverage
    overview. Read-only transformation of already-fetched data.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function _Join { param($v) if ($null -eq $v) { '' } elseif ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) { (@($v) -join '; ') } else { "$v" } }
function _Count { param($v) if ($null -eq $v) { 0 } elseif ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) { @($v).Count } else { 1 } }

# Safe member/key accessor that works for both hashtables and PSObjects and
# returns $null for missing members (StrictMode-safe).
function _Get {
    param($obj, [string]$name)
    if ($null -eq $obj) { return $null }
    if ($obj -is [System.Collections.IDictionary]) {
        if ($obj.Contains($name)) { return $obj[$name] } else { return $null }
    }
    $p = $obj.PSObject.Properties[$name]
    if ($p) { return $p.Value } else { return $null }
}

# --- Friendly enum-label maps (mirror the Entra portal wording) -------------
$script:CapPlatformLabels = @{
    all = 'All'; android = 'Android'; iOS = 'iOS'; linux = 'Linux'
    macOS = 'macOS'; windows = 'Windows'; windowsPhone = 'Windows Phone'
}
$script:CapClientAppLabels = @{
    all = 'All clients'; browser = 'Browser'
    mobileAppsAndDesktopClients = 'Mobile apps and desktop clients'
    exchangeActiveSync = 'Exchange ActiveSync clients'
    easSupported = 'Exchange ActiveSync clients'
    other = 'Other legacy clients'
}
$script:CapRiskLabels = @{
    high = 'High'; medium = 'Medium'; low = 'Low'; none = 'No risk'; hidden = 'Hidden'
}
$script:CapAuthFlowLabels = @{
    deviceCodeFlow         = 'Device code flow'
    authenticationTransfer = 'Authentication transfer'
}
$script:CapUserActionLabels = @{
    'urn:user:registersecurityinfo' = 'Register security information'
    'urn:user:registerdevice'       = 'Register or join devices'
}
$script:CapGuestTypeLabels = @{
    internalGuest         = 'Local guest users'
    b2bCollaborationGuest = 'B2B collaboration guest users'
    b2bCollaborationMember= 'B2B collaboration member users'
    b2bDirectConnectUser  = 'B2B direct connect users'
    otherExternalUser     = 'Other external users'
    serviceProvider       = 'Service provider users'
}
$script:CapGrantLabels = @{
    mfa                  = 'Require multifactor authentication'
    compliantDevice      = 'Require device to be marked as compliant'
    domainJoinedDevice   = 'Require Microsoft Entra hybrid joined device'
    approvedApplication  = 'Require approved client app'
    compliantApplication = 'Require app protection policy'
    passwordChange       = 'Require password change'
    block                = 'Block access'
}
$script:CapCasLabels = @{
    monitorOnly     = 'Monitor only'
    blockDownloads  = 'Block downloads'
    mcasConfigured  = 'Use custom policy'
    unknownFutureValue = 'Custom policy'
}
$script:CapCaeLabels = @{
    disabled          = 'Disabled'
    strictEnforcement = 'Strictly enforce location policies'
    strictLocation    = 'Strictly enforce location policies'
}
$script:CapPersistentBrowserLabels = @{ always = 'Always persistent'; never = 'Never persistent' }

function _Label { param($map, $value) if ($null -eq $value) { return $null }; $k = "$value"; if ($map.ContainsKey($k)) { return $map[$k] } else { return $k } }
function _Labels { param($map, $values) @(@($values) | Where-Object { $_ } | ForEach-Object { _Label $map $_ }) }

function _SignInFrequencyLabel {
    param($sf)
    if (-not $sf) { return $null }
    $fi = _Get $sf 'frequencyInterval'
    if ("$fi" -eq 'everyTime') { return 'Every time' }
    $val = _Get $sf 'value'
    $type = "$(_Get $sf 'type')"
    if ($null -eq $val -or '' -eq "$val") { return $null }
    $unit = switch ($type) { 'days' { 'day' } 'hours' { 'hour' } default { $type } }
    if ("$val" -eq '1') { return "$val $unit" } else { return "$val ${unit}s" }
}

function ConvertTo-CapFriendlyPolicy {
<#
.SYNOPSIS
    Flatten one raw CA policy into a friendly, analysis-ready object. Optionally
    substitutes resolved display names for object GUIDs.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Policy,
        [hashtable]$NameMap = @{},
        [hashtable]$LocationMap = @{}
    )

    function _Resolve($ids, $kind) {
        if (-not $ids) { return @() }
        return @($ids | ForEach-Object {
            $v = "$_"
            $special = $null
            if ($kind -eq 'user') {
                switch ($v) {
                    'All'                   { $special = 'All users' }
                    'None'                  { $special = 'None' }
                    'GuestsOrExternalUsers' { $special = 'Guests or external users' }
                }
            }
            elseif ($kind -eq 'app') {
                switch ($v) {
                    'All'                   { $special = 'All cloud apps' }
                    'None'                  { $special = 'None' }
                    'Office365'             { $special = 'Office 365' }
                    'MicrosoftAdminPortals' { $special = 'Microsoft Admin Portals' }
                    'AllAgentIdResources'   { $special = 'All agent resources' }
                }
            }
            elseif ($kind -eq 'sp') {
                switch ($v) {
                    'ServicePrincipalsInMyTenant' { $special = 'All service principals in the tenant' }
                    'None'                        { $special = 'None' }
                }
            }
            if ($special) { $special }
            elseif ($NameMap.ContainsKey($v)) { $NameMap[$v] }
            else { $v }
        })
    }
    function Names($ids) { _Resolve $ids 'user' }
    function Apps($ids)  { _Resolve $ids 'app' }
    function Locs($ids) {
        if (-not $ids) { return @() }
        return @($ids | ForEach-Object {
            switch ("$_") {
                'All'        { 'All locations' }
                'AllTrusted' { 'All trusted locations' }
                default { if ($LocationMap.ContainsKey("$_")) { $LocationMap["$_"] } else { "$_" } }
            }
        })
    }

    $c = _Get $Policy 'conditions'
    $users = _Get $c 'users'
    $apps  = _Get $c 'applications'
    $grant = _Get $Policy 'grantControls'
    $sess  = _Get $Policy 'sessionControls'
    $platforms = _Get $c 'platforms'
    $locations = _Get $c 'locations'

    $grantControls = @()
    if ($grant) { $grantControls = @(_Get $grant 'builtInControls') }
    $authStrengthObj = _Get $grant 'authenticationStrength'
    $authStrength = if ($authStrengthObj) { _Get $authStrengthObj 'displayName' } else { $null }
    $customAuthFactors = @(_Get $grant 'customAuthenticationFactors')
    $grantLabels = @($grantControls | Where-Object { $_ } | ForEach-Object { _Label $script:CapGrantLabels $_ })

    # --- Session controls (structured, friendly) ---
    $sessionSummary = @()
    if ($sess) {
        $aer = _Get $sess 'applicationEnforcedRestrictions'
        if ($aer -and (_Get $aer 'isEnabled')) { $sessionSummary += 'App enforced restrictions: On' }
        $cas = _Get $sess 'cloudAppSecurity'
        if ($cas -and (_Get $cas 'isEnabled')) { $sessionSummary += "Conditional Access App Control: $(_Label $script:CapCasLabels (_Get $cas 'cloudAppSecurityType'))" }
        $sf = _Get $sess 'signInFrequency'
        if ($sf -and (_Get $sf 'isEnabled')) { $sfl = _SignInFrequencyLabel $sf; if ($sfl) { $sessionSummary += "Sign-in frequency: $sfl" } }
        $pb = _Get $sess 'persistentBrowser'
        if ($pb -and (_Get $pb 'isEnabled')) { $sessionSummary += "Persistent browser: $(_Label $script:CapPersistentBrowserLabels (_Get $pb 'mode'))" }
        $cae = _Get $sess 'continuousAccessEvaluation'
        if ($cae -and (_Get $cae 'mode')) { $sessionSummary += "Continuous access evaluation: $(_Label $script:CapCaeLabels (_Get $cae 'mode'))" }
        if ((_Get $sess 'disableResilienceDefaults') -eq $true) { $sessionSummary += 'Disable resilience defaults: On' }
        $ssis = _Get $sess 'secureSignInSession'
        if ($ssis -and (_Get $ssis 'isEnabled')) { $sessionSummary += 'Token protection (secure sign-in session): On' }
    }

    # --- Filters ---
    $deviceFilter = $null
    $devices = _Get $c 'devices'
    $df = _Get $devices 'deviceFilter'
    if ($df) { $deviceFilter = "$(if ((_Get $df 'mode') -eq 'exclude') {'Exclude when'} else {'Include when'}) $(_Get $df 'rule')" }
    $appFilter = $null
    $af = _Get $apps 'applicationFilter'
    if ($af) { $appFilter = "$(if ((_Get $af 'mode') -eq 'exclude') {'Exclude when'} else {'Include when'}) $(_Get $af 'rule')" }

    # --- Workload identities (service principals) ---
    $clientApps = _Get $c 'clientApplications'
    $inclSp = _Resolve (_Get $clientApps 'includeServicePrincipals') 'sp'
    $exclSp = _Resolve (_Get $clientApps 'excludeServicePrincipals') 'sp'
    $isWorkloadIdentity = [bool](@($inclSp).Count -or @($exclSp).Count)

    # --- Guest / external user types ---
    $inclGuest = _Get $users 'includeGuestsOrExternalUsers'
    $exclGuest = _Get $users 'excludeGuestsOrExternalUsers'
    $inclGuestTypes = @()
    $exclGuestTypes = @()
    if ($inclGuest) { $inclGuestTypes = _Labels $script:CapGuestTypeLabels (("$(_Get $inclGuest 'guestOrExternalUserTypes')") -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    if ($exclGuest) { $exclGuestTypes = _Labels $script:CapGuestTypeLabels (("$(_Get $exclGuest 'guestOrExternalUserTypes')") -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }

    # Which partner organisations the guest selector covers. Without this the
    # report says "external users" and stops, so a policy admitting one named
    # managed provider is indistinguishable from one admitting every tenant in
    # the world. Graph unrolls a single-member list to a scalar, so accept both.
    $extOf = {
        param($block)
        $ext = _Get $block 'externalTenants'
        if (-not $ext) { return $null }
        $kind = "$(_Get $ext 'membershipKind')"
        $members = _Get $ext 'members'
        $ids = @()
        if ($null -ne $members) { $ids = @($members | Where-Object { $_ } | ForEach-Object { "$_" }) }
        [ordered]@{
            membershipKind = $kind
            tenantIds      = $ids
            label          = if ($kind -eq 'enumerated' -and $ids.Count) {
                                 "Named tenants only: $($ids -join ', ')"
                             } elseif ($kind -eq 'enumerated') {
                                 'Named tenants only (none listed)'
                             } else { 'All external tenants' }
        }
    }
    $inclExtTenants = if ($inclGuest) { & $extOf $inclGuest } else { $null }
    $exclExtTenants = if ($exclGuest) { & $extOf $exclGuest } else { $null }

    # Global Secure Access selects resources by traffic profile instead of by
    # application id, so a policy can protect real traffic while naming no app.
    $trafficProfiles = @(@(_Get (_Get $apps 'globalSecureAccess') 'includeTrafficProfiles') +
                         @(_Get (_Get $apps 'networkAccess') 'includeTrafficProfiles')) |
                       ForEach-Object { ("$_" -split ',') } | ForEach-Object { $_.Trim() } |
                       Where-Object { $_ } | Select-Object -Unique

    # Agent identities are targeted through their own lists.
    $inclAgents = @(_Get $clientApps 'includeAgentIdServicePrincipals')
    $exclAgents = @(_Get $clientApps 'excludeAgentIdServicePrincipals')

    return [ordered]@{
        id                    = _Get $Policy 'id'
        displayName           = _Get $Policy 'displayName'
        state                 = _Get $Policy 'state'
        createdDateTime       = _Get $Policy 'createdDateTime'
        modifiedDateTime      = _Get $Policy 'modifiedDateTime'
        portalLink            = "https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/PolicyBlade/policyId/$(_Get $Policy 'id')"

        isWorkloadIdentity    = $isWorkloadIdentity
        includeUsers          = Names (_Get $users 'includeUsers')
        excludeUsers          = Names (_Get $users 'excludeUsers')
        includeGroups         = Names (_Get $users 'includeGroups')
        excludeGroups         = Names (_Get $users 'excludeGroups')
        includeRoles          = Names (_Get $users 'includeRoles')
        excludeRoles          = Names (_Get $users 'excludeRoles')
        includeGuestsExternal = [bool]$inclGuest
        excludeGuestsExternal = [bool]$exclGuest
        includeGuestTypes     = $inclGuestTypes
        excludeGuestTypes     = $exclGuestTypes
        includeGuestTenants   = $inclExtTenants
        excludeGuestTenants   = $exclExtTenants
        includeServicePrincipals = $inclSp
        excludeServicePrincipals = $exclSp
        includeAgentIdentities   = $inclAgents
        excludeAgentIdentities   = $exclAgents

        includeApplications   = Apps (_Get $apps 'includeApplications')
        excludeApplications   = Apps (_Get $apps 'excludeApplications')
        applicationFilter     = $appFilter
        trafficProfiles       = @($trafficProfiles)
        includeUserActions    = _Labels $script:CapUserActionLabels (_Get $apps 'includeUserActions')
        authenticationContext = @(_Get $apps 'includeAuthenticationContextClassReferences' | ForEach-Object { if ($NameMap.ContainsKey("$_")) { $NameMap["$_"] } else { "$_" } })

        clientAppTypes        = $(
            $cat = @(_Get $c 'clientAppTypes')
            # Graph returns ["all"] as the default when Client apps is NOT
            # configured (portal shows "Not available"). Only treat it as a real
            # condition when a specific subset is selected.
            if ($cat.Count -eq 1 -and "$($cat[0])" -eq 'all') { @() }
            else { _Labels $script:CapClientAppLabels $cat }
        )
        includePlatforms      = _Labels $script:CapPlatformLabels (_Get $platforms 'includePlatforms')
        excludePlatforms      = _Labels $script:CapPlatformLabels (_Get $platforms 'excludePlatforms')
        includeLocations      = Locs (_Get $locations 'includeLocations')
        excludeLocations      = Locs (_Get $locations 'excludeLocations')
        signInRiskLevels      = _Labels $script:CapRiskLabels (_Get $c 'signInRiskLevels')
        userRiskLevels        = _Labels $script:CapRiskLabels (_Get $c 'userRiskLevels')
        servicePrincipalRiskLevels = _Labels $script:CapRiskLabels (_Get $c 'servicePrincipalRiskLevels')
        insiderRiskLevels     = _Labels $script:CapRiskLabels (_Get $c 'insiderRiskLevels')
        agentRiskLevels       = _Labels $script:CapRiskLabels (@(_Get $c 'agentIdRiskLevels') + @(_Get $c 'agentRiskLevels'))
        authenticationFlows   = _Labels $script:CapAuthFlowLabels (@(if ("$(_Get (_Get $c 'authenticationFlows') 'transferMethods')") { ("$(_Get (_Get $c 'authenticationFlows') 'transferMethods')" -split ',\s*') } else { @() }))
        deviceFilter          = $deviceFilter

        grantOperator         = _Get $grant 'operator'
        grantControls         = $grantControls
        grantControlLabels    = $grantLabels
        customAuthenticationFactors = $customAuthFactors
        authenticationStrength = $authStrength
        termsOfUse            = @(_Get $grant 'termsOfUse' | ForEach-Object { if ($NameMap.ContainsKey("$_")) { $NameMap["$_"] } else { "$_" } })
        isBlock               = [bool]($grantControls -contains 'block')
        requiresMfa           = [bool]($grantControls -contains 'mfa' -or $authStrength)
        sessionControls       = $sessionSummary
    }
}

function ConvertTo-CapCsvRow {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Friendly)
    [pscustomobject][ordered]@{
        Id                 = $Friendly.id
        DisplayName        = $Friendly.displayName
        State              = $Friendly.state
        Created            = $Friendly.createdDateTime
        Modified           = $Friendly.modifiedDateTime
        IncludeUsers       = _Join $Friendly.includeUsers
        ExcludeUsers       = _Join $Friendly.excludeUsers
        IncludeGroups      = _Join $Friendly.includeGroups
        ExcludeGroups      = _Join $Friendly.excludeGroups
        IncludeRoles       = _Join $Friendly.includeRoles
        ExcludeRoles       = _Join $Friendly.excludeRoles
        IncludeGuestTypes  = _Join $Friendly.includeGuestTypes
        ExcludeGuestTypes  = _Join $Friendly.excludeGuestTypes
        IncludeGuestTenants = if ($Friendly.includeGuestTenants) { $Friendly.includeGuestTenants.label } else { $null }
        ExcludeGuestTenants = if ($Friendly.excludeGuestTenants) { $Friendly.excludeGuestTenants.label } else { $null }
        WorkloadIdentity   = $Friendly.isWorkloadIdentity
        IncludeServicePrincipals = _Join $Friendly.includeServicePrincipals
        ExcludeServicePrincipals = _Join $Friendly.excludeServicePrincipals
        IncludeAgentIdentities   = _Join $Friendly.includeAgentIdentities
        IncludeApps        = _Join $Friendly.includeApplications
        ExcludeApps        = _Join $Friendly.excludeApplications
        AppFilter          = $Friendly.applicationFilter
        TrafficProfiles    = _Join $Friendly.trafficProfiles
        UserActions        = _Join $Friendly.includeUserActions
        AuthContext        = _Join $Friendly.authenticationContext
        ClientAppTypes     = _Join $Friendly.clientAppTypes
        IncludePlatforms   = _Join $Friendly.includePlatforms
        ExcludePlatforms   = _Join $Friendly.excludePlatforms
        IncludeLocations   = _Join $Friendly.includeLocations
        ExcludeLocations   = _Join $Friendly.excludeLocations
        SignInRisk         = _Join $Friendly.signInRiskLevels
        UserRisk           = _Join $Friendly.userRiskLevels
        ServicePrincipalRisk = _Join $Friendly.servicePrincipalRiskLevels
        InsiderRisk        = _Join $Friendly.insiderRiskLevels
        AgentRisk          = _Join $Friendly.agentRiskLevels
        AuthFlows          = _Join $Friendly.authenticationFlows
        DeviceFilter       = $Friendly.deviceFilter
        GrantOperator      = $Friendly.grantOperator
        GrantControls      = _Join $Friendly.grantControlLabels
        CustomAuthFactors  = _Join $Friendly.customAuthenticationFactors
        AuthStrength       = $Friendly.authenticationStrength
        TermsOfUse         = _Join $Friendly.termsOfUse
        IsBlock            = $Friendly.isBlock
        RequiresMfa        = $Friendly.requiresMfa
        SessionControls    = _Join $Friendly.sessionControls
    }
}

function Get-CapHygieneFindings {
<#
.SYNOPSIS
    Non-destructive hygiene / gap checks over the friendly policy set. Flags
    only; never changes anything.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$FriendlyPolicies)

    $findings = [System.Collections.Generic.List[object]]::new()
    function Add($sev, $code, $policy, $msg) {
        $findings.Add([ordered]@{ severity = $sev; code = $code; policyId = $policy.id; policyName = $policy.displayName; message = $msg })
    }

    $enabled = @($FriendlyPolicies | Where-Object { $_.state -eq 'enabled' })
    $anyLegacyBlock = $false

    foreach ($p in $FriendlyPolicies) {
        if ($p.state -eq 'disabled') { Add 'info' 'DISABLED' $p 'Policy is disabled and has no effect.' }
        if ($p.state -eq 'enabledForReportingButNotEnforced') { Add 'info' 'REPORT_ONLY' $p 'Policy is in report-only mode (not enforced).' }

        if ($p.state -eq 'enabled') {
            if (@($p.grantControls).Count -eq 0 -and @($p.sessionControls).Count -eq 0) {
                Add 'warning' 'NO_CONTROLS' $p 'Enabled policy grants access with no grant or session controls.'
            }
            if (-not $p.isBlock -and -not $p.requiresMfa -and @($p.grantControls).Count -gt 0 -and
                -not ($p.grantControls -contains 'compliantDevice' -or $p.grantControls -contains 'domainJoinedDevice')) {
                Add 'info' 'NO_STRONG_AUTH' $p 'Enabled grant policy requires neither MFA/auth-strength nor a compliant/hybrid device.'
            }
            # Legacy auth block detection: block + only legacy client app types.
            $legacyTypes = @('exchangeActiveSync', 'other')
            $onlyLegacy = (@($p.clientAppTypes).Count -gt 0) -and (@($p.clientAppTypes | Where-Object { $_ -notin $legacyTypes }).Count -eq 0)
            if ($p.isBlock -and $onlyLegacy) { $anyLegacyBlock = $true }

            # Broad targeting without exclusions (break-glass risk).
            if ($p.includeUsers -contains 'All' -and @($p.excludeUsers).Count -eq 0 -and @($p.excludeGroups).Count -eq 0 -and @($p.excludeRoles).Count -eq 0) {
                Add 'warning' 'NO_BREAKGLASS_EXCLUSION' $p 'Targets All users with no user/group/role exclusion (verify emergency-access accounts are excluded).'
            }
        }
    }

    if ($enabled.Count -gt 0 -and -not $anyLegacyBlock) {
        $findings.Add([ordered]@{ severity = 'warning'; code = 'NO_LEGACY_AUTH_BLOCK'; policyId = ''; policyName = ''; message = 'No enabled policy appears to block legacy authentication (exchangeActiveSync/other).' })
    }

    return @($findings)
}

function New-CapSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Export,
        [Parameter(Mandatory)]$FriendlyPolicies,
        [Parameter(Mandatory)]$Findings
    )
    $stateMap = [ordered]@{}
    foreach ($p in $FriendlyPolicies) {
        $st = $p.state
        if ([string]::IsNullOrEmpty($st)) { $st = 'unknown' }
        if ($stateMap.Contains($st)) { $stateMap[$st] = $stateMap[$st] + 1 }
        else { $stateMap[$st] = 1 }
    }

    return [ordered]@{
        tenantId        = $Export.metadata.tenantId
        generatedUtc    = $Export.metadata.generatedUtc
        totalPolicies   = @($FriendlyPolicies).Count
        byState         = $stateMap
        blockPolicies   = @($FriendlyPolicies | Where-Object { $_.isBlock }).Count
        mfaPolicies     = @($FriendlyPolicies | Where-Object { $_.requiresMfa }).Count
        namedLocations  = @($Export.namedLocations).Count
        authStrengths   = @($Export.authenticationStrengths).Count
        findingCounts   = [ordered]@{
            warning = @($Findings | Where-Object { $_.severity -eq 'warning' }).Count
            info    = @($Findings | Where-Object { $_.severity -eq 'info' }).Count
        }
    }
}

Export-ModuleMember -Function ConvertTo-CapFriendlyPolicy, ConvertTo-CapCsvRow, Get-CapHygieneFindings, New-CapSummary
