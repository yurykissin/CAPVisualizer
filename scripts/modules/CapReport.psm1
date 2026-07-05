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

    $sessionSummary = @()
    if ($sess) {
        $sf = _Get $sess 'signInFrequency'
        if ($sf -and (_Get $sf 'isEnabled')) { $sessionSummary += "SignInFrequency=$(_Get $sf 'value') $(_Get $sf 'type')" }
        $pb = _Get $sess 'persistentBrowser'
        if ($pb -and (_Get $pb 'isEnabled')) { $sessionSummary += "PersistentBrowser=$(_Get $pb 'mode')" }
        $cas = _Get $sess 'cloudAppSecurity'
        if ($cas -and (_Get $cas 'isEnabled')) { $sessionSummary += "CloudAppSecurity=$(_Get $cas 'cloudAppSecurityType')" }
        $aer = _Get $sess 'applicationEnforcedRestrictions'
        if ($aer -and (_Get $aer 'isEnabled')) { $sessionSummary += 'AppEnforcedRestrictions' }
        $cae = _Get $sess 'continuousAccessEvaluation'
        if ($cae -and (_Get $cae 'mode')) { $sessionSummary += "CAE=$(_Get $cae 'mode')" }
    }

    $deviceFilter = $null
    $devices = _Get $c 'devices'
    $df = _Get $devices 'deviceFilter'
    if ($df) { $deviceFilter = "$(_Get $df 'mode'): $(_Get $df 'rule')" }

    return [ordered]@{
        id                    = _Get $Policy 'id'
        displayName           = _Get $Policy 'displayName'
        state                 = _Get $Policy 'state'
        createdDateTime       = _Get $Policy 'createdDateTime'
        modifiedDateTime      = _Get $Policy 'modifiedDateTime'

        includeUsers          = Names (_Get $users 'includeUsers')
        excludeUsers          = Names (_Get $users 'excludeUsers')
        includeGroups         = Names (_Get $users 'includeGroups')
        excludeGroups         = Names (_Get $users 'excludeGroups')
        includeRoles          = Names (_Get $users 'includeRoles')
        excludeRoles          = Names (_Get $users 'excludeRoles')
        includeGuestsExternal = _Get $users 'includeGuestsOrExternalUsers'
        excludeGuestsExternal = _Get $users 'excludeGuestsOrExternalUsers'

        includeApplications   = Apps (_Get $apps 'includeApplications')
        excludeApplications   = Apps (_Get $apps 'excludeApplications')
        includeUserActions    = @(_Get $apps 'includeUserActions')
        authenticationContext = @(_Get $apps 'includeAuthenticationContextClassReferences')

        clientAppTypes        = @(_Get $c 'clientAppTypes')
        includePlatforms      = @(_Get $platforms 'includePlatforms')
        excludePlatforms      = @(_Get $platforms 'excludePlatforms')
        includeLocations      = Locs (_Get $locations 'includeLocations')
        excludeLocations      = Locs (_Get $locations 'excludeLocations')
        signInRiskLevels      = @(_Get $c 'signInRiskLevels')
        userRiskLevels        = @(_Get $c 'userRiskLevels')
        deviceFilter          = $deviceFilter

        grantOperator         = _Get $grant 'operator'
        grantControls         = $grantControls
        authenticationStrength = $authStrength
        termsOfUse            = @(_Get $grant 'termsOfUse')
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
        IncludeApps        = _Join $Friendly.includeApplications
        ExcludeApps        = _Join $Friendly.excludeApplications
        UserActions        = _Join $Friendly.includeUserActions
        AuthContext        = _Join $Friendly.authenticationContext
        ClientAppTypes     = _Join $Friendly.clientAppTypes
        IncludePlatforms   = _Join $Friendly.includePlatforms
        ExcludePlatforms   = _Join $Friendly.excludePlatforms
        IncludeLocations   = _Join $Friendly.includeLocations
        ExcludeLocations   = _Join $Friendly.excludeLocations
        SignInRisk         = _Join $Friendly.signInRiskLevels
        UserRisk           = _Join $Friendly.userRiskLevels
        DeviceFilter       = $Friendly.deviceFilter
        GrantOperator      = $Friendly.grantOperator
        GrantControls      = _Join $Friendly.grantControls
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
    $byState = $FriendlyPolicies | Group-Object state | ForEach-Object { @{ $_.Name = $_.Count } }
    $stateMap = [ordered]@{}
    foreach ($h in $byState) { foreach ($k in $h.Keys) { $stateMap[$k] = $h[$k] } }

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
