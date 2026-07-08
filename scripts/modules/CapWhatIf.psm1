<#
.SYNOPSIS
    CAPVisualizer offline what-if engine (Phase 3). Simulates a sign-in against
    the normalized policy set and classifies each policy as Applied(definitive),
    Applied(signal-dependent), or NotApplied - then computes the cumulative
    enforcement outcome (block / MFA / other controls). Fully offline.

.DESCRIPTION
    Offline evaluation cannot know signals that Entra only resolves at sign-in
    (sign-in/user risk, location, client app, device state, auth flow) unless the
    caller supplies them. This engine makes that explicit: a policy whose
    remaining gating condition depends on an unsupplied signal is reported as
    "could apply" (signal-dependent) with the missing signal named, rather than
    guessing. This mirrors how a definitive policy differs from a contingent one.

    Authored independently from public Microsoft documentation of the CA
    evaluation model; no third-party tool code or logic is reused.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function _WArr { param($v) if ($null -eq $v) { return @() }; if ($v -is [string]) { return @($v) }; if ($v -is [System.Collections.IEnumerable]) { return @($v | ForEach-Object { "$_" }) }; @("$v") }

# ---- Per-condition matchers: return 'match' | 'nomatch' | 'unknown' ----------

function _MatchResource {
    param($AppsCond, [string]$Resource)
    if (-not $Resource) {
        # No resource supplied: applicability depends on the target resource.
        if ($AppsCond.includeNone) { return 'nomatch' }
        return 'unknown'
    }
    if ($AppsCond.includeNone) { return 'nomatch' }
    if (@(_WArr $AppsCond.excludeAppIds) -contains $Resource) { return 'nomatch' }
    if ($AppsCond.includeAll) { return 'match' }
    if (@(_WArr $AppsCond.includeAppIds) -contains $Resource) { return 'match' }
    return 'nomatch'
}

function _MatchPlatform {
    param($PlatformCanon, [string]$Platform)
    if ($null -eq $PlatformCanon) { return 'match' }       # no platform constraint
    if (-not $Platform) { return 'unknown' }
    if (@(_WArr $PlatformCanon.effective) -contains $Platform) { return 'match' } else { return 'nomatch' }
}

function _MatchClientApp {
    param($ClientCanon, [string]$ClientApp)
    if ($ClientCanon.isAll) { return 'match' }             # applies to every client app
    if (-not $ClientApp) { return 'unknown' }
    $c = $ClientApp
    if ($c -eq 'modern') { $c = 'mobileAppsAndDesktopClients' }
    $eff = @(_WArr $ClientCanon.effective)
    if ($c -eq 'legacy') {
        if ($eff | Where-Object { @('exchangeActiveSync', 'other') -contains $_ }) { return 'match' } else { return 'nomatch' }
    }
    if ($eff -contains $c) { return 'match' } else { return 'nomatch' }
}

function _MatchLocation {
    param($LocCanon, $Location)
    if ($null -eq $LocCanon) { return 'match' }            # no location constraint
    if (-not $Location) { return 'unknown' }
    # $Location: hashtable/string. Accept 'trusted'/'untrusted' or { trusted=$bool; id='...' }.
    $isTrusted = $false; $locId = $null
    if ($Location -is [string]) { $isTrusted = ($Location -eq 'trusted') }
    else { $isTrusted = [bool]($Location.trusted); $locId = "$($Location.id)" }

    $included = $false
    if ($LocCanon.includeAll) { $included = $true }
    if ($LocCanon.includeAllTrusted -and $isTrusted) { $included = $true }
    if ($locId -and (@(_WArr $LocCanon.includeIds) -contains $locId)) { $included = $true }

    $excluded = $false
    if ($LocCanon.excludeAll) { $excluded = $true }
    if ($LocCanon.excludeAllTrusted -and $isTrusted) { $excluded = $true }
    if ($locId -and (@(_WArr $LocCanon.excludeIds) -contains $locId)) { $excluded = $true }

    if ($excluded) { return 'nomatch' }
    if ($included) { return 'match' }
    return 'nomatch'
}

function _MatchRisk {
    param([string[]]$RequiredLevels, [string]$Supplied)
    $req = @(_WArr $RequiredLevels)
    if ($req.Count -eq 0) { return 'match' }               # no risk constraint
    if (-not $Supplied) { return 'unknown' }
    if ($req -contains $Supplied) { return 'match' } else { return 'nomatch' }
}

function Test-CapWhatIfPolicy {
<#
.SYNOPSIS
    Evaluate one normalized policy against a sign-in context + principal scope.

.OUTPUTS
    Ordered hashtable: policyId, policyName, state, applicability
    (Definitive|SignalDependent|NotApplied), reason, missingSignals[], and the
    grant summary for applied policies.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$NormalizedPolicy,
        [Parameter(Mandatory)]$ScopeResult,
        [Parameter(Mandatory)]$Context
    )

    $p = $NormalizedPolicy
    # Scope gate first.
    if ($ScopeResult.bucket -eq 'Excluded') {
        return _WhatIfResult $p 'NotApplied' "Principal excluded ($($ScopeResult.reason))" @()
    }
    if ($ScopeResult.bucket -eq 'NotInScope') {
        return _WhatIfResult $p 'NotApplied' 'Principal not targeted' @()
    }

    $statuses = [ordered]@{}
    $statuses['resource']   = _MatchResource   $p.conditions.applications $Context.Resource
    $statuses['platform']   = _MatchPlatform   $p.conditions.platforms    $Context.Platform
    $statuses['clientApp']  = _MatchClientApp  $p.conditions.clientApps   $Context.ClientApp
    $statuses['location']   = _MatchLocation   $p.conditions.locations    $Context.Location
    $statuses['signInRisk'] = _MatchRisk       $p.conditions.signInRisk   $Context.SignInRisk
    $statuses['userRisk']   = _MatchRisk       $p.conditions.userRisk     $Context.UserRisk
    $statuses['authFlow']   = _MatchAuthFlow   $p.conditions.authFlows    $Context.AuthFlow
    $statuses['deviceState']= _MatchDevice     $p.conditions.deviceFilter $Context.DeviceState

    $nomatch = @($statuses.GetEnumerator() | Where-Object { $_.Value -eq 'nomatch' } | ForEach-Object { $_.Key })
    if ($nomatch.Count) {
        return _WhatIfResult $p 'NotApplied' "Condition did not match: $($nomatch -join ', ')" @()
    }
    $unknown = @($statuses.GetEnumerator() | Where-Object { $_.Value -eq 'unknown' } | ForEach-Object { $_.Key })
    if ($unknown.Count) {
        return _WhatIfResult $p 'SignalDependent' "Depends on unsupplied signal(s): $($unknown -join ', ')" $unknown
    }
    return _WhatIfResult $p 'Definitive' 'All supplied conditions match' @()
}

function _MatchAuthFlow {
    param([string[]]$Required, [string]$Supplied)
    $req = @(_WArr $Required)
    if ($req.Count -eq 0) { return 'match' }
    if (-not $Supplied) { return 'unknown' }
    if ($req -contains $Supplied) { return 'match' } else { return 'nomatch' }
}

function _MatchDevice {
    param($DeviceFilter, [string]$DeviceState)
    if ($null -eq $DeviceFilter) { return 'match' }        # no device filter
    if (-not $DeviceState) { return 'unknown' }
    # Naive intent evaluation of the filter rule against a coarse device state.
    $rule = "$($DeviceFilter.rule)".ToLowerInvariant()
    $mode = "$($DeviceFilter.mode)".ToLowerInvariant()     # include|exclude
    $matchesRule = $false
    switch ($DeviceState) {
        'compliant' { $matchesRule = ($rule -match 'iscompliant\s*-eq\s*true') }
        'managed'   { $matchesRule = ($rule -match 'trusttype|iscompliant|domainjoined') }
        'unmanaged' { $matchesRule = -not ($rule -match 'iscompliant\s*-eq\s*true') }
        default     { return 'unknown' }
    }
    # mode=include: the policy applies to devices matching the rule.
    if ($mode -eq 'exclude') { if ($matchesRule) { return 'nomatch' } else { return 'match' } }
    if ($matchesRule) { return 'match' } else { return 'nomatch' }
}

function _WhatIfResult {
    param($Policy, [string]$Applicability, [string]$Reason, [string[]]$Missing)
    [ordered]@{
        policyId      = $Policy.id
        policyName    = $Policy.displayName
        state         = $Policy.state
        enforced      = $Policy.enforced
        reportOnly    = $Policy.reportOnly
        applicability = $Applicability
        reason        = $Reason
        missingSignals= @($Missing)
        grant         = $Policy.grant
    }
}

function Test-CapWhatIf {
<#
.SYNOPSIS
    Full offline what-if: evaluate all policies for a principal + sign-in context
    and compute the cumulative enforcement outcome.

.PARAMETER PrincipalId
    Object id of the signing-in principal.

.PARAMETER NormalizedPolicies
    Array of normalized policies.

.PARAMETER Enrichment
    export.enrichment block (for scope). Optional.

.PARAMETER Resource / Platform / ClientApp / Location / SignInRisk / UserRisk /
           AuthFlow / DeviceState
    Sign-in signals. Any omitted signal that a policy gates on makes that policy
    signal-dependent rather than definitive.

.OUTPUTS
    Ordered hashtable: principal, context, outcome (blocked, mfaRequired,
    grantControls, reportOnly[]), definitive[], signalDependent[], notApplied[].
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PrincipalId,
        [Parameter(Mandatory)]$NormalizedPolicies,
        $Enrichment,
        [string]$Resource,
        [ValidateSet('windows', 'macOS', 'iOS', 'android', 'linux', 'windowsPhone')][string]$Platform,
        [ValidateSet('browser', 'mobileAppsAndDesktopClients', 'exchangeActiveSync', 'other', 'modern', 'legacy')][string]$ClientApp,
        $Location,
        [ValidateSet('none', 'low', 'medium', 'high')][string]$SignInRisk,
        [ValidateSet('none', 'low', 'medium', 'high')][string]$UserRisk,
        [string]$AuthFlow,
        [ValidateSet('compliant', 'managed', 'unmanaged')][string]$DeviceState
    )

    $ctx = Resolve-CapPrincipalContext -PrincipalId $PrincipalId -Enrichment $Enrichment
    $signals = [ordered]@{
        Resource = $Resource; Platform = $Platform; ClientApp = $ClientApp; Location = $Location
        SignInRisk = $SignInRisk; UserRisk = $UserRisk; AuthFlow = $AuthFlow; DeviceState = $DeviceState
    }

    $definitive = [System.Collections.Generic.List[object]]::new()
    $signalDep  = [System.Collections.Generic.List[object]]::new()
    $notApplied = [System.Collections.Generic.List[object]]::new()

    foreach ($np in @($NormalizedPolicies)) {
        $scope = Test-CapPolicyScope -NormalizedPolicy $np -Context $ctx
        $r = Test-CapWhatIfPolicy -NormalizedPolicy $np -ScopeResult $scope -Context $signals
        switch ($r.applicability) {
            'Definitive'      { $definitive.Add($r) }
            'SignalDependent' { $signalDep.Add($r) }
            default           { $notApplied.Add($r) }
        }
    }

    # Cumulative enforcement over DEFINITIVE + ENFORCED policies. Report-only
    # policies are applied for reporting only and never enforce.
    $enforcedApplied = @($definitive | Where-Object { $_.enforced })
    $blocked = [bool](@($enforcedApplied | Where-Object { $_.grant.block }).Count)
    $mfaRequired = [bool](@($enforcedApplied | Where-Object { $_.grant.requireMfa }).Count)
    $controls = @($enforcedApplied | ForEach-Object { @(_WArr $_.grant.controls) } | ForEach-Object { $_ } | Sort-Object -Unique)
    $reportOnlyApplied = @($definitive | Where-Object { $_.reportOnly } | ForEach-Object { $_.policyName })

    $outcome = [ordered]@{
        blocked           = $blocked
        mfaRequired       = $mfaRequired
        grantControls     = @($controls)
        enforcedPolicyNames = @($enforcedApplied | ForEach-Object { $_.policyName })
        reportOnlyApplied = @($reportOnlyApplied)
        # A gap: nothing definitively enforces a block or MFA for this sign-in.
        noDefinitiveEnforcement = (-not $blocked -and -not $mfaRequired -and @($enforcedApplied | Where-Object { $_.grant.hasControls }).Count -eq 0)
    }

    return [ordered]@{
        principal      = $ctx
        context        = $signals
        outcome        = $outcome
        definitive     = @($definitive)
        signalDependent= @($signalDep)
        notApplied     = @($notApplied)
    }
}

Export-ModuleMember -Function Test-CapWhatIf, Test-CapWhatIfPolicy
