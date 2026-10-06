<#
.SYNOPSIS
    CAPVisualizer rationalization & consolidation engine. Compares every policy
    against every other to surface duplicates, same-effect overlaps, and safe
    merge candidates, then reports dead weight (disabled + stuck report-only),
    best-practice completeness gaps, and exclusion concentration - so a sprawling
    estate can be reduced with no loss of protection.

.DESCRIPTION
    The existing engines answer "is each policy correct?" (audit) and "what
    changed since last run?" (delta). Neither compares two DIFFERENT policies to
    each other. This module fills that gap: it reduces each normalized policy to a
    functional fingerprint (control / apps / target / conditions) and clusters on
    it.

      - exact duplicate  = all four fingerprint parts identical
      - overlap          = same control + same apps (may differ by target/cond -
                           a distinct control, NOT necessarily a duplicate)
      - merge candidate  = same control + target + conditions, apps differ (these
                           can be combined into one policy with a merged app list)

    Guardrail: same effect + same apps but DIFFERENT conditions (trusted-IP vs
    country vs legacy-client) are distinct controls, not duplicates. Overlap
    clusters are therefore flagged for review, not auto-merged.

    Pure functions over the normalized policy shape (see CapNormalize.psm1). No
    Graph calls, no side effects, safe fully offline. Authored independently
    against the public Entra Conditional Access evaluation model; no third-party
    tool code or logic is reused.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Well-known resource ids used by the completeness scan.
$script:CapAzureMgmtAppId = '797f4846-ba00-4fd7-ba43-dac1f8f63013'   # Windows Azure Service Management API
$script:CapRegSecInfoAction = 'urn:user:registersecurityinfo'

function _CsJoin {
    # Deterministic, order-independent join of a value into a sorted string.
    param($Value)
    if ($null -eq $Value) { return '' }
    $arr = @($Value | ForEach-Object { "$_" } | Where-Object { $_ -ne '' } | Sort-Object -Unique)
    return ($arr -join ',')
}

function Get-CapPolicyFingerprint {
<#
.SYNOPSIS
    Reduce one normalized policy to its functional fingerprint: four order-
    independent signatures (control / apps / target / conditions) plus a combined
    key. Two policies with the same combined key do exactly the same thing.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$NormalizedPolicy)

    $p = $NormalizedPolicy
    $g = $p.grant

    $control = if ($g.block) { 'BLOCK' } else { 'GRANT:' + (_CsJoin $g.controls) }
    $controlSig = "$control|op=$($g.operator)|as=$($g.authStrengthId)|mfa=$($g.requireMfa)|comp=$($g.requireCompliant)|hyb=$($g.requireHybrid)|sess=$($p.hasSession)"

    $apps = $p.conditions.applications
    if ($apps.includeAll) {
        $appSig = 'ALL'
    }
    else {
        $inc = _CsJoin (@($apps.includeAppIds) + @($apps.includeGroupings))
        $appSig = "inc=$inc;ua=$(_CsJoin $apps.userActions);ac=$(_CsJoin $apps.authContexts)"
    }
    $appSig += "|exc=$(_CsJoin $apps.excludeAppIds)"

    $u = $p.conditions.users
    $gIn  = "$($u.includeGuests)" + $(if ($u.includeGuestTypes) { ":$(_CsJoin $u.includeGuestTypes)" } else { '' }) +
            $(if ($u.includeGuestTenantMode) { "@$($u.includeGuestTenantMode)" } else { '' }) +
            $(if ($u.includeGuestTenants) { "/$(_CsJoin $u.includeGuestTenants)" } else { '' })
    $gEx  = "$($u.excludeGuests)" + $(if ($u.excludeGuestTypes) { ":$(_CsJoin $u.excludeGuestTypes)" } else { '' }) +
            $(if ($u.excludeGuestTenantMode) { "@$($u.excludeGuestTenantMode)" } else { '' }) +
            $(if ($u.excludeGuestTenants) { "/$(_CsJoin $u.excludeGuestTenants)" } else { '' })
    # Guest scope belongs in the fingerprint. Without the types and the external
    # tenant list, two policies delegating access to two different partner
    # organisations look like the same policy.
    $targetSig = "all=$($u.includeAll);guest=$gIn;u=$(_CsJoin $u.includeUsers);grp=$(_CsJoin $u.includeGroups);rol=$(_CsJoin $u.includeRoles)" +
                 "|exu=$(_CsJoin $u.excludeUsers);exg=$(_CsJoin $u.excludeGroups);exr=$(_CsJoin $u.excludeRoles);exguest=$gEx"

    $plat = if ($null -ne $p.conditions.platforms) { _CsJoin $p.conditions.platforms.effective } else { 'any' }
    $cli  = if ($p.conditions.clientApps.isAll) { 'all' } else { _CsJoin $p.conditions.clientApps.effective }
    $loc  = 'any'
    if ($null -ne $p.conditions.locations) {
        $l = $p.conditions.locations
        $loc = "inclAll=$($l.includeAll);inclTrust=$($l.includeAllTrusted);inc=$(_CsJoin $l.includeIds);excAll=$($l.excludeAll);excTrust=$($l.excludeAllTrusted);exc=$(_CsJoin $l.excludeIds)"
    }
    $risk = "sir=$(_CsJoin $p.conditions.signInRisk);ur=$(_CsJoin $p.conditions.userRisk);spr=$(_CsJoin $p.conditions.servicePrincipalRisk);ir=$(_CsJoin $p.conditions.insiderRisk);ar=$(_CsJoin $p.conditions.agentRisk)"
    $dev = if ($null -ne $p.conditions.deviceFilter) { "$($p.conditions.deviceFilter.mode):$($p.conditions.deviceFilter.rule)" } else { 'none' }
    $condSig = "plat=$plat|cli=$cli|loc=$loc|$risk|flows=$(_CsJoin $p.conditions.authFlows)|dev=$dev"

    [ordered]@{
        id          = $p.id
        displayName = $p.displayName
        state       = $p.state
        controlSig  = $controlSig
        appSig      = $appSig
        targetSig   = $targetSig
        condSig     = $condSig
        key         = "$controlSig##$appSig##$targetSig##$condSig"
    }
}

function Find-CapDuplicatePolicies {
<#
.SYNOPSIS
    Cluster policies by functional fingerprint into exact duplicates, same-effect
    overlaps (control + apps), and merge candidates (control + target + conditions,
    apps differ).

.OUTPUTS
    Ordered hashtable { exact[], overlap[], merge[] }. Exact duplicates consider
    policies in any state; overlap and merge consider enforced (enabled) policies
    only, since those are the actionable ones.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$NormalizedPolicies)

    $fps = @($NormalizedPolicies | ForEach-Object { Get-CapPolicyFingerprint -NormalizedPolicy $_ })
    $enforcedIds = @{}
    foreach ($p in @($NormalizedPolicies)) { if ($p.enforced) { $enforcedIds[$p.id] = $true } }

    $member = { param($f) [ordered]@{ id = $f.id; displayName = $f.displayName; state = $f.state } }

    # Exact duplicates - any state.
    $exact = [System.Collections.Generic.List[object]]::new()
    foreach ($grp in ($fps | Group-Object { $_.key } | Where-Object { $_.Count -gt 1 })) {
        $g0 = $grp.Group[0]
        $exact.Add([ordered]@{
            controlSig = $g0.controlSig
            appSig     = $g0.appSig
            members    = @($grp.Group | ForEach-Object { & $member $_ })
            count      = $grp.Count
        })
    }

    # Overlap - same control + same apps, enforced only. Flag whether members
    # actually differ by target/conditions (then they are distinct controls, not
    # duplicates, and must NOT be blindly merged).
    $enforcedFps = @($fps | Where-Object { $enforcedIds.ContainsKey($_.id) })
    $overlap = [System.Collections.Generic.List[object]]::new()
    foreach ($grp in ($enforcedFps | Group-Object { "$($_.controlSig)##$($_.appSig)" } | Where-Object { $_.Count -gt 1 })) {
        $identical = (@($grp.Group | ForEach-Object { $_.key } | Select-Object -Unique).Count -eq 1)
        $overlap.Add([ordered]@{
            controlSig      = $grp.Group[0].controlSig
            appSig          = $grp.Group[0].appSig
            members         = @($grp.Group | ForEach-Object { [ordered]@{ id = $_.id; displayName = $_.displayName; targetSig = $_.targetSig; condSig = $_.condSig } })
            count           = $grp.Count
            identical       = $identical
            differsByTargetOrConditions = (-not $identical)
            note            = if ($identical) { 'Identical effect, target and conditions - true duplicate, keep one.' }
                              else { 'Same control on the same apps but different target/conditions - distinct controls; review before merging.' }
        })
    }

    # Merge candidates - same control + target + conditions, apps differ, enforced.
    $merge = [System.Collections.Generic.List[object]]::new()
    foreach ($grp in ($enforcedFps | Group-Object { "$($_.controlSig)##$($_.targetSig)##$($_.condSig)" } | Where-Object { $_.Count -gt 1 })) {
        $distinctApps = @($grp.Group | ForEach-Object { $_.appSig } | Select-Object -Unique)
        if ($distinctApps.Count -lt 2) { continue }   # identical apps -> already an exact/overlap cluster
        $merge.Add([ordered]@{
            controlSig = $grp.Group[0].controlSig
            members    = @($grp.Group | ForEach-Object { [ordered]@{ id = $_.id; displayName = $_.displayName; appSig = $_.appSig } })
            count      = $grp.Count
            note       = 'Same control, target and conditions on different apps - combine into one policy with a merged application list.'
        })
    }

    [ordered]@{ exact = @($exact); overlap = @($overlap); merge = @($merge) }
}

function Get-CapDeadWeight {
<#
.SYNOPSIS
    Policies that enforce nothing today: disabled, stuck in report-only, or whose
    name signals they should be retired (test / check / leave disabled / etc).
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$NormalizedPolicies)

    $retirePattern = '(?i)\b(test|check|chk|leave\s*disabled|deprecat|obsolete|old|do\s*not\s*use|dnu|delete|remove|temp|poc|demo)\b|(^|\s)xx|_x$'
    # A name that says "DO NOT DELETE" is the strongest possible statement that a
    # policy must be kept, and the bare word 'delete' above matches inside it. Left
    # unguarded, the toolchain recommends deleting exactly the policies whose names
    # exist to prevent that, which is how two managed-provider policies ended up in
    # a customer's deletion list. Suppress the name signal whenever the match is
    # negated. 'do not use' stays a retire signal: it means the policy is out of
    # service, not that it must be preserved.
    $keepPattern = '(?i)\bdo\s*not\s*(delete|remove|modify|touch|change|disable|alter|edit)\b|\bdon''t\s*(delete|remove|modify|touch|change|disable)\b'
    $items = [System.Collections.Generic.List[object]]::new()
    foreach ($p in @($NormalizedPolicies)) {
        $reasons = [System.Collections.Generic.List[string]]::new()
        if (-not $p.enforced -and -not $p.reportOnly) { [void]$reasons.Add('disabled - enforces nothing') }
        if ($p.reportOnly) { [void]$reasons.Add('report-only - telemetry only, not enforced') }
        if ($p.displayName -match $retirePattern -and $p.displayName -notmatch $keepPattern) {
            [void]$reasons.Add('name suggests a test/temporary/retire policy')
        }
        if ($reasons.Count) {
            $items.Add([ordered]@{
                id          = $p.id
                displayName = $p.displayName
                state       = $p.state
                reportOnly  = $p.reportOnly
                reasons     = @($reasons)
            })
        }
    }
    @($items)
}

function Test-CapBaselineCompleteness {
<#
.SYNOPSIS
    Scan the estate for baseline best-practice controls that should exist. Each
    result is { control, present, severity, detail, recommendation }. Absence is
    the gap; a report-only-only implementation counts as "not enforced".
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$NormalizedPolicies)

    $pols = @($NormalizedPolicies)
    $enforced = @($pols | Where-Object { $_.enforced })

    # A control is only a tenant control if something broad is in scope. An
    # enabled policy that names three individuals is a pilot, not protection,
    # and reporting it as present is how a real gap gets signed off as covered.
    #   tenant   - all users are in scope
    #   targeted - groups, roles or the guest selector; breadth is a directory
    #              fact this tool cannot see offline, so it is credited
    #   narrow   - a handful of named users only
    $scopeOf = {
        param($p)
        $u = $p.conditions.users
        if ($u.includeAll) { return 'tenant' }
        if (@($u.includeGroups).Count -or @($u.includeRoles).Count -or $u.includeGuests) { return 'targeted' }
        if (@($u.includeUsers).Count) { return 'narrow' }
        return 'none'
    }

    $results = [System.Collections.Generic.List[object]]::new()

    # Adds a control whose presence is qualified by the scope of the policies
    # that implement it. 'present' stays a plain boolean for existing consumers,
    # it is simply no longer satisfied by a narrowly scoped implementation.
    $addScoped = {
        param($control, $matched, $severity, $detail, $recommendation)
        $m = @($matched)
        $scopes = @($m | ForEach-Object { & $scopeOf $_ })
        $broad = @($m | Where-Object { (& $scopeOf $_) -in @('tenant', 'targeted') })
        $narrow = $m.Count - $broad.Count
        $coverage = if (-not $m.Count) { 'none' }
        elseif ($scopes -contains 'tenant') { 'tenant' }
        elseif ($broad.Count) { 'targeted' }
        else { 'narrow' }

        $note = ''
        if ($coverage -eq 'narrow') {
            $note = " Every implementing policy targets named individuals only, so this is a pilot rather than a tenant control and is reported as a gap."
        }
        elseif ($narrow -gt 0) {
            $note = " $narrow of them target named individuals only and do not count towards coverage."
        }

        $results.Add([ordered]@{
            control        = $control
            present        = [bool]($coverage -in @('tenant', 'targeted'))
            coverage       = $coverage
            enforcedCount  = $m.Count
            broadCount     = $broad.Count
            narrowCount    = $narrow
            severity       = $severity
            detail         = ($detail + $note)
            recommendation = $recommendation
        })
    }

    # Graph stores conditions.authenticationFlows.transferMethods as a comma-joined
    # string ("deviceCodeFlow,authenticationTransfer"); the normalizer keeps it as a
    # single element, so expand + split before testing membership.
    $flowTokens = {
        param($p)
        @(@($p.conditions.authFlows) | ForEach-Object { "$_" -split '[,\s]+' } | Where-Object { $_ })
    }

    $blocksDeviceCode = @($enforced | Where-Object { $_.grant.block -and ((& $flowTokens $_) -contains 'deviceCodeFlow') })
    & $addScoped 'Block device-code flow' $blocksDeviceCode 'high' `
        "$($blocksDeviceCode.Count) enforced policy(ies) block device-code flow (Authentication Flows condition)." `
        'Add an enabled Block policy with the Authentication Flows = device code flow condition, targeting all users, excluding break-glass and any Teams/Poly device resource-account group + the Device Registration Service.'

    $controlsTransfer = @($enforced | Where-Object { (& $flowTokens $_) -contains 'authenticationTransfer' })
    & $addScoped 'Control authentication transfer' $controlsTransfer 'medium' `
        "$($controlsTransfer.Count) enforced policy(ies) reference the authentication-transfer flow." `
        'Add a policy that governs the authentication-transfer flow (Authentication Flows condition).'

    $azureMgmtMfa = @($enforced | Where-Object {
            $_.grant.requireMfa -and ($_.conditions.applications.includeAll -or (@($_.conditions.applications.includeAppIds) -contains $script:CapAzureMgmtAppId))
        })
    & $addScoped 'MFA for Azure management' $azureMgmtMfa 'high' `
        "$($azureMgmtMfa.Count) enforced policy(ies) require MFA covering the Azure management API ($script:CapAzureMgmtAppId or All apps)." `
        'Require MFA (ideally phishing-resistant) for the Windows Azure Service Management API / Microsoft Admin Portals.'

    $userRisk = @($enforced | Where-Object { @($_.conditions.userRisk).Count -and $_.grant.hasControls })
    & $addScoped 'User-risk policy' $userRisk 'high' `
        "$($userRisk.Count) enforced policy(ies) act on user risk levels." `
        'Add a high user-risk policy (require secure password change / block). Requires Entra ID Protection (P2).'

    $signInRisk = @($enforced | Where-Object { @($_.conditions.signInRisk).Count -and $_.grant.hasControls })
    & $addScoped 'Sign-in-risk policy' $signInRisk 'high' `
        "$($signInRisk.Count) enforced policy(ies) act on sign-in risk levels." `
        'Add a high sign-in-risk policy (require MFA / block). Requires Entra ID Protection (P2).'

    $authStrength = @($enforced | Where-Object { $_.grant.authStrengthId })
    $adminStrength = @($authStrength | Where-Object { @($_.conditions.users.includeRoles).Count })
    & $addScoped 'Phishing-resistant strength for admins' $adminStrength 'high' `
        "$($authStrength.Count) enforced policy(ies) use an authentication-strength control, $($adminStrength.Count) of them scoped to directory roles." `
        'Require a phishing-resistant authentication strength for privileged directory roles.'

    $secReg = @($enforced | Where-Object { @($_.conditions.applications.userActions) -contains $script:CapRegSecInfoAction })
    & $addScoped 'Secure security-info registration' $secReg 'medium' `
        "$($secReg.Count) enforced policy(ies) target the register-security-info user action." `
        'Add a policy on the "Register security information" user action (trusted network / compliant device).'

    $tokenProt = @($enforced | Where-Object { $_.hasSession })
    & $addScoped 'Token protection / session hardening' $tokenProt 'info' `
        "$($tokenProt.Count) enforced policy(ies) apply session controls (token protection cannot be fully confirmed offline - verify in portal)." `
        'Pilot token protection (sign-in session token binding) for Exchange/SharePoint on Windows; enable Continuous Access Evaluation.'

    @($results)
}

function Get-CapExclusionConcentration {
<#
.SYNOPSIS
    Rank the principals (users/groups/roles) that recur most often as exclusions
    across ENFORCED policies. High-recurrence exclusion groups are the real-world
    bypass surface and prime consolidation targets. Optionally resolves names.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$NormalizedPolicies,
        [hashtable]$NameMap = @{},
        $UnreadShapes = @()
    )

    $acc = @{}   # id -> { id, type, policies[] }
    foreach ($p in @($NormalizedPolicies)) {
        if (-not $p.enforced) { continue }
        $exclusions = @(
            @($p.conditions.users.excludeUsers)  | ForEach-Object { @{ id = "$_"; type = 'user' } }
            @($p.conditions.users.excludeGroups) | ForEach-Object { @{ id = "$_"; type = 'group' } }
            @($p.conditions.users.excludeRoles)  | ForEach-Object { @{ id = "$_"; type = 'role' } }
        )
        foreach ($ex in $exclusions) {
            $id = $ex.id
            if ([string]::IsNullOrWhiteSpace($id)) { continue }
            if (-not $acc.ContainsKey($id)) {
                $acc[$id] = [ordered]@{ id = $id; type = $ex.type; displayName = $(if ($NameMap.ContainsKey($id)) { $NameMap[$id] } else { $null }); policies = [System.Collections.Generic.List[string]]::new() }
            }
            $acc[$id].policies.Add($p.id)
        }
    }

    @($acc.Values | ForEach-Object {
        [ordered]@{ id = $_.id; type = $_.type; displayName = $_.displayName; policyCount = @($_.policies).Count; policies = @($_.policies) }
    } | Sort-Object -Property @{ Expression = 'policyCount'; Descending = $true }, @{ Expression = 'id' })
}

function Invoke-CapConsolidate {
<#
.SYNOPSIS
    Run the full rationalization pass over a normalized policy set: duplicates,
    overlaps, merge candidates, dead weight, completeness gaps and exclusion
    concentration, plus a summary with an estimated before -> after policy count.

.OUTPUTS
    Ordered hashtable { summary, duplicates{exact,overlap,merge}, deadWeight[],
    completeness[], exclusionConcentration[] }.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$NormalizedPolicies,
        [hashtable]$NameMap = @{},
        $UnreadShapes = @()
    )

    $pols = @($NormalizedPolicies)
    $dupes        = Find-CapDuplicatePolicies -NormalizedPolicies $pols
    $deadWeight   = Get-CapDeadWeight -NormalizedPolicies $pols
    $completeness = Test-CapBaselineCompleteness -NormalizedPolicies $pols
    $exclusion    = Get-CapExclusionConcentration -NormalizedPolicies $pols -NameMap $NameMap

    $total      = $pols.Count
    $enforced   = @($pols | Where-Object { $_.enforced }).Count
    $reportOnly = @($pols | Where-Object { $_.reportOnly }).Count
    $disabled   = @($pols | Where-Object { -not $_.enforced -and -not $_.reportOnly }).Count

    # Estimated end state: start from the enforced count (report-only + disabled
    # are dropped anyway, so they are not in this base and cannot be double-counted),
    # then collapse each exact-duplicate and merge cluster among ENABLED members.
    $enabledExactExtra = 0
    foreach ($c in @($dupes.exact)) {
        $enabledMembers = @($c.members | Where-Object { $_.state -eq 'enabled' }).Count
        if ($enabledMembers -gt 1) { $enabledExactExtra += ($enabledMembers - 1) }
    }
    $mergeExtra = 0
    foreach ($c in @($dupes.merge)) { $mergeExtra += ($c.count - 1) }
    $target = [Math]::Max(0, $enforced - $enabledExactExtra - $mergeExtra)
    $reductions = $total - $target

    $gaps = @($completeness | Where-Object { -not $_.present })

    [ordered]@{
        summary = [ordered]@{
            total                 = $total
            enforced              = $enforced
            reportOnly            = $reportOnly
            disabled              = $disabled
            exactDuplicateClusters= @($dupes.exact).Count
            overlapClusters       = @($dupes.overlap).Count
            mergeCandidateClusters= @($dupes.merge).Count
            deadWeightCount       = @($deadWeight).Count
            completenessGaps      = @($gaps).Count
            estimatedTarget       = $target
            estimatedReduction    = $reductions
        }
        duplicates            = $dupes
        deadWeight            = @($deadWeight)
        completeness          = @($completeness)
        exclusionConcentration= @($exclusion)
        # Condition data present in the export that the model does not read.
        # Carried alongside the verdicts rather than logged and forgotten,
        # because it is the one thing that says how far the verdicts can be
        # trusted. Path and count only: a sample value can be a device filter
        # rule, which is tenant data.
        unreadShapes = @(@($UnreadShapes) | ForEach-Object {
            [ordered]@{ path = $_.path; count = $_.count; policyIds = @($_.policyIds) }
        })
    }
}

Export-ModuleMember -Function Get-CapPolicyFingerprint, Find-CapDuplicatePolicies, `
    Get-CapDeadWeight, Test-CapBaselineCompleteness, Get-CapExclusionConcentration, `
    Invoke-CapConsolidate
