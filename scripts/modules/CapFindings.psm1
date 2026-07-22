<#
.SYNOPSIS
    CAPVisualizer risk-scored findings model (Phase 6). Produces a uniform,
    sortable finding schema with a deterministic impact x likelihood risk score
    over directory + policy state, and folds in the Phase 5 audit issues.

.DESCRIPTION
    Every finding carries { id, checkId, title, severity, impact, likelihood,
    riskScore, description, threat, remediation, affectedObjects[], references[] }.
    Severity is derived from the numeric risk score so ordering is objective and
    reproducible. References point only at public standards (MITRE ATT&CK, CISA
    SCuBA, NIST 800-53).

    Authored independently; no third-party tool code or logic is reused. The
    scoring model and thresholds below are original and documented in
    docs/FINDINGS.md.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function _FiArr { param($v) if ($null -eq $v) { return @() }; if ($v -is [string]) { return @($v) }; if ($v -is [System.Collections.IEnumerable]) { return @($v | ForEach-Object { $_ }) }; @($v) }

function _FiGet {
    param($Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [System.Collections.IDictionary]) { if ($Obj.Contains($Name)) { return $Obj[$Name] } return $null }
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    $null
}

function _FiToDate {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $s = "$Value"
    if (-not $s) { return $null }
    $parsed = [datetime]::MinValue
    if ([datetime]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$parsed)) { return $parsed }
    $null
}

function Get-CapSeverityFromScore {
<#
.SYNOPSIS
    Map a numeric risk score (impact x likelihood, 1-25) to a severity band.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][int]$RiskScore)
    if ($RiskScore -ge 20) { return 'critical' }
    if ($RiskScore -ge 12) { return 'high' }
    if ($RiskScore -ge 6)  { return 'medium' }
    if ($RiskScore -ge 1)  { return 'low' }
    'info'
}

function New-CapFinding {
<#
.SYNOPSIS
    Build one finding, computing riskScore = impact x likelihood and the derived
    severity band. Impact and likelihood are on a 1-5 scale.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CheckId,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][ValidateRange(1, 5)][int]$Impact,
        [Parameter(Mandatory)][ValidateRange(1, 5)][int]$Likelihood,
        [Parameter(Mandatory)][string]$Description,
        [string]$Summary = '',
        [string]$Logic = '',
        [string]$Threat = '',
        [string]$Remediation = '',
        [object[]]$AffectedObjects = @(),
        [string[]]$References = @()
    )
    $score = $Impact * $Likelihood
    [ordered]@{
        id              = ('{0}:{1}' -f $CheckId, ([Math]::Abs(($AffectedObjects -join ';').GetHashCode())))
        checkId         = $CheckId
        title           = $Title
        severity        = Get-CapSeverityFromScore -RiskScore $score
        impact          = $Impact
        likelihood      = $Likelihood
        riskScore       = $score
        description     = $Description
        summary         = $Summary
        logic           = $Logic
        threat          = $Threat
        remediation     = $Remediation
        affectedObjects = @($AffectedObjects)
        references      = @($References)
    }
}

# Metadata used when promoting Phase 5 audit issues into the finding schema.
$script:CapAuditFindingMeta = @{
    'app-include-exclude-overlap'  = @{ impact = 4; likelihood = 4; threat = 'Resource assumed protected is silently uncovered, allowing unconditioned access.'; remediation = 'Remove the conflicting exclusion or the redundant explicit include so the intended app is actually in scope.'; references = @('MITRE ATT&CK T1078'); logic = 'Detected when the same application appears in both the include and exclude application lists of a policy; the exclude wins, so the app is not actually protected.' }
    'platform-include-exclude-overlap' = @{ impact = 2; likelihood = 3; threat = 'Platform intended to be in scope is excluded, weakening coverage.'; remediation = 'Reconcile the platform include and exclude lists.'; references = @(); logic = 'Detected when the same device platform appears in both the include and exclude platform lists of a policy.' }
    'principal-include-exclude-overlap' = @{ impact = 2; likelihood = 2; threat = 'Principal is excluded despite being named for inclusion; the inclusion is a no-op.'; remediation = 'Remove the principal from either the include or the exclude list to reflect intent.'; references = @(); logic = 'Detected when the same user, group or role appears in both the include and exclude principal lists of a policy.' }
    'legacy-auth-not-blocked'      = @{ impact = 5; likelihood = 4; threat = 'Legacy protocols bypass MFA and modern controls, enabling password spray / credential stuffing.'; remediation = 'Add an enabled Block policy for All users / All apps with client apps = exchangeActiveSync + other.'; references = @('MITRE ATT&CK T1110', 'CISA SCuBA MS.AAD.1.1', 'NIST 800-53 IA-2'); logic = 'Detected when no enabled block policy for All users / All apps targets the legacy client-app types (exchangeActiveSync, other).' }
    'privileged-user-exempt'       = @{ impact = 5; likelihood = 3; threat = 'A privileged account is exempt from protection; compromise grants tenant-wide control.'; remediation = 'Remove the privileged account from the exclusion, or restrict the exclusion to dedicated break-glass identities only.'; references = @('MITRE ATT&CK T1078.004', 'CISA SCuBA MS.AAD.3.1'); logic = 'Detected when a user holding a privileged directory role is named directly in the exclude-users list of an enforced protective policy.' }
    'privileged-via-excluded-group' = @{ impact = 5; likelihood = 3; threat = 'Privileged members inherit an exclusion through group membership, escaping protection non-obviously.'; remediation = 'Ensure exclusion groups contain only intended break-glass accounts and are tightly governed.'; references = @('MITRE ATT&CK T1078.004', 'CISA SCuBA MS.AAD.3.1'); logic = 'Detected when a privileged-role holder is a member of a group that is in the exclude-groups list of an enforced protective policy.' }
}

function Get-CapDirectoryFindings {
<#
.SYNOPSIS
    Enrichment-driven findings: ownerless group in a CA exclusion, in-scope users
    lacking MFA capability, and inactive privileged accounts.

.PARAMETER InactiveDays
    Threshold (default 30) beyond which a privileged account's last sign-in is
    considered inactive, measured against enrichment.collectedUtc.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$NormalizedPolicies,
        $Enrichment,
        [int]$InactiveDays = 30
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    if (-not $Enrichment) { return @($findings) }

    $users  = @(_FiArr (_FiGet (_FiGet $Enrichment 'users') 'data'))
    $groups = @(_FiArr (_FiGet (_FiGet $Enrichment 'groups') 'data'))
    $mfa    = @(_FiArr (_FiGet (_FiGet $Enrichment 'mfaCapability') 'data'))
    $roles  = @(_FiArr (_FiGet (_FiGet $Enrichment 'roleAssignments') 'data'))

    $nameOf = @{}
    foreach ($u in $users)  { $nameOf["$(_FiGet $u 'id')"] = "$(_FiGet $u 'displayName')" }
    foreach ($g in $groups) { $nameOf["$(_FiGet $g 'id')"] = "$(_FiGet $g 'displayName')" }

    $privRoles = Get-CapPrivilegedRoleSet
    $privUsers = @{}
    foreach ($ra in $roles) {
        $rid = "$(_FiGet $ra 'roleTemplateId')"
        if ($privRoles.ContainsKey($rid)) { $privUsers["$(_FiGet $ra 'principalId')"] = "$(_FiGet $ra 'roleName')" }
    }

    # --- Ownerless group used in a CA exclusion ---
    $excludedGroupIds = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($p in @($NormalizedPolicies)) {
        if (-not $p.enforced) { continue }
        foreach ($gid in @(_FiArr $p.conditions.users.excludeGroups)) { [void]$excludedGroupIds.Add("$gid") }
    }
    foreach ($g in $groups) {
        $gid = "$(_FiGet $g 'id')"
        if ($excludedGroupIds.Contains($gid) -and [bool](_FiGet $g 'ownerless')) {
            $findings.Add((New-CapFinding -CheckId 'ownerless-exclusion-group' `
                -Title 'Ownerless group used as a Conditional Access exclusion' `
                -Impact 4 -Likelihood 3 `
                -Summary 'A group with no owner is used to exclude principals from one or more enforced policies, so its membership is ungoverned.' `
                -Logic 'Flagged when a group ID appears in excludeGroups of any enforced policy AND enrichment marks the group as ownerless.' `
                -Description "Group '$($nameOf[$gid])' is used to exclude principals from one or more enforced policies but has no owner, so its membership is ungoverned." `
                -Threat 'Membership of an ownerless exclusion group can be changed without accountability, silently exempting new accounts from protection.' `
                -Remediation 'Assign an accountable owner to the group and review its membership, or replace the exclusion with an explicitly enumerated break-glass account list.' `
                -AffectedObjects @($gid) `
                -References @('MITRE ATT&CK T1078', 'CISA SCuBA MS.AAD.3.1')))
        }
    }

    # --- In-scope users lacking MFA capability ---
    $mfaRequiringAllUsers = @($NormalizedPolicies | Where-Object { $_.enforced -and $_.grant.requireMfa -and $_.conditions.users.includeAll }).Count -ge 1
    foreach ($m in $mfa) {
        if (-not [bool](_FiGet $m 'isMfaCapable')) {
            $uid = "$(_FiGet $m 'userId')"
            $impact = if ($privUsers.ContainsKey($uid)) { 5 } else { 3 }
            $likelihood = if ($mfaRequiringAllUsers) { 4 } else { 2 }
            $findings.Add((New-CapFinding -CheckId 'user-not-mfa-capable' `
                -Title 'User is not capable of MFA' `
                -Impact $impact -Likelihood $likelihood `
                -Summary 'One or more in-scope users have no registered authentication method capable of satisfying multifactor authentication.' `
                -Logic 'Flagged per user when enrichment mfaCapability.isMfaCapable is false. Likelihood is raised when an enforced All-users policy requires MFA (lockout risk); impact is raised when the user holds a privileged role.' `
                -Description "$(if ($nameOf.ContainsKey($uid)) { $nameOf[$uid] } else { $uid }) has no registered method capable of satisfying multifactor authentication$(if ($privUsers.ContainsKey($uid)) { ' and holds a privileged role' } else { '' })." `
                -Threat 'An account with no MFA capability either cannot satisfy an MFA policy (lockout) or, if excluded, authenticates with a single factor - a prime target for credential theft.' `
                -Remediation 'Drive registration of a phishing-resistant authentication method for this user.' `
                -AffectedObjects @($uid) `
                -References @('MITRE ATT&CK T1078', 'CISA SCuBA MS.AAD.3.2', 'NIST 800-53 IA-2(1)')))
        }
    }

    # --- Inactive / disabled privileged accounts ---
    $now = _FiToDate (_FiGet $Enrichment 'collectedUtc')
    if (-not $now) { $now = (Get-Date).ToUniversalTime() }
    foreach ($u in $users) {
        $uid = "$(_FiGet $u 'id')"
        if (-not $privUsers.ContainsKey($uid)) { continue }
        $uname = if ($nameOf.ContainsKey($uid)) { $nameOf[$uid] } else { $uid }

        # Disabled privileged account: role still assigned to a blocked sign-in.
        $enabledVal = _FiGet $u 'accountEnabled'
        if ($enabledVal -is [bool] -and -not $enabledVal) {
            $findings.Add((New-CapFinding -CheckId 'disabled-privileged-account' `
                -Title 'Privileged account is disabled' `
                -Impact 4 -Likelihood 3 `
                -Summary 'A disabled account still holds a privileged directory role, leaving a dormant grant that can be reactivated.' `
                -Logic 'Flagged when an account with an active privileged role assignment has accountEnabled = false in enrichment.' `
                -Description "$uname holds $($privUsers[$uid]) but the account is disabled (accountEnabled = false)." `
                -Threat 'A disabled account retains its role assignment; if it is ever re-enabled (deliberately or by a compromised admin) it instantly regains privileged access with no fresh review.' `
                -Remediation 'Remove the privileged role assignment from disabled accounts. If the account is being retired, delete it; if it is a break-glass identity, keep it enabled and governed by PIM instead.' `
                -AffectedObjects @($uid) `
                -References @('MITRE ATT&CK T1078.004', 'CISA SCuBA MS.AAD.7.1', 'NIST 800-53 AC-2(3)')))
            continue
        }

        $last = _FiToDate (_FiGet $u 'lastSignInDateTime')
        $days = if ($last) { [int]($now - $last).TotalDays } else { 9999 }
        if ($days -ge $InactiveDays) {
            $findings.Add((New-CapFinding -CheckId 'inactive-privileged-account' `
                -Title 'Privileged account is inactive' `
                -Impact 5 -Likelihood 3 `
                -Summary 'A privileged account has not signed in within the inactivity threshold, expanding the attack surface with a dormant high-value credential.' `
                -Logic "Flagged when an account with a privileged directory role has an interactive lastSignInDateTime older than the threshold ($InactiveDays day(s)); accounts with no recorded sign-in are treated as inactive." `
                -Description "$uname holds $($privUsers[$uid]) but has not signed in for $days day(s) (threshold $InactiveDays)." `
                -Threat 'Dormant privileged accounts expand the attack surface: their credentials may be stale, unmonitored, and unlikely to be noticed if abused.' `
                -Remediation 'Confirm the account is still required; if not, remove the privileged role or disable the account. Enforce PIM/just-in-time elevation.' `
                -AffectedObjects @($uid) `
                -References @('MITRE ATT&CK T1078.004', 'CISA SCuBA MS.AAD.7.1', 'NIST 800-53 AC-2(3)')))
        }
    }

    @($findings)
}

function Get-CapPolicyStateFindings {
<#
.SYNOPSIS
    Policy-state findings carried into the risk-scored schema: enabled grant
    policy with no controls, no strong auth, and critical (block / MFA) policy
    left disabled or report-only.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$NormalizedPolicies)

    $findings = [System.Collections.Generic.List[object]]::new()
    foreach ($p in @($NormalizedPolicies)) {
        $isCritical = ($p.grant.block -or $p.grant.requireMfa -or $p.grant.requireCompliant -or $p.grant.requireHybrid)
        if ($p.enforced) {
            if (-not $p.grant.hasControls -and -not $p.hasSession) {
                $findings.Add((New-CapFinding -CheckId 'enabled-no-controls' `
                    -Title 'Enabled policy grants access with no controls' `
                    -Impact 3 -Likelihood 3 `
                    -Summary 'An enabled policy applies neither a grant nor a session control, so it enforces nothing.' `
                    -Logic 'Flagged when a policy is in the enabled state but grant.hasControls is false and it has no session controls.' `
                    -Description "'$($p.displayName)' is enabled but applies neither grant nor session controls." `
                    -Threat 'A policy with no controls provides a false sense of protection while enforcing nothing.' `
                    -Remediation 'Add a grant control (block, MFA, compliant device) or retire the policy.' `
                    -AffectedObjects @($p.id)))
            }
            elseif (-not $p.grant.block -and -not $p.grant.requireMfa -and $p.grant.hasControls -and
                    -not ($p.grant.requireCompliant -or $p.grant.requireHybrid)) {
                $findings.Add((New-CapFinding -CheckId 'no-strong-auth' `
                    -Title 'Grant policy requires neither strong auth nor device compliance' `
                    -Impact 2 -Likelihood 3 `
                    -Summary 'An enabled grant policy requires neither MFA/auth-strength nor a compliant/hybrid device, so its control is weak.' `
                    -Logic 'Flagged when an enabled policy has grant controls but none of them is block, requireMfa, requireCompliant or requireHybrid.' `
                    -Description "'$($p.displayName)' grants access without MFA/auth-strength or a compliant/hybrid device requirement." `
                    -Threat 'Weak grant controls may not meaningfully raise the bar for an attacker.' `
                    -Remediation 'Require phishing-resistant MFA or device compliance where appropriate.' `
                    -AffectedObjects @($p.id) `
                    -References @('CISA SCuBA MS.AAD.3.1')))
            }
        }
        elseif ($isCritical) {
            $mode = if ($p.reportOnly) { 'report-only (not enforced)' } else { 'disabled' }
            $findings.Add((New-CapFinding -CheckId 'critical-policy-inactive' `
                -Title 'Critical policy is not enforced' `
                -Impact 4 -Likelihood 3 `
                -Summary 'A policy that would block access or require MFA is currently disabled or report-only, so its protection is not applied.' `
                -Logic 'Flagged when a policy with a block / require-MFA / require-compliant / require-hybrid control is not in the enabled state.' `
                -Description "'$($p.displayName)' would block or require MFA but is currently $mode." `
                -Threat 'A protective control that is disabled or report-only enforces nothing, leaving the intended risk unmitigated.' `
                -Remediation 'Move the policy to the enabled state after validating its impact in report-only.' `
                -AffectedObjects @($p.id) `
                -References @('CISA SCuBA MS.AAD.3.2')))
        }
    }

    # Tenant-level hardening: is there an enforced policy that blocks the device
    # code / authentication-transfer flow? Its absence is a common gap that
    # enables device-code phishing, so surface it once for the whole tenant.
    $blocksDeviceCode = @(@($NormalizedPolicies) | Where-Object {
        $_.enforced -and $_.grant.block -and
        @(@($_.conditions.authFlows) | Where-Object { "$_" -in @('deviceCodeFlow', 'authenticationTransfer') }).Count -ge 1
    })
    if ($blocksDeviceCode.Count -eq 0) {
        $findings.Add((New-CapFinding -CheckId 'no-device-code-flow-block' `
            -Title 'Device code flow authentication is not blocked' `
            -Impact 3 -Likelihood 3 `
            -Summary 'No enabled policy blocks the device code / authentication-transfer flow, a common token-phishing vector.' `
            -Logic 'Flagged once tenant-wide when no enabled block policy targets authentication flows deviceCodeFlow or authenticationTransfer.' `
            -Description 'No enabled Conditional Access policy blocks the device code / authentication-transfer flow for users who do not need it.' `
            -Threat 'Device code flow is a common phishing vector: an attacker relays a legitimate code to a victim to capture tokens without the victim ever visiting a malicious site.' `
            -Remediation 'Create a policy that blocks the device code flow (Conditions > Authentication flows) for all users except those with a genuine headless/kiosk need.' `
            -AffectedObjects @('Tenant-wide') `
            -References @('MITRE ATT&CK T1528', 'MITRE ATT&CK T1566')))
    }

    @($findings)
}

function ConvertFrom-CapAuditIssue {
<#
.SYNOPSIS
    Promote a Phase 5 audit issue into the risk-scored finding schema using the
    audit finding metadata catalog.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Issue)

    $meta = if ($script:CapAuditFindingMeta.ContainsKey($Issue.checkId)) { $script:CapAuditFindingMeta[$Issue.checkId] } else { @{ impact = 3; likelihood = 3; threat = ''; remediation = ''; references = @(); logic = '' } }
    $logic = if ($meta.ContainsKey('logic')) { $meta.logic } else { '' }
    $affected = @()
    if ($Issue.policyId) { $affected += "policy:$($Issue.policyId)" }
    if ($Issue.evidence) {
        foreach ($k in 'principalId', 'groupId') {
            $v = _FiGet $Issue.evidence $k
            if ($v) { $affected += "$($k):$v" }
        }
    }
    New-CapFinding -CheckId $Issue.checkId -Title $Issue.title `
        -Impact $meta.impact -Likelihood $meta.likelihood `
        -Description $Issue.detail -Logic $logic -Threat $meta.threat -Remediation $meta.remediation `
        -AffectedObjects @($affected) -References @($meta.references)
}

function Invoke-CapFindings {
<#
.SYNOPSIS
    Produce the full risk-scored finding set: directory findings + policy-state
    findings + promoted audit issues, sorted by risk score descending.

.OUTPUTS
    Ordered hashtable: findings[] (sorted), summary{ total, bySeverity, topRisk }.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$NormalizedPolicies,
        $Enrichment,
        $AuditResult,
        [int]$InactiveDays = 30
    )

    $all = [System.Collections.Generic.List[object]]::new()
    foreach ($f in @(Get-CapDirectoryFindings -NormalizedPolicies $NormalizedPolicies -Enrichment $Enrichment -InactiveDays $InactiveDays)) { $all.Add($f) }
    foreach ($f in @(Get-CapPolicyStateFindings -NormalizedPolicies $NormalizedPolicies)) { $all.Add($f) }

    if (-not $AuditResult) {
        $AuditResult = Invoke-CapAudit -NormalizedPolicies $NormalizedPolicies -Enrichment $Enrichment
    }
    foreach ($issue in @($AuditResult.issues)) { $all.Add((ConvertFrom-CapAuditIssue -Issue $issue)) }

    $sorted = @($all | Sort-Object -Property @{ Expression = { $_.riskScore } } -Descending)

    $bySeverity = @{}
    foreach ($sev in 'critical', 'high', 'medium', 'low', 'info') {
        $bySeverity[$sev] = @($sorted | Where-Object { $_.severity -eq $sev }).Count
    }

    [ordered]@{
        findings = $sorted
        summary  = [ordered]@{
            total      = @($sorted).Count
            bySeverity = $bySeverity
            topRisk    = if (@($sorted).Count) { $sorted[0].riskScore } else { 0 }
        }
    }
}

Export-ModuleMember -Function Invoke-CapFindings, New-CapFinding, Get-CapSeverityFromScore, Get-CapDirectoryFindings, Get-CapPolicyStateFindings, ConvertFrom-CapAuditIssue
