<#
.SYNOPSIS
    CAPVisualizer contradiction & misconfiguration engine (Phase 5). Static
    logical checks over the normalized Conditional Access policy set that surface
    self-defeating configuration: app-grouping contradictions, include/exclude
    overlaps, legacy-authentication reachability, and an exemption exposure view
    (who is excluded from what, with privileged-role emphasis).

.DESCRIPTION
    These checks answer "does this policy set actually do what it looks like it
    does?". A policy can name an app in both its include and (via a grouping) its
    exclude list, silently leaving that app uncovered - the kind of mistake that
    is invisible in the portal. Results are emitted as structured issues that the
    Phase 6 findings model can absorb.

    Authored independently against the public Entra CA evaluation model and CISA
    highly-privileged role list; no third-party tool code or logic is reused.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function _AuArr { param($v) if ($null -eq $v) { return @() }; if ($v -is [string]) { return @($v) }; if ($v -is [System.Collections.IEnumerable]) { return @($v | ForEach-Object { $_ }) }; @($v) }

function _AuGet {
    param($Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [System.Collections.IDictionary]) { if ($Obj.Contains($Name)) { return $Obj[$Name] } return $null }
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    $null
}

function Get-CapPrivilegedRoleSet {
<#
.SYNOPSIS
    Load the highly-privileged + additional-sensitive role template ids from the
    packaged reference pack. Returns a hashtable roleTemplateId -> name.
#>
    [CmdletBinding()]
    param([string]$ReferencePath)
    if (-not $ReferencePath) {
        $ReferencePath = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'assets/reference/privileged-roles.json'
    }
    $map = @{}
    if (-not (Test-Path $ReferencePath)) { return $map }
    $ref = Get-Content -Raw -Path $ReferencePath | ConvertFrom-Json
    foreach ($key in 'highlyPrivilegedRoles', 'additionalSensitiveRoles') {
        foreach ($r in @(_AuArr (_AuGet $ref $key))) {
            $id = "$(_AuGet $r 'roleTemplateId')"
            if ($id) { $map[$id] = "$(_AuGet $r 'name')" }
        }
    }
    $map
}

function _AuIssue {
    param([string]$CheckId, [string]$Severity, [string]$Category, [string]$Title,
          [string]$Detail, $PolicyId, $PolicyName, $Evidence)
    [ordered]@{
        checkId    = $CheckId
        severity   = $Severity        # high | medium | low | info
        category   = $Category
        title      = $Title
        detail     = $Detail
        policyId   = $PolicyId
        policyName = $PolicyName
        evidence   = $Evidence
    }
}

function Test-CapPolicyContradictions {
<#
.SYNOPSIS
    Per-policy static contradiction checks over one normalized policy.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$NormalizedPolicy)

    $p = $NormalizedPolicy
    $issues = [System.Collections.Generic.List[object]]::new()

    # 1. Included application nullified by an exclusion (grouping-expanded).
    $incApps = @(_AuArr $p.conditions.applications.includeAppIds)
    $excApps = @(_AuArr $p.conditions.applications.excludeAppIds)
    $appOverlap = @($incApps | Where-Object { $excApps -contains $_ })
    if ($appOverlap.Count) {
        $issues.Add((_AuIssue 'app-include-exclude-overlap' 'high' 'contradiction' `
            'Included application is cancelled by an exclusion' `
            "Application(s) appear in both the include and (grouping-expanded) exclude set, so the policy silently does not cover them: $($appOverlap -join ', ')." `
            $p.id $p.displayName ([ordered]@{ apps = $appOverlap; excludeGroupings = @(_AuArr $p.conditions.applications.excludeGroupings) })))
    }

    # 2. Platform included and excluded simultaneously.
    if ($null -ne $p.conditions.platforms) {
        $incP = @(_AuArr $p.conditions.platforms.include)
        $excP = @(_AuArr $p.conditions.platforms.exclude)
        $pOverlap = @($incP | Where-Object { $excP -contains $_ })
        if ($pOverlap.Count) {
            $issues.Add((_AuIssue 'platform-include-exclude-overlap' 'medium' 'contradiction' `
                'Platform is both included and excluded' `
                "Platform(s) listed in include and exclude - the exclusion wins and the platform is not covered: $($pOverlap -join ', ')." `
                $p.id $p.displayName ([ordered]@{ platforms = $pOverlap })))
        }
    }

    # 3. Same principal object in include and exclude.
    foreach ($pair in @(
            @{ k = 'Users';  inc = 'includeUsers';  exc = 'excludeUsers' },
            @{ k = 'Groups'; inc = 'includeGroups'; exc = 'excludeGroups' },
            @{ k = 'Roles';  inc = 'includeRoles';  exc = 'excludeRoles' })) {
        $inc = @(_AuArr (_AuGet $p.conditions.users $pair.inc))
        $exc = @(_AuArr (_AuGet $p.conditions.users $pair.exc))
        $ov = @($inc | Where-Object { $exc -contains $_ })
        if ($ov.Count) {
            $issues.Add((_AuIssue "principal-include-exclude-overlap" 'medium' 'contradiction' `
                "$($pair.k) both included and excluded" `
                "$($pair.k) referenced in both include and exclude; the inclusion is a no-op for them: $($ov -join ', ')." `
                $p.id $p.displayName ([ordered]@{ scope = $pair.k; ids = $ov })))
        }
    }

    @($issues)
}

function Test-CapLegacyAuthCoverage {
<#
.SYNOPSIS
    Tenant-level check: is legacy authentication blocked anywhere? Legacy auth
    (exchangeActiveSync / other) is a top bypass vector; at least one enabled
    policy should block it broadly.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$NormalizedPolicies)

    $blockers = @($NormalizedPolicies | Where-Object {
        $_.enforced -and $_.grant.block -and
        $_.conditions.users.includeAll -and
        ($_.conditions.applications.includeAll) -and
        (@(_AuArr $_.conditions.clientApps.effective) | Where-Object { @('exchangeActiveSync', 'other') -contains $_ }).Count -ge 1 -and
        (-not $_.conditions.clientApps.isAll)
    })

    if ($blockers.Count -ge 1) { return @() }

    @(_AuIssue 'legacy-auth-not-blocked' 'high' 'coverage' `
        'Legacy authentication is not blocked' `
        'No enabled policy broadly blocks legacy authentication clients (exchangeActiveSync / other) for all users and apps. Legacy protocols bypass modern controls such as MFA.' `
        $null $null ([ordered]@{ recommendation = 'Add an enabled Block policy scoped to All users, All apps, client apps = exchangeActiveSync + other.' }))
}

function Get-CapExemptionExposure {
<#
.SYNOPSIS
    Aggregate every user/group/role excluded across all ENABLED policies into a
    "who is exempt from what" view, and flag privileged principals excluded from
    broad protective policies.

.PARAMETER Enrichment
    export.enrichment (for display names + role assignments). Optional.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$NormalizedPolicies,
        $Enrichment
    )

    $privRoles = Get-CapPrivilegedRoleSet
    $nameMap = @{}
    $memberOfPrivRole = @{}   # principalId -> [roleName]

    if ($Enrichment) {
        foreach ($u in @(_AuArr (_AuGet (_AuGet $Enrichment 'users') 'data'))) {
            $nameMap["$(_AuGet $u 'id')"] = "$(_AuGet $u 'displayName')"
        }
        foreach ($g in @(_AuArr (_AuGet (_AuGet $Enrichment 'groups') 'data'))) {
            $nameMap["$(_AuGet $g 'id')"] = "$(_AuGet $g 'displayName')"
        }
        # Role display names: from the privileged reference pack (keyed by role
        # template id) plus any names carried on the role assignments themselves.
        # Excluded roles in a CA policy are referenced by role template id.
        foreach ($rt in $privRoles.Keys) { if (-not $nameMap.ContainsKey($rt)) { $nameMap[$rt] = $privRoles[$rt] } }
        foreach ($ra in @(_AuArr (_AuGet (_AuGet $Enrichment 'roleAssignments') 'data'))) {
            $rtid = "$(_AuGet $ra 'roleTemplateId')"; $rtn = "$(_AuGet $ra 'roleName')"
            if ($rtid -and -not [string]::IsNullOrWhiteSpace($rtn)) { $nameMap[$rtid] = $rtn }
        }
        foreach ($ra in @(_AuArr (_AuGet (_AuGet $Enrichment 'roleAssignments') 'data'))) {
            $rid = "$(_AuGet $ra 'roleTemplateId')"
            if ($privRoles.ContainsKey($rid)) {
                $pid = "$(_AuGet $ra 'principalId')"
                if (-not $memberOfPrivRole.ContainsKey($pid)) { $memberOfPrivRole[$pid] = [System.Collections.Generic.List[string]]::new() }
                # Prefer the assignment's roleName; fall back to the reference-pack
                # name so real-tenant data with a blank roleName still shows a name.
                $rn = "$(_AuGet $ra 'roleName')"
                if ([string]::IsNullOrWhiteSpace($rn)) { $rn = $privRoles[$rid] }
                if (-not [string]::IsNullOrWhiteSpace($rn) -and -not $memberOfPrivRole[$pid].Contains($rn)) { $memberOfPrivRole[$pid].Add($rn) }
            }
        }
    }

    # exclusions: principalId -> { type, policies[] }
    $exposure = @{}
    $issues = [System.Collections.Generic.List[object]]::new()

    foreach ($p in @($NormalizedPolicies)) {
        if (-not $p.enforced) { continue }
        $broad = ($p.conditions.users.includeAll -and $p.conditions.applications.includeAll)
        $excluded = @(
            @(_AuArr $p.conditions.users.excludeUsers)  | ForEach-Object { @{ id = $_; type = 'user' } }
            @(_AuArr $p.conditions.users.excludeGroups) | ForEach-Object { @{ id = $_; type = 'group' } }
            @(_AuArr $p.conditions.users.excludeRoles)  | ForEach-Object { @{ id = $_; type = 'role' } }
        )
        foreach ($ex in $excluded) {
            $id = "$($ex.id)"
            if (-not $exposure.ContainsKey($id)) {
                $exposure[$id] = [ordered]@{ id = $id; type = $ex.type; displayName = $(if ($nameMap.ContainsKey($id)) { $nameMap[$id] } else { $null }); policies = [System.Collections.Generic.List[string]]::new() }
            }
            $exposure[$id].policies.Add($p.displayName)
        }

        # Privileged principals excluded from a broad protective policy.
        if ($broad -and $p.grant.hasControls) {
            foreach ($uid in @(_AuArr $p.conditions.users.excludeUsers)) {
                if ($memberOfPrivRole.ContainsKey($uid)) {
                    $issues.Add((_AuIssue 'privileged-user-exempt' 'high' 'exemption' `
                        'Privileged user excluded from a broad protective policy' `
                        "$(if ($nameMap.ContainsKey($uid)) { $nameMap[$uid] } else { $uid }) holds $(@($memberOfPrivRole[$uid]) -join ', ') and is excluded from '$($p.displayName)' (All users / All apps)." `
                        $p.id $p.displayName ([ordered]@{ principalId = $uid; roles = @($memberOfPrivRole[$uid]) })))
                }
            }
            # Privileged members reachable through an excluded group.
            foreach ($gid in @(_AuArr $p.conditions.users.excludeGroups)) {
                $grp = @(_AuArr (_AuGet (_AuGet $Enrichment 'groups') 'data')) | Where-Object { "$(_AuGet $_ 'id')" -eq $gid } | Select-Object -First 1
                if ($grp) {
                    $privMembers = @(_AuArr (_AuGet $grp 'memberIds')) | Where-Object { $memberOfPrivRole.ContainsKey($_) }
                    if (@($privMembers).Count) {
                        $issues.Add((_AuIssue 'privileged-via-excluded-group' 'high' 'exemption' `
                            'Privileged users excluded via a group exclusion' `
                            "Group '$(if ($nameMap.ContainsKey($gid)) { $nameMap[$gid] } else { $gid })' is excluded from broad policy '$($p.displayName)' and contains privileged member(s): $((@($privMembers) | ForEach-Object { if ($nameMap.ContainsKey($_)) { $nameMap[$_] } else { $_ } }) -join ', ')." `
                            $p.id $p.displayName ([ordered]@{ groupId = $gid; privilegedMembers = @($privMembers) })))
                    }
                }
            }
        }
    }

    $exposureList = @($exposure.Values | ForEach-Object {
        [ordered]@{ id = $_.id; type = $_.type; displayName = $_.displayName; excludedFromPolicies = @($_.policies); policyCount = @($_.policies).Count }
    } | Sort-Object -Property @{ Expression = 'policyCount'; Descending = $true })

    [ordered]@{ exposure = $exposureList; issues = @($issues) }
}

function Invoke-CapAudit {
<#
.SYNOPSIS
    Run the full contradiction / misconfiguration audit over a normalized policy
    set and return the combined issue list plus the exemption exposure view.

.OUTPUTS
    Ordered hashtable: issues[], exemptionExposure[], summary{ bySeverity }.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$NormalizedPolicies,
        $Enrichment
    )

    $issues = [System.Collections.Generic.List[object]]::new()
    foreach ($p in @($NormalizedPolicies)) {
        foreach ($i in @(Test-CapPolicyContradictions -NormalizedPolicy $p)) { $issues.Add($i) }
    }
    foreach ($i in @(Test-CapLegacyAuthCoverage -NormalizedPolicies $NormalizedPolicies)) { $issues.Add($i) }

    $exempt = Get-CapExemptionExposure -NormalizedPolicies $NormalizedPolicies -Enrichment $Enrichment
    foreach ($i in @($exempt.issues)) { $issues.Add($i) }

    $bySeverity = @{}
    foreach ($sev in 'high', 'medium', 'low', 'info') {
        $bySeverity[$sev] = @($issues | Where-Object { $_.severity -eq $sev }).Count
    }

    [ordered]@{
        issues            = @($issues)
        exemptionExposure = @($exempt.exposure)
        summary           = [ordered]@{
            total      = @($issues).Count
            bySeverity = $bySeverity
        }
    }
}

Export-ModuleMember -Function Invoke-CapAudit, Test-CapPolicyContradictions, Test-CapLegacyAuthCoverage, Get-CapExemptionExposure, Get-CapPrivilegedRoleSet
