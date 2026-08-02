<#
.SYNOPSIS
    CAPVisualizer per-user scope resolution (Phase 2). Answers "which Conditional
    Access policies could ever apply to this principal, and why" using the
    normalized policy set plus directory enrichment - fully offline.

.DESCRIPTION
    A CA policy's user targeting is a layered include/exclude structure over
    users, groups (transitive, including nested), directory roles, and
    guest/member type, where exclusions always win. This module expands a
    principal into that context and evaluates each policy into one of four
    buckets: InScopeDirect, InScopeVia (naming the group/role), Excluded (naming
    the excluder), or NotInScope.

    Authored independently from public Microsoft documentation of the CA user
    condition; no third-party tool code or logic is reused.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function _SGet {
    param($o, [string]$k)
    if ($null -eq $o) { return $null }
    if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($k)) { return $o[$k] } else { return $null } }
    $p = $o.PSObject.Properties[$k]
    if ($p) { return $p.Value } else { return $null }
}

function _SArr { param($v) if ($null -eq $v) { return @() }; if ($v -is [string]) { return @($v) }; if ($v -is [System.Collections.IEnumerable]) { return @($v | ForEach-Object { "$_" }) }; @("$v") }

function Resolve-CapPrincipalContext {
<#
.SYNOPSIS
    Build a principal context (user id + transitive group ids + role template ids
    + guest/member type + display name) from directory enrichment.

.PARAMETER PrincipalId
    Object id of the user (or group/service principal) to resolve.

.PARAMETER Enrichment
    The export.enrichment block (may be $null; context is then minimal).

.OUTPUTS
    Ordered hashtable: id, displayName, kind, isGuest, groupIds[], roleTemplateIds[],
    plus warnings[] describing any missing enrichment.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PrincipalId,
        $Enrichment
    )

    $warnings = [System.Collections.Generic.List[string]]::new()
    $groupIds = [System.Collections.Generic.HashSet[string]]::new()
    $roleIds  = [System.Collections.Generic.HashSet[string]]::new()
    $displayName = $PrincipalId
    $isGuest = $false
    $homeTenantId = $null
    $kind = 'user'

    $groupsDs = _SGet $Enrichment 'groups'
    $rolesDs  = _SGet $Enrichment 'roleAssignments'
    $usersDs  = _SGet $Enrichment 'users'

    if (-not ($groupsDs -and (_SGet $groupsDs 'available'))) {
        $warnings.Add('group membership enrichment unavailable - InScopeVia(group) may be incomplete')
    }
    else {
        foreach ($g in @(_SGet $groupsDs 'data')) {
            $members = _SArr (_SGet $g 'memberIds')
            if ((_SGet $g 'membersKnown') -and ($members -contains $PrincipalId)) {
                [void]$groupIds.Add("$(_SGet $g 'id')")
            }
        }
    }

    if (-not ($rolesDs -and (_SGet $rolesDs 'available'))) {
        $warnings.Add('role assignment enrichment unavailable - InScopeVia(role) may be incomplete')
    }
    else {
        foreach ($ra in @(_SGet $rolesDs 'data')) {
            if ("$(_SGet $ra 'principalId')" -eq $PrincipalId) { [void]$roleIds.Add("$(_SGet $ra 'roleTemplateId')") }
        }
    }

    if ($usersDs -and (_SGet $usersDs 'available')) {
        foreach ($u in @(_SGet $usersDs 'data')) {
            if ("$(_SGet $u 'id')" -eq $PrincipalId) {
                $displayName = "$(_SGet $u 'displayName')"
                $ut = "$(_SGet $u 'userType')"
                if ($ut -eq 'Guest') { $isGuest = $true }
                $ht = "$(_SGet $u 'homeTenantId')"
                if ($ht) { $homeTenantId = $ht }
                break
            }
        }
    }

    return [ordered]@{
        id             = $PrincipalId
        displayName    = $displayName
        kind           = $kind
        isGuest        = $isGuest
        homeTenantId   = $homeTenantId
        groupIds       = @($groupIds)
        roleTemplateIds= @($roleIds)
        warnings       = @($warnings)
    }
}

function Test-CapPolicyScope {
<#
.SYNOPSIS
    Evaluate a single normalized policy's user targeting against a principal
    context. Returns a bucket + reason. Exclusion wins over inclusion.

.OUTPUTS
    Ordered hashtable: policyId, policyName, bucket
    (InScopeDirect|InScopeVia|Excluded|NotInScope), via, reason.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$NormalizedPolicy,
        [Parameter(Mandatory)]$Context
    )

    $u = $NormalizedPolicy.conditions.users
    $pid = $Context.id
    $gids = @($Context.groupIds)
    $rids = @($Context.roleTemplateIds)

    # --- Exclusion first (wins). ---
    if ((_SArr $u.excludeUsers) -contains $pid) {
        return _ScopeResult $NormalizedPolicy 'Excluded' $null "Excluded directly as a user"
    }
    $exG = @($gids | Where-Object { (_SArr $u.excludeGroups) -contains $_ })
    if ($exG.Count) {
        return _ScopeResult $NormalizedPolicy 'Excluded' ($exG -join ',') "Excluded via group membership"
    }
    $exR = @($rids | Where-Object { (_SArr $u.excludeRoles) -contains $_ })
    if ($exR.Count) {
        return _ScopeResult $NormalizedPolicy 'Excluded' ($exR -join ',') "Excluded via directory role"
    }
    $exGuest = _SGuestScope $u.excludeGuests $u.excludeGuestTenantMode $u.excludeGuestTenants $Context
    if ($exGuest -eq 'yes') {
        return _ScopeResult $NormalizedPolicy 'Excluded' 'GuestsOrExternalUsers' "Excluded as guest/external user"
    }
    if ($exGuest -eq 'unknown') {
        return _ScopeResult $NormalizedPolicy 'Excluded' 'GuestsOrExternalUsers' "Excluded as guest/external user if their home tenant is one of: $(@($u.excludeGuestTenants) -join ', ')"
    }

    # --- Inclusion. ---
    if ((_SArr $u.includeUsers) -contains $pid) {
        return _ScopeResult $NormalizedPolicy 'InScopeDirect' $null "Included directly as a user"
    }
    if ($u.includeAll) {
        return _ScopeResult $NormalizedPolicy 'InScopeDirect' 'All' "Included via All users"
    }
    $inG = @($gids | Where-Object { (_SArr $u.includeGroups) -contains $_ })
    if ($inG.Count) {
        return _ScopeResult $NormalizedPolicy 'InScopeVia' ($inG -join ',') "In scope via group membership"
    }
    $inR = @($rids | Where-Object { (_SArr $u.includeRoles) -contains $_ })
    if ($inR.Count) {
        return _ScopeResult $NormalizedPolicy 'InScopeVia' ($inR -join ',') "In scope via directory role"
    }
    $inGuest = _SGuestScope $u.includeGuests $u.includeGuestTenantMode $u.includeGuestTenants $Context
    if ($inGuest -eq 'yes') {
        return _ScopeResult $NormalizedPolicy 'InScopeVia' 'GuestsOrExternalUsers' "In scope as guest/external user"
    }
    if ($inGuest -eq 'unknown') {
        return _ScopeResult $NormalizedPolicy 'InScopeVia' 'GuestsOrExternalUsers' "In scope as guest/external user if their home tenant is one of: $(@($u.includeGuestTenants) -join ', ')"
    }

    return _ScopeResult $NormalizedPolicy 'NotInScope' $null "Principal not targeted by this policy"
}

function _SGuestScope {
<#
.SYNOPSIS
    Does this policy's guest/external selector cover this principal?

.DESCRIPTION
    Returns 'no', 'yes', or 'unknown'. A policy restricted to enumerated external
    tenants only covers guests from those tenants, so claiming a plain yes would
    tell someone a partner policy applies to a guest from a different partner.

    When the policy names specific tenants and the principal's home tenant is not
    known offline, the honest answer is 'unknown' rather than a guess in either
    direction.
#>
    param($GuestFlag, $TenantMode, $TenantIds, $Context)

    if (-not $GuestFlag) { return 'no' }
    if (-not $Context.isGuest) { return 'no' }
    if ("$TenantMode" -ne 'enumerated') { return 'yes' }

    $ids = @($TenantIds)
    if (-not $ids.Count) { return 'yes' }

    $home = "$(if ($Context.Contains('homeTenantId')) { $Context['homeTenantId'] })"
    if (-not $home) { return 'unknown' }
    if ($ids -contains $home) { return 'yes' }
    return 'no'
}

function _ScopeResult {
    param($Policy, [string]$Bucket, $Via, [string]$Reason)
    [ordered]@{
        policyId   = $Policy.id
        policyName = $Policy.displayName
        state      = $Policy.state
        bucket     = $Bucket
        via        = $Via
        reason     = $Reason
    }
}

function Resolve-CapScope {
<#
.SYNOPSIS
    Resolve every policy's scope for a principal and summarize the buckets.

.PARAMETER PrincipalId
    Object id of the principal (user).

.PARAMETER NormalizedPolicies
    Array of normalized policies (ConvertTo-CapNormalizedPolicy output).

.PARAMETER Enrichment
    export.enrichment block for membership/role expansion. Optional.

.OUTPUTS
    Ordered hashtable: principal, counts, results[] (one per policy).
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PrincipalId,
        [Parameter(Mandatory)]$NormalizedPolicies,
        $Enrichment
    )

    $ctx = Resolve-CapPrincipalContext -PrincipalId $PrincipalId -Enrichment $Enrichment
    $results = @(@($NormalizedPolicies) | ForEach-Object { Test-CapPolicyScope -NormalizedPolicy $_ -Context $ctx })

    $counts = [ordered]@{
        inScopeDirect = @($results | Where-Object { $_.bucket -eq 'InScopeDirect' }).Count
        inScopeVia    = @($results | Where-Object { $_.bucket -eq 'InScopeVia' }).Count
        excluded      = @($results | Where-Object { $_.bucket -eq 'Excluded' }).Count
        notInScope    = @($results | Where-Object { $_.bucket -eq 'NotInScope' }).Count
    }

    return [ordered]@{
        principal = $ctx
        counts    = $counts
        results   = @($results)
    }
}

Export-ModuleMember -Function Resolve-CapPrincipalContext, Test-CapPolicyScope, Resolve-CapScope
