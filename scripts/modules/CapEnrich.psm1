<#
.SYNOPSIS
    CAPVisualizer directory enrichment (Phase 0). Collects the read-only Entra
    directory context that downstream analysis engines (scope resolution, risk
    findings, contradiction and compliance checks) need beyond the CA policies
    themselves.

.DESCRIPTION
    Everything here is READ-ONLY (GET only) and best-effort: any dataset that the
    signed-in principal lacks permission to read is recorded as unavailable rather
    than aborting the run. The collected data is embedded in the export so that a
    later -FromJson render stays fully offline.

    Datasets:
      * groups        - id, displayName, protection state (role-assignable,
                        dynamic, ownerless), owner ids.
      * roleAssignments - active directory-role member assignments (principal ->
                        role template) plus PIM-eligible where readable.
      * users         - id, UPN, displayName, accountEnabled, last sign-in.
      * mfaCapability - per-user registration/capability (beta reports API).
      * appGroupings  - the static grouping reference (from assets/reference).

    Authored independently from public Microsoft Graph documentation; no
    third-party tool code or logic is reused.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function _EnrichTry {
    # Run a read-only collection scriptblock, capturing availability + error.
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Script
    )
    try {
        $data = & $Script
        return [ordered]@{ available = $true; error = $null; data = $data }
    }
    catch {
        Write-CapLog "Enrichment '$Name' unavailable (continuing): $($_.Exception.Message)" 'WARN'
        return [ordered]@{ available = $false; error = "$($_.Exception.Message)"; data = $null }
    }
}

function Get-CapGroupEnrichment {
<#
.SYNOPSIS
    Groups with protection-relevant properties. Requires Group.Read.All (or
    Directory.Read.All). Owners are fetched only for the supplied group ids to
    bound the cost.

.PARAMETER GroupIds
    Optional. Restrict owner lookups to these group ids (e.g. groups referenced
    by CA policies). When omitted, owners are not expanded.
#>
    [CmdletBinding()]
    param([string[]]$GroupIds = @())

    $select = 'id,displayName,isAssignableToRole,groupTypes,membershipRule,securityEnabled,mailEnabled'
    $groups = @(Invoke-CapGraphGet -Uri "groups?`$select=$select&`$top=999")

    $wanted = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($g in @($GroupIds)) { if ($g) { [void]$wanted.Add("$g") } }

    $result = foreach ($g in $groups) {
        $id = $g.PSObject.Properties['id'].Value
        $groupTypes = @($g.PSObject.Properties['groupTypes'].Value)
        $isDynamic = [bool]($groupTypes -contains 'DynamicMembership')
        $ownerIds = @()
        $ownersKnown = $false
        if ($wanted.Contains("$id")) {
            try {
                $owners = @(Invoke-CapGraphGet -Uri "groups/$id/owners?`$select=id")
                $ownerIds = @($owners | ForEach-Object { $_.PSObject.Properties['id'].Value } | Where-Object { $_ })
                $ownersKnown = $true
            }
            catch { }
        }
        [ordered]@{
            id                = "$id"
            displayName       = "$($g.PSObject.Properties['displayName'].Value)"
            isAssignableToRole= [bool]$g.PSObject.Properties['isAssignableToRole'].Value
            isDynamic         = $isDynamic
            securityEnabled   = [bool]$g.PSObject.Properties['securityEnabled'].Value
            ownersKnown       = $ownersKnown
            ownerIds          = @($ownerIds)
            ownerless         = [bool]($ownersKnown -and $ownerIds.Count -eq 0)
        }
    }
    return @($result)
}

function Get-CapRoleAssignmentEnrichment {
<#
.SYNOPSIS
    Active directory-role assignments (principal -> role) plus PIM-eligible
    assignments where readable. Requires RoleManagement.Read.Directory (or
    Directory.Read.All). Each returns { principalId, roleTemplateId, roleName,
    assignmentType }.
#>
    [CmdletBinding()]
    param()

    $assignments = [System.Collections.Generic.List[object]]::new()

    # Active role assignments via directoryRoles + members.
    $roles = @(Invoke-CapGraphGet -Uri 'directoryRoles?$select=id,displayName,roleTemplateId')
    foreach ($r in $roles) {
        $roleId = $r.PSObject.Properties['id'].Value
        $tpl    = $r.PSObject.Properties['roleTemplateId'].Value
        $name   = $r.PSObject.Properties['displayName'].Value
        try {
            $members = @(Invoke-CapGraphGet -Uri "directoryRoles/$roleId/members?`$select=id")
            foreach ($m in $members) {
                $assignments.Add([ordered]@{
                    principalId    = "$($m.PSObject.Properties['id'].Value)"
                    roleTemplateId = "$tpl"
                    roleName       = "$name"
                    assignmentType = 'active'
                })
            }
        }
        catch { }
    }

    # PIM-eligible assignments (best effort; requires RoleEligibilitySchedule read).
    try {
        $eligible = @(Invoke-CapGraphGet -Uri 'roleManagement/directory/roleEligibilityScheduleInstances?$select=principalId,roleDefinitionId')
        foreach ($e in $eligible) {
            $assignments.Add([ordered]@{
                principalId    = "$($e.PSObject.Properties['principalId'].Value)"
                roleTemplateId = "$($e.PSObject.Properties['roleDefinitionId'].Value)"
                roleName       = $null
                assignmentType = 'eligible'
            })
        }
    }
    catch { }

    return @($assignments)
}

function Get-CapUserEnrichment {
<#
.SYNOPSIS
    Directory users with account state and last sign-in. Requires User.Read.All
    (or Directory.Read.All); signInActivity requires AuditLog.Read.All.

.PARAMETER IncludeSignInActivity
    Attempt to select signInActivity (may require an extra scope / P1 licence).
#>
    [CmdletBinding()]
    param([switch]$IncludeSignInActivity)

    $select = 'id,userPrincipalName,displayName,accountEnabled,userType,onPremisesSyncEnabled'
    if ($IncludeSignInActivity) { $select += ',signInActivity' }
    $users = @(Invoke-CapGraphGet -Uri "users?`$select=$select&`$top=999")

    $result = foreach ($u in $users) {
        $sia = $u.PSObject.Properties['signInActivity']
        $lastSignIn = $null
        if ($sia -and $sia.Value) {
            $p = $sia.Value.PSObject.Properties['lastSignInDateTime']
            if ($p) { $lastSignIn = $p.Value }
        }
        [ordered]@{
            id                  = "$($u.PSObject.Properties['id'].Value)"
            userPrincipalName   = "$($u.PSObject.Properties['userPrincipalName'].Value)"
            displayName         = "$($u.PSObject.Properties['displayName'].Value)"
            accountEnabled      = [bool]$u.PSObject.Properties['accountEnabled'].Value
            userType            = "$($u.PSObject.Properties['userType'].Value)"
            onPremisesSyncEnabled = [bool]$u.PSObject.Properties['onPremisesSyncEnabled'].Value
            lastSignInDateTime  = $lastSignIn
        }
    }
    return @($result)
}

function Get-CapMfaCapabilityEnrichment {
<#
.SYNOPSIS
    Per-user MFA registration/capability from the beta reports API
    (authenticationMethods userRegistrationDetails). Requires
    AuditLog.Read.All + UserAuthenticationMethod.Read.All (or Reports.Read.All).
    Returns { userId, isMfaCapable, isMfaRegistered }.
#>
    [CmdletBinding()]
    param()

    $details = @(Invoke-CapGraphGet -Beta -Uri 'reports/authenticationMethods/userRegistrationDetails?$select=id,userPrincipalName,isMfaCapable,isMfaRegistered')
    $result = foreach ($d in $details) {
        [ordered]@{
            userId          = "$($d.PSObject.Properties['id'].Value)"
            userPrincipalName = "$($d.PSObject.Properties['userPrincipalName'].Value)"
            isMfaCapable    = [bool]$d.PSObject.Properties['isMfaCapable'].Value
            isMfaRegistered = [bool]$d.PSObject.Properties['isMfaRegistered'].Value
        }
    }
    return @($result)
}

function Get-CapEnrichment {
<#
.SYNOPSIS
    Orchestrate all read-only directory enrichment collections, each wrapped so a
    permission gap degrades gracefully. Returns a single ordered hashtable keyed
    by dataset, each { available, error, data }.

.PARAMETER GroupIds
    Group ids referenced by policies (for bounded owner expansion).
#>
    [CmdletBinding()]
    param([string[]]$GroupIds = @())

    Write-CapLog "Collecting directory enrichment (read-only, best-effort)..." 'INFO'

    $enrichment = [ordered]@{
        collectedUtc   = (Get-Date).ToUniversalTime().ToString('o')
        groups         = _EnrichTry -Name 'groups'          -Script { Get-CapGroupEnrichment -GroupIds $GroupIds }
        roleAssignments= _EnrichTry -Name 'roleAssignments' -Script { Get-CapRoleAssignmentEnrichment }
        users          = _EnrichTry -Name 'users'           -Script { Get-CapUserEnrichment -IncludeSignInActivity }
        mfaCapability  = _EnrichTry -Name 'mfaCapability'    -Script { Get-CapMfaCapabilityEnrichment }
    }

    # If users failed with signInActivity, retry without it (common on tenants
    # lacking AuditLog.Read.All) so at least account state is captured.
    if (-not $enrichment.users.available) {
        $enrichment.users = _EnrichTry -Name 'users (no signInActivity)' -Script { Get-CapUserEnrichment }
    }

    $avail = @($enrichment.Keys | Where-Object { $_ -ne 'collectedUtc' -and $enrichment[$_].available })
    Write-CapLog "Enrichment collected. Available datasets: $($avail -join ', ')" 'OK'
    return $enrichment
}

Export-ModuleMember -Function Get-CapEnrichment, Get-CapGroupEnrichment, `
    Get-CapRoleAssignmentEnrichment, Get-CapUserEnrichment, Get-CapMfaCapabilityEnrichment
