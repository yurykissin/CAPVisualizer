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
        $memberIds = @()
        $membersKnown = $false
        if ($wanted.Contains("$id")) {
            try {
                $owners = @(Invoke-CapGraphGet -Uri "groups/$id/owners?`$select=id")
                $ownerIds = @($owners | ForEach-Object { $_.PSObject.Properties['id'].Value } | Where-Object { $_ })
                $ownersKnown = $true
            }
            catch { }
            try {
                # Transitive members so nested-group membership is captured. Only
                # collected for policy-referenced groups to bound the cost.
                $members = @(Invoke-CapGraphGet -Uri "groups/$id/transitiveMembers?`$select=id")
                $memberIds = @($members | ForEach-Object { $_.PSObject.Properties['id'].Value } | Where-Object { $_ })
                $membersKnown = $true
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
            membersKnown      = $membersKnown
            memberIds         = @($memberIds)
        }
    }
    return @($result)
}

function Get-CapRoleAssignmentEnrichment {
<#
.SYNOPSIS
    Active directory-role assignments (principal -> role) plus PIM-eligible
    assignments where readable. Requires RoleManagement.Read.Directory (or
    Directory.Read.All). Each assignment keeps both the tenant-specific
    roleDefinitionId and the cross-tenant roleTemplateId.
#>
    [CmdletBinding()]
    param([switch]$IncludeStatus)

    $assignments = [System.Collections.Generic.List[object]]::new()
    $warnings = [System.Collections.Generic.List[string]]::new()
    $activeComplete = $true
    $eligibleComplete = $true
    $definitionsComplete = $true
    $definitionsById = @{}
    $definitionsByTemplate = @{}

    try {
        $definitions = @(Invoke-CapGraphGet -Uri 'roleManagement/directory/roleDefinitions?$select=id,templateId,displayName,isBuiltIn')
        foreach ($d in $definitions) {
            $id = "$($d.PSObject.Properties['id'].Value)"
            $templateId = "$($d.PSObject.Properties['templateId'].Value)"
            $record = [ordered]@{
                id          = $id
                templateId  = $templateId
                displayName = "$($d.PSObject.Properties['displayName'].Value)"
                isBuiltIn   = [bool]$d.PSObject.Properties['isBuiltIn'].Value
            }
            if ($id) { $definitionsById[$id] = $record }
            if ($templateId) { $definitionsByTemplate[$templateId] = $record }
        }
    }
    catch {
        $definitionsComplete = $false
        $warnings.Add("Role definitions unavailable: $($_.Exception.Message)")
    }

    # Active role assignments via directoryRoles + members.
    $roles = @(Invoke-CapGraphGet -Uri 'directoryRoles?$select=id,displayName,roleTemplateId')
    foreach ($r in $roles) {
        $roleId = $r.PSObject.Properties['id'].Value
        $tpl    = $r.PSObject.Properties['roleTemplateId'].Value
        $name   = $r.PSObject.Properties['displayName'].Value
        $definitionId = if ($definitionsByTemplate.ContainsKey("$tpl")) {
            "$($definitionsByTemplate["$tpl"]['id'])"
        } else { $null }
        try {
            $members = @(Invoke-CapGraphGet -Uri "directoryRoles/$roleId/members?`$select=id")
            foreach ($m in $members) {
                $assignments.Add([ordered]@{
                    principalId    = "$($m.PSObject.Properties['id'].Value)"
                    roleDefinitionId = $definitionId
                    roleTemplateId = "$tpl"
                    roleName       = "$name"
                    assignmentType = 'active'
                })
            }
        }
        catch {
            $activeComplete = $false
            $warnings.Add("Active members unavailable for role '$name' ($tpl): $($_.Exception.Message)")
        }
    }

    # PIM-eligible assignments (best effort; requires RoleEligibilitySchedule read).
    try {
        $eligible = @(Invoke-CapGraphGet -Uri 'roleManagement/directory/roleEligibilityScheduleInstances?$select=principalId,roleDefinitionId')
        foreach ($e in $eligible) {
            $definitionId = "$($e.PSObject.Properties['roleDefinitionId'].Value)"
            $definition = if ($definitionsById.ContainsKey($definitionId)) { $definitionsById[$definitionId] } else { $null }
            if (-not $definition) {
                $eligibleComplete = $false
                $warnings.Add("PIM assignment references unmapped role definition '$definitionId'.")
            }
            $assignments.Add([ordered]@{
                principalId    = "$($e.PSObject.Properties['principalId'].Value)"
                roleDefinitionId = $definitionId
                roleTemplateId = $(if ($definition) { "$($definition['templateId'])" } else { $null })
                roleName       = $(if ($definition) { "$($definition['displayName'])" } else { $null })
                assignmentType = 'eligible'
            })
        }
    }
    catch {
        $eligibleComplete = $false
        $warnings.Add("PIM-eligible assignments unavailable: $($_.Exception.Message)")
    }

    if (-not $IncludeStatus) { return @($assignments) }
    return [ordered]@{
        data                    = @($assignments)
        completeness            = $(if ($activeComplete -and $eligibleComplete -and $definitionsComplete) { 'complete' } else { 'partial' })
        activeComplete          = $activeComplete
        eligibleComplete        = $eligibleComplete
        roleDefinitionsComplete = $definitionsComplete
        warnings                = @($warnings)
        groupEligibilityExpanded= $false
    }
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
    Per-user authentication-method registration/capability from the beta reports
    API (authenticationMethods userRegistrationDetails). Requires
    AuditLog.Read.All + UserAuthenticationMethod.Read.All (or Reports.Read.All).
    Returns per-user registration state: MFA/passwordless/SSPR capability and
    registration, the methods registered, default method, admin flag and type.
    This is the reporting rollup only - it never reads a user's actual method
    secrets (phone numbers, security-key names).
#>
    [CmdletBinding()]
    param()

    $select = 'id,userPrincipalName,userDisplayName,isMfaCapable,isMfaRegistered,' +
        'isPasswordlessCapable,isSsprCapable,isSsprRegistered,isSsprEnabled,' +
        'methodsRegistered,defaultMfaMethod,systemPreferredAuthenticationMethods,' +
        'isAdmin,userType,lastUpdatedDateTime'
    $details = @(Invoke-CapGraphGet -Beta -Uri "reports/authenticationMethods/userRegistrationDetails?`$select=$select")
    $result = foreach ($d in $details) {
        [ordered]@{
            userId              = "$($d.PSObject.Properties['id'].Value)"
            userPrincipalName   = "$($d.PSObject.Properties['userPrincipalName'].Value)"
            userDisplayName     = "$($d.PSObject.Properties['userDisplayName'].Value)"
            isMfaCapable        = [bool]$d.PSObject.Properties['isMfaCapable'].Value
            isMfaRegistered     = [bool]$d.PSObject.Properties['isMfaRegistered'].Value
            isPasswordlessCapable = [bool]$d.PSObject.Properties['isPasswordlessCapable'].Value
            isSsprCapable       = [bool]$d.PSObject.Properties['isSsprCapable'].Value
            isSsprRegistered    = [bool]$d.PSObject.Properties['isSsprRegistered'].Value
            isSsprEnabled       = [bool]$d.PSObject.Properties['isSsprEnabled'].Value
            methodsRegistered   = @($d.PSObject.Properties['methodsRegistered'].Value)
            defaultMfaMethod    = "$($d.PSObject.Properties['defaultMfaMethod'].Value)"
            systemPreferredAuthenticationMethods = @($d.PSObject.Properties['systemPreferredAuthenticationMethods'].Value)
            isAdmin             = [bool]$d.PSObject.Properties['isAdmin'].Value
            userType            = "$($d.PSObject.Properties['userType'].Value)"
            lastUpdatedDateTime = "$($d.PSObject.Properties['lastUpdatedDateTime'].Value)"
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
        roleAssignments= _EnrichTry -Name 'roleAssignments' -Script { Get-CapRoleAssignmentEnrichment -IncludeStatus }
        users          = _EnrichTry -Name 'users'           -Script { Get-CapUserEnrichment -IncludeSignInActivity }
        mfaCapability  = _EnrichTry -Name 'mfaCapability'    -Script { Get-CapMfaCapabilityEnrichment }
    }

    # If users failed with signInActivity, retry without it (common on tenants
    # lacking AuditLog.Read.All) so at least account state is captured.
    if (-not $enrichment.users.available) {
        $enrichment.users = _EnrichTry -Name 'users (no signInActivity)' -Script { Get-CapUserEnrichment }
    }

    if ($enrichment.roleAssignments.available -and $enrichment.roleAssignments.data -is [System.Collections.IDictionary] -and
        $enrichment.roleAssignments.data.Contains('data')) {
        $roleResult = $enrichment.roleAssignments.data
        $enrichment.roleAssignments.data = @($roleResult['data'])
        foreach ($key in 'completeness', 'activeComplete', 'eligibleComplete', 'roleDefinitionsComplete',
                         'warnings', 'groupEligibilityExpanded') {
            $enrichment.roleAssignments[$key] = $roleResult[$key]
        }
    }

    $avail = @($enrichment.Keys | Where-Object { $_ -ne 'collectedUtc' -and $enrichment[$_].available })
    Write-CapLog "Enrichment collected. Available datasets: $($avail -join ', ')" 'OK'
    return $enrichment
}

Export-ModuleMember -Function Get-CapEnrichment, Get-CapGroupEnrichment, `
    Get-CapRoleAssignmentEnrichment, Get-CapUserEnrichment, Get-CapMfaCapabilityEnrichment
