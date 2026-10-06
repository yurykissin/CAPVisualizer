#Requires -Modules Pester

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $root 'scripts/modules/CapCommon.psm1') -Force
    Import-Module (Join-Path $root 'scripts/modules/CapEnrich.psm1') -Force
}

Describe 'Get-CapRoleAssignmentEnrichment' {
    BeforeEach {
        Mock Invoke-CapGraphGet -ModuleName CapEnrich {
            param($Uri)
            switch -Wildcard ($Uri) {
                'roleManagement/directory/roleDefinitions*' {
                    return [pscustomobject]@{
                        id = 'definition-object-id'
                        templateId = '62e90394-69f5-4237-9190-012177145e10'
                        displayName = 'Global Administrator'
                        isBuiltIn = $true
                    }
                }
                'directoryRoles?*' {
                    return [pscustomobject]@{
                        id = 'active-role-object-id'
                        roleTemplateId = '62e90394-69f5-4237-9190-012177145e10'
                        displayName = 'Global Administrator'
                    }
                }
                'directoryRoles/*/members*' { return [pscustomobject]@{ id = 'active-user-id' } }
                'roleManagement/directory/roleEligibilityScheduleInstances*' {
                    return [pscustomobject]@{
                        principalId = 'eligible-user-id'
                        roleDefinitionId = 'definition-object-id'
                    }
                }
            }
        }
    }

    It 'maps the tenant role definition id to the stable template id' {
        $result = Get-CapRoleAssignmentEnrichment -IncludeStatus
        $eligible = @($result.data | Where-Object assignmentType -eq 'eligible')[0]

        $eligible.roleDefinitionId | Should -Be 'definition-object-id'
        $eligible.roleTemplateId | Should -Be '62e90394-69f5-4237-9190-012177145e10'
        $eligible.roleName | Should -Be 'Global Administrator'
        $result.completeness | Should -Be 'complete'
    }

    It 'keeps both identifiers on active assignments' {
        $result = Get-CapRoleAssignmentEnrichment -IncludeStatus
        $active = @($result.data | Where-Object assignmentType -eq 'active')[0]

        $active.roleDefinitionId | Should -Be 'definition-object-id'
        $active.roleTemplateId | Should -Be '62e90394-69f5-4237-9190-012177145e10'
    }

    It 'reports partial collection when PIM eligibility cannot be read' {
        Mock Invoke-CapGraphGet -ModuleName CapEnrich {
            param($Uri)
            if ($Uri -like 'roleManagement/directory/roleEligibilityScheduleInstances*') { throw 'denied' }
            if ($Uri -like 'roleManagement/directory/roleDefinitions*') {
                return [pscustomobject]@{
                    id = 'definition-object-id'; templateId = '62e90394-69f5-4237-9190-012177145e10'
                    displayName = 'Global Administrator'; isBuiltIn = $true
                }
            }
            if ($Uri -like 'directoryRoles?*') {
                return [pscustomobject]@{
                    id = 'active-role-object-id'; roleTemplateId = '62e90394-69f5-4237-9190-012177145e10'
                    displayName = 'Global Administrator'
                }
            }
            return [pscustomobject]@{ id = 'active-user-id' }
        }

        $result = Get-CapRoleAssignmentEnrichment -IncludeStatus
        $result.completeness | Should -Be 'partial'
        $result.eligibleComplete | Should -BeFalse
        ($result.warnings -join ' ') | Should -Match 'denied'
    }
}
