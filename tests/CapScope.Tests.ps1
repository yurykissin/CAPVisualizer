#Requires -Modules Pester
<#
    Pester tests for CapScope.psm1 (Phase 2). Offline against the enriched fixture.
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    $modules = Join-Path $root 'scripts/modules'
    Import-Module (Join-Path $modules 'CapCommon.psm1') -Force
    Import-Module (Join-Path $modules 'CapExport.psm1') -Force
    Import-Module (Join-Path $modules 'CapNormalize.psm1') -Force
    Import-Module (Join-Path $modules 'CapScope.psm1') -Force

    $export = Import-CapExportJson -Path (Join-Path $root 'samples/sample-export-enriched.json')
    $gm = Get-CapAppGroupingMap
    $script:Norm = @($export.policies | ForEach-Object { ConvertTo-CapNormalizedPolicy -Policy $_ -AppGroupingMap $gm })
    $script:Enrichment = $export.enrichment

    $script:BreakGlass = '22222222-2222-2222-2222-222222222222'  # in break-glass group + GA role
    $script:NoMfaUser  = '77777777-7777-7777-7777-777777777777'  # in Engineering group
}

Describe 'Resolve-CapPrincipalContext' {
    It 'expands break-glass user group membership and GA role' {
        $ctx = Resolve-CapPrincipalContext -PrincipalId $script:BreakGlass -Enrichment $script:Enrichment
        $ctx.groupIds | Should -Contain '33333333-3333-3333-3333-333333333333'
        $ctx.roleTemplateIds | Should -Contain '62e90394-69f5-4237-9190-012177145e10'
        $ctx.displayName | Should -Be 'Break Glass Admin'
    }
    It 'warns when enrichment is absent' {
        $ctx = Resolve-CapPrincipalContext -PrincipalId $script:BreakGlass -Enrichment $null
        $ctx.warnings.Count | Should -BeGreaterThan 0
    }
}

Describe 'Resolve-CapScope for the break-glass admin' {
    BeforeAll {
        $script:Scope = Resolve-CapScope -PrincipalId $script:BreakGlass -NormalizedPolicies $script:Norm -Enrichment $script:Enrichment
    }
    It 'marks the MFA policy as Excluded via the break-glass group' {
        $r = $script:Scope.results | Where-Object { $_.policyName -like 'CA001*' }
        $r.bucket | Should -Be 'Excluded'
        $r.via | Should -Be '33333333-3333-3333-3333-333333333333'
    }
    It 'places the admin in scope (via GA role) for the report-only compliant-device policy' {
        $r = $script:Scope.results | Where-Object { $_.policyName -like 'CA005*' }
        $r.bucket | Should -Be 'InScopeVia'
        $r.via | Should -Be '62e90394-69f5-4237-9190-012177145e10'
    }
    It 'includes the admin directly (All users) for the legacy-block policy' {
        $r = $script:Scope.results | Where-Object { $_.policyName -like 'CA002*' }
        $r.bucket | Should -Be 'InScopeDirect'
    }
}

Describe 'Resolve-CapScope for a normal user' {
    It 'is in scope for the all-users MFA policy (not in break-glass group)' {
        $scope = Resolve-CapScope -PrincipalId $script:NoMfaUser -NormalizedPolicies $script:Norm -Enrichment $script:Enrichment
        $r = $scope.results | Where-Object { $_.policyName -like 'CA001*' }
        $r.bucket | Should -Be 'InScopeDirect'
        # Not a Global Admin, so the admin-only report-only policy does not target them
        $r5 = $scope.results | Where-Object { $_.policyName -like 'CA005*' }
        $r5.bucket | Should -Be 'NotInScope'
    }
}
