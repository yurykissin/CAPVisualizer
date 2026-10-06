#Requires -Modules Pester

BeforeAll {
    $repo = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repo 'scripts/modules/CapCommon.psm1') -Force
}

Describe 'Get-CapRequiredScopes' {
    It 'returns Policy.Read.All only for the minimum mode' {
        Get-CapRequiredScopes -RequestedScopes @('Policy.Read.All') |
            Should -Be @('Policy.Read.All')
    }

    It 'uses Directory.Read.All without redundant group and user scopes' {
        $scopes = @(Get-CapRequiredScopes -RequestedScopes @('Policy.Read.All') -ResolveNames -IncludeDirectory)
        $scopes | Should -Contain 'Directory.Read.All'
        $scopes | Should -Contain 'RoleManagement.Read.Directory'
        $scopes | Should -Contain 'AuditLog.Read.All'
        $scopes | Should -Contain 'UserAuthenticationMethod.Read.All'
        $scopes | Should -Not -Contain 'Group.Read.All'
        $scopes | Should -Not -Contain 'User.Read.All'
        @($scopes | Select-Object -Unique).Count | Should -Be $scopes.Count
    }

    It 'preserves explicitly requested narrower scopes without duplicates' {
        $scopes = @(Get-CapRequiredScopes -RequestedScopes @('Policy.Read.All', 'Group.Read.All', 'Group.Read.All'))
        $scopes | Should -Be @('Policy.Read.All', 'Group.Read.All')
    }
}
