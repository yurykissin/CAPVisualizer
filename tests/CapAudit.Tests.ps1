#Requires -Version 7.0
<#
    Pester tests for the Phase 5 contradiction / misconfiguration engine
    (CapAudit.psm1). Offline against samples/sample-export-enriched.json.
#>

BeforeAll {
    $repo = Split-Path $PSScriptRoot -Parent
    $modules = Join-Path $repo 'scripts/modules'
    foreach ($m in 'CapCommon', 'CapExport', 'CapNormalize', 'CapAudit') {
        Import-Module (Join-Path $modules "$m.psm1") -Force
    }

    $export = Import-CapExportJson -Path (Join-Path $repo 'samples/sample-export-enriched.json')
    $grouping = Get-CapAppGroupingMap
    $script:Normalized = @($export.policies | ForEach-Object { ConvertTo-CapNormalizedPolicy -Policy $_ -AppGroupingMap $grouping })
    $script:Enrichment = $export.enrichment
    $script:Audit = Invoke-CapAudit -NormalizedPolicies $script:Normalized -Enrichment $script:Enrichment
}

Describe 'Get-CapPrivilegedRoleSet' {
    It 'loads Global Administrator from the reference pack' {
        $set = Get-CapPrivilegedRoleSet
        $set['62e90394-69f5-4237-9190-012177145e10'] | Should -Be 'Global Administrator'
    }
}

Describe 'App-grouping contradiction (CA004)' {
    It 'detects the Exchange app cancelled by the Office365 exclusion' {
        $ca004 = @($script:Normalized | Where-Object { $_.displayName -like 'CA004*' })[0]
        $issues = @(Test-CapPolicyContradictions -NormalizedPolicy $ca004)
        $overlap = @($issues | Where-Object { $_.checkId -eq 'app-include-exclude-overlap' })
        $overlap.Count | Should -Be 1
        $overlap[0].evidence.apps | Should -Contain '00000002-0000-0ff1-ce00-000000000000'
        $overlap[0].severity | Should -Be 'high'
    }
}

Describe 'Legacy authentication coverage' {
    It 'passes because CA002 blocks legacy auth broadly' {
        @(Test-CapLegacyAuthCoverage -NormalizedPolicies $script:Normalized).Count | Should -Be 0
    }

    It 'flags a set with no legacy-auth block' {
        $noBlock = @($script:Normalized | Where-Object { $_.displayName -notlike 'CA002*' })
        $issues = @(Test-CapLegacyAuthCoverage -NormalizedPolicies $noBlock)
        $issues.Count | Should -Be 1
        $issues[0].checkId | Should -Be 'legacy-auth-not-blocked'
    }
}

Describe 'Exemption exposure' {
    It 'aggregates the break-glass group exclusion from CA001' {
        $bg = @($script:Audit.exemptionExposure | Where-Object { $_.id -eq '33333333-3333-3333-3333-333333333333' })
        $bg.Count | Should -Be 1
        $bg[0].excludedFromPolicies | Should -Contain 'CA001 - Require MFA for all users'
    }

    It 'flags the privileged (GA) user reachable via the excluded break-glass group' {
        $issue = @($script:Audit.issues | Where-Object { $_.checkId -eq 'privileged-via-excluded-group' })
        $issue.Count | Should -BeGreaterThan 0
        $issue[0].evidence.privilegedMembers | Should -Contain '22222222-2222-2222-2222-222222222222'
        $issue[0].severity | Should -Be 'high'
    }
}

Describe 'Invoke-CapAudit summary' {
    It 'produces a severity breakdown consistent with the issue list' {
        $sumHigh = $script:Audit.summary.bySeverity['high']
        $sumHigh | Should -Be (@($script:Audit.issues | Where-Object { $_.severity -eq 'high' }).Count)
        $script:Audit.summary.total | Should -Be (@($script:Audit.issues).Count)
    }
}
