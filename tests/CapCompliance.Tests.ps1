#Requires -Version 7.0
<#
    Pester tests for the Phase 7 compliance baseline engine (CapCompliance.psm1).
    Offline against samples/sample-export-enriched.json.
#>

BeforeAll {
    $repo = Split-Path $PSScriptRoot -Parent
    $modules = Join-Path $repo 'scripts/modules'
    foreach ($m in 'CapCommon', 'CapExport', 'CapNormalize', 'CapCompliance') {
        Import-Module (Join-Path $modules "$m.psm1") -Force
    }

    $export = Import-CapExportJson -Path (Join-Path $repo 'samples/sample-export-enriched.json')
    $grouping = Get-CapAppGroupingMap
    $script:Normalized = @($export.policies | ForEach-Object { ConvertTo-CapNormalizedPolicy -Policy $_ -AppGroupingMap $grouping })
    $script:Result = Invoke-CapCompliance -NormalizedPolicies $script:Normalized
}

Describe 'Baseline pack' {
    It 'loads the full SCuBA MS.AAD baseline' {
        $ids = @($script:Result.controls | ForEach-Object { $_.id })
        $ids | Should -Contain 'MS.AAD.1.1'
        $ids | Should -Contain 'MS.AAD.3.9'
        $ids | Should -Contain 'MS.AAD.7.1'
        $ids | Should -Contain 'MS.AAD.8.1'
        $ids | Should -Contain 'MS.AAD.9.1'
        @($ids).Count | Should -Be 34
    }

    It 'carries NIST and MITRE references per control' {
        $c11 = @($script:Result.controls | Where-Object { $_.id -eq 'MS.AAD.1.1' })[0]
        $c11.nist  | Should -Contain 'CM-7'
        $c11.mitre | Should -Contain 'T1110'
    }

    It 'tags each control with a scope' {
        $ca = @($script:Result.controls | Where-Object { $_.id -eq 'MS.AAD.1.1' })[0]
        $ca.scope | Should -Be 'conditional-access'
        $pim = @($script:Result.controls | Where-Object { $_.id -eq 'MS.AAD.7.1' })[0]
        $pim.scope | Should -Be 'privileged-access'
    }
}

Describe 'Control evaluation against the fixture' {
    It 'passes MS.AAD.1.1 (CA002 blocks legacy auth)' {
        $c = @($script:Result.controls | Where-Object { $_.id -eq 'MS.AAD.1.1' })[0]
        $c.result | Should -Be 'pass'
        # Evidence cites policy ids, not names: names never leave the tenant.
        $c.evidence | Should -Contain 'aaaaaaaa-0000-0000-0000-000000000002'
    }

    It 'passes MS.AAD.2.1 (CA003 blocks high-risk users)' {
        $c = @($script:Result.controls | Where-Object { $_.id -eq 'MS.AAD.2.1' })[0]
        $c.result | Should -Be 'pass'
        # Evidence cites policy ids, not names: names never leave the tenant.
        $c.evidence | Should -Contain 'aaaaaaaa-0000-0000-0000-000000000003'
    }

    It 'fails MS.AAD.2.3 (no high sign-in-risk block in the fixture)' {
        $c = @($script:Result.controls | Where-Object { $_.id -eq 'MS.AAD.2.3' })[0]
        $c.result | Should -Be 'fail'
    }

    It 'fails MS.AAD.3.1 (no phishing-resistant strength in the fixture)' {
        $c = @($script:Result.controls | Where-Object { $_.id -eq 'MS.AAD.3.1' })[0]
        $c.result | Should -Be 'fail'
    }

    It 'passes MS.AAD.3.2 (CA001 requires MFA for all users)' {
        $c = @($script:Result.controls | Where-Object { $_.id -eq 'MS.AAD.3.2' })[0]
        $c.result | Should -Be 'pass'
        # Evidence cites policy ids, not names: names never leave the tenant.
        $c.evidence | Should -Contain 'aaaaaaaa-0000-0000-0000-000000000001'
    }

    It 'fails MS.AAD.3.6 (no phishing-resistant strength for privileged roles in the fixture)' {
        $c = @($script:Result.controls | Where-Object { $_.id -eq 'MS.AAD.3.6' })[0]
        $c.result | Should -Be 'fail'
    }

    It 'fails MS.AAD.3.7 (CA005 managed-device policy is report-only and admin-scoped)' {
        $c = @($script:Result.controls | Where-Object { $_.id -eq 'MS.AAD.3.7' })[0]
        $c.result | Should -Be 'fail'
    }

    It 'fails MS.AAD.3.9 (no device-code-flow block in the fixture)' {
        $c = @($script:Result.controls | Where-Object { $_.id -eq 'MS.AAD.3.9' })[0]
        $c.result | Should -Be 'fail'
    }

    It 'fails MS.AAD.9.1 (no agent-risk block in the fixture)' {
        $c = @($script:Result.controls | Where-Object { $_.id -eq 'MS.AAD.9.1' })[0]
        $c.result | Should -Be 'fail'
    }

    It 'marks non-CA controls as manual with official guidance' {
        $c = @($script:Result.controls | Where-Object { $_.id -eq 'MS.AAD.7.1' })[0]
        $c.result | Should -Be 'manual'
        $c.rationale | Should -Not -BeNullOrEmpty
    }
}

Describe 'Compliance summary' {
    It 'computes pass/fail counts and a pass rate over automatable controls' {
        $s = $script:Result.summary
        $s.total | Should -Be 34
        $s.automatable | Should -Be 9
        $s.pass  | Should -Be (@($script:Result.controls | Where-Object { $_.result -eq 'pass' }).Count)
        $s.fail  | Should -Be (@($script:Result.controls | Where-Object { $_.result -eq 'fail' }).Count)
        $s.manual | Should -BeGreaterThan 0
        $s.passRate | Should -BeGreaterThan 0
    }
}
