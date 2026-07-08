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
    It 'loads all CA-relevant controls' {
        $ids = @($script:Result.controls | ForEach-Object { $_.id })
        $ids | Should -Contain 'MS.AAD.1.1'
        $ids | Should -Contain 'MS.AAD.3.2'
        $ids | Should -Contain 'MS.AAD.3.6'
        $ids | Should -Contain 'MS.AAD.3.7'
        $ids | Should -Contain 'MS.AAD.3.8'
        @($ids).Count | Should -Be 8
    }

    It 'carries NIST and MITRE references per control' {
        $c11 = @($script:Result.controls | Where-Object { $_.id -eq 'MS.AAD.1.1' })[0]
        $c11.nist  | Should -Contain 'IA-2'
        $c11.mitre | Should -Contain 'T1110'
    }
}

Describe 'Control evaluation against the fixture' {
    It 'passes MS.AAD.1.1 (CA002 blocks legacy auth)' {
        $c = @($script:Result.controls | Where-Object { $_.id -eq 'MS.AAD.1.1' })[0]
        $c.result | Should -Be 'pass'
        $c.evidence | Should -Contain 'CA002 - Block legacy authentication'
    }

    It 'passes MS.AAD.2.1 (CA003 blocks high-risk users)' {
        $c = @($script:Result.controls | Where-Object { $_.id -eq 'MS.AAD.2.1' })[0]
        $c.result | Should -Be 'pass'
        $c.evidence | Should -Contain 'CA003 - Block high risk users'
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
        $c.evidence | Should -Contain 'CA001 - Require MFA for all users'
    }

    It 'fails MS.AAD.3.6 (no phishing-resistant strength for privileged roles in the fixture)' {
        $c = @($script:Result.controls | Where-Object { $_.id -eq 'MS.AAD.3.6' })[0]
        $c.result | Should -Be 'fail'
    }

    It 'fails MS.AAD.3.7 (CA005 managed-device policy is report-only and admin-scoped)' {
        $c = @($script:Result.controls | Where-Object { $_.id -eq 'MS.AAD.3.7' })[0]
        $c.result | Should -Be 'fail'
    }

    It 'marks MS.AAD.3.8 as manual (no automated check)' {
        $c = @($script:Result.controls | Where-Object { $_.id -eq 'MS.AAD.3.8' })[0]
        $c.result | Should -Be 'manual'
    }
}

Describe 'Compliance summary' {
    It 'computes pass/fail counts and a pass rate' {
        $s = $script:Result.summary
        $s.total | Should -Be 8
        $s.pass  | Should -Be (@($script:Result.controls | Where-Object { $_.result -eq 'pass' }).Count)
        $s.fail  | Should -Be (@($script:Result.controls | Where-Object { $_.result -eq 'fail' }).Count)
        $s.passRate | Should -BeGreaterThan 0
    }
}
