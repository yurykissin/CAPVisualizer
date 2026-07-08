#Requires -Version 7.0
<#
    Pester tests for the Phase 4 gap-permutation engine (CapAnalyze.psm1).
    Offline against samples/sample-export-enriched.json.
#>

BeforeAll {
    $repo = Split-Path $PSScriptRoot -Parent
    $modules = Join-Path $repo 'scripts/modules'
    foreach ($m in 'CapCommon', 'CapExport', 'CapNormalize', 'CapScope', 'CapWhatIf', 'CapAnalyze') {
        Import-Module (Join-Path $modules "$m.psm1") -Force
    }

    $export = Import-CapExportJson -Path (Join-Path $repo 'samples/sample-export-enriched.json')
    $grouping = Get-CapAppGroupingMap
    $script:Normalized = @($export.policies | ForEach-Object { ConvertTo-CapNormalizedPolicy -Policy $_ -AppGroupingMap $grouping })
    $script:Enrichment = $export.enrichment

    $script:NoMfaUser   = '77777777-7777-7777-7777-777777777777'
    $script:BreakGlass  = '22222222-2222-2222-2222-222222222222'
    $script:ExchangeApp = '00000002-0000-0ff1-ce00-000000000000'
}

Describe 'Get-CapRelevantSignals' {
    It 'includes ClientApp plus the signals the in-scope policies gate on' {
        $dims = Get-CapRelevantSignals -PrincipalId $script:NoMfaUser -NormalizedPolicies $script:Normalized -Enrichment $script:Enrichment -Resource $script:ExchangeApp
        $dims | Should -Contain 'ClientApp'
        $dims | Should -Contain 'UserRisk'   # CA003 gates on high user risk
    }
}

Describe 'Invoke-CapAnalyze - standard user to Exchange' {
    BeforeAll {
        $script:A = Invoke-CapAnalyze -PrincipalId $script:NoMfaUser -NormalizedPolicies $script:Normalized `
            -Enrichment $script:Enrichment -Resource $script:ExchangeApp
    }

    It 'evaluates the full cartesian product within the cap' {
        $script:A.evaluated | Should -Be $script:A.totalScenarios
        $script:A.totalScenarios | Should -BeGreaterThan 1
    }

    It 'never reports a legacy-auth gap (CA002 blocks legacy definitively)' {
        @($script:A.gaps | Where-Object { $_.gapType -eq 'legacy-auth-bypass' }).Count | Should -Be 0
    }

    It 'produces a deterministic summary consistent with the gap list' {
        $script:A.summary.gapCount | Should -Be (@($script:A.gaps).Count)
        $script:A.summary.actionableCount | Should -Be (@($script:A.gaps | Where-Object { -not $_.byDesign }).Count)
    }
}

Describe 'Invoke-CapAnalyze - break-glass account is a coverage gap' {
    BeforeAll {
        $script:BG = Invoke-CapAnalyze -PrincipalId $script:BreakGlass -NormalizedPolicies $script:Normalized `
            -Enrichment $script:Enrichment -Resource $script:ExchangeApp
    }

    It 'finds actionable gaps because the break-glass user is excluded from MFA' {
        $script:BG.summary.actionableCount | Should -BeGreaterThan 0
    }

    It 'classifies clean-risk scenarios as report-only-only or no-enforcement' {
        $clean = @($script:BG.gaps | Where-Object { $_.signals['ClientApp'] -eq 'browser' -and (-not $_.byDesign) })
        $clean.Count | Should -BeGreaterThan 0
        @($clean | Where-Object { $_.gapType -in @('report-only-only', 'no-enforcement') }).Count | Should -Be $clean.Count
    }
}

Describe 'ConvertTo-CapAnalyzeJsonl' {
    It 'emits one compact JSON line per gap' {
        $a = Invoke-CapAnalyze -PrincipalId $script:BreakGlass -NormalizedPolicies $script:Normalized `
            -Enrichment $script:Enrichment -Resource $script:ExchangeApp
        $lines = @(ConvertTo-CapAnalyzeJsonl -AnalyzeResult $a)
        $lines.Count | Should -Be (@($a.gaps).Count)
        ($lines[0] | ConvertFrom-Json).principalId | Should -Be $script:BreakGlass
    }
}
