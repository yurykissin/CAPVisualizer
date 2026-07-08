#Requires -Version 7.0
<#
    Pester tests for the Phase 8 assertion / test engine (CapTest.psm1).
    Offline against samples/sample-export-enriched.json.
#>

BeforeAll {
    $repo = Split-Path $PSScriptRoot -Parent
    $modules = Join-Path $repo 'scripts/modules'
    foreach ($m in 'CapCommon', 'CapExport', 'CapNormalize', 'CapScope', 'CapWhatIf', 'CapAudit', 'CapFindings', 'CapCompliance', 'CapTest') {
        Import-Module (Join-Path $modules "$m.psm1") -Force
    }

    $export = Import-CapExportJson -Path (Join-Path $repo 'samples/sample-export-enriched.json')
    $grouping = Get-CapAppGroupingMap
    $script:Normalized = @($export.policies | ForEach-Object { ConvertTo-CapNormalizedPolicy -Policy $_ -AppGroupingMap $grouping })
    $script:Enrichment = $export.enrichment

    # Write a temp assertion pack mixing passing + failing assertions.
    $script:PackPath = Join-Path ([System.IO.Path]::GetTempPath()) ("cap-assert-{0}.json" -f ([guid]::NewGuid()))
    @{
        schemaVersion = '1.0'
        name = 'test pack'
        assertions = @(
            @{ id = 'a1'; name = 'legacy blocked'; type = 'compliance'; control = 'MS.AAD.1.1'; expect = 'pass' }
            @{ id = 'a2'; name = 'high signin risk blocked (should fail)'; type = 'compliance'; control = 'MS.AAD.2.3'; expect = 'pass' }
            @{ id = 'a3'; name = 'nomfa user must get MFA'; type = 'whatif'; principalId = '77777777-7777-7777-7777-777777777777'; resource = '00000002-0000-0ff1-ce00-000000000000'; signals = @{ ClientApp = 'browser' }; expect = @{ mfaRequired = $true } }
            @{ id = 'a4'; name = 'legacy client must be blocked'; type = 'whatif'; principalId = '77777777-7777-7777-7777-777777777777'; resource = '00000002-0000-0ff1-ce00-000000000000'; signals = @{ ClientApp = 'exchangeActiveSync' }; expect = @{ blocked = $true } }
        )
    } | ConvertTo-Json -Depth 8 | Set-Content -Path $script:PackPath -Encoding utf8

    $script:Result = Invoke-CapTest -NormalizedPolicies $script:Normalized -Enrichment $script:Enrichment -AssertionPath $script:PackPath
}

AfterAll {
    if (Test-Path $script:PackPath) { Remove-Item $script:PackPath -Force }
}

Describe 'Assertion evaluation' {
    It 'passes the legacy-auth compliance assertion' {
        (@($script:Result.assertions | Where-Object { $_.id -eq 'a1' })[0]).result | Should -Be 'pass'
    }

    It 'fails the high-sign-in-risk compliance assertion (not met in fixture)' {
        (@($script:Result.assertions | Where-Object { $_.id -eq 'a2' })[0]).result | Should -Be 'fail'
    }

    It 'passes the what-if MFA assertion' {
        (@($script:Result.assertions | Where-Object { $_.id -eq 'a3' })[0]).result | Should -Be 'pass'
    }

    It 'passes the what-if legacy-block assertion' {
        (@($script:Result.assertions | Where-Object { $_.id -eq 'a4' })[0]).result | Should -Be 'pass'
    }

    It 'reports overall failure because one assertion failed' {
        $script:Result.passed | Should -BeFalse
        $script:Result.summary.failed | Should -Be 1
    }
}

Describe 'Machine-readable output' {
    It 'emits well-formed JUnit XML with the failure count' {
        $xml = [xml](ConvertTo-CapJUnit -TestResult $script:Result)
        $xml.testsuites.failures | Should -Be '1'
        [int]$xml.testsuites.tests | Should -Be 4
    }

    It 'emits SARIF 2.1.0 containing only the failing result' {
        $sarif = ConvertTo-CapSarif -TestResult $script:Result | ConvertFrom-Json
        $sarif.version | Should -Be '2.1.0'
        @($sarif.runs[0].results).Count | Should -Be 1
        $sarif.runs[0].results[0].ruleId | Should -Be 'a2'
    }
}

Describe 'Starter pack loads' {
    It 'loads the packaged starter assertion pack' {
        $pack = Get-CapAssertionPack
        @($pack.assertions).Count | Should -BeGreaterThan 0
    }
}
