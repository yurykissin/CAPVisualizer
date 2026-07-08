#Requires -Version 7.0
<#
    Pester tests for the Phase 3 offline what-if engine (CapWhatIf.psm1).
    All evaluation is offline against samples/sample-export-enriched.json.
#>

BeforeAll {
    $repo = Split-Path $PSScriptRoot -Parent
    $modules = Join-Path $repo 'scripts/modules'
    Import-Module (Join-Path $modules 'CapCommon.psm1') -Force
    Import-Module (Join-Path $modules 'CapExport.psm1') -Force
    Import-Module (Join-Path $modules 'CapNormalize.psm1') -Force
    Import-Module (Join-Path $modules 'CapScope.psm1') -Force
    Import-Module (Join-Path $modules 'CapWhatIf.psm1') -Force

    $export = Import-CapExportJson -Path (Join-Path $repo 'samples/sample-export-enriched.json')
    $grouping = Get-CapAppGroupingMap
    $script:Normalized = @($export.policies | ForEach-Object { ConvertTo-CapNormalizedPolicy -Policy $_ -AppGroupingMap $grouping })
    $script:Enrichment = $export.enrichment

    $script:NoMfaUser    = '77777777-7777-7777-7777-777777777777'   # Engineering group, not admin
    $script:BreakGlass   = '22222222-2222-2222-2222-222222222222'   # break-glass group + GA role
    $script:ExchangeApp  = '00000002-0000-0ff1-ce00-000000000000'

    function Invoke-WhatIf { param($h) Test-CapWhatIf @h }
}

Describe 'Test-CapWhatIf - standard user, browser to Exchange' {
    BeforeAll {
        $script:R = Test-CapWhatIf -PrincipalId $script:NoMfaUser -NormalizedPolicies $script:Normalized `
            -Enrichment $script:Enrichment -Resource $script:ExchangeApp -ClientApp 'browser'
    }

    It 'requires MFA definitively (CA001)' {
        $script:R.outcome.mfaRequired | Should -BeTrue
        @($script:R.definitive | Where-Object { $_.policyName -like 'CA001*' }).Count | Should -Be 1
    }

    It 'does not block (no legacy, no confirmed risk)' {
        $script:R.outcome.blocked | Should -BeFalse
    }

    It 'treats the legacy-auth block (CA002) as not applied for a browser client' {
        @($script:R.notApplied | Where-Object { $_.policyName -like 'CA002*' }).Count | Should -Be 1
    }

    It 'reports the high-risk block (CA003) as signal-dependent on userRisk' {
        $ca003 = @($script:R.signalDependent | Where-Object { $_.policyName -like 'CA003*' })
        $ca003.Count | Should -Be 1
        $ca003[0].missingSignals | Should -Contain 'userRisk'
    }

    It 'excludes the Exchange resource from CA004 via the Office365 grouping contradiction' {
        @($script:R.notApplied | Where-Object { $_.policyName -like 'CA004*' }).Count | Should -Be 1
    }
}

Describe 'Test-CapWhatIf - confirmed high user risk makes CA003 definitive' {
    It 'blocks when userRisk=high is supplied' {
        $r = Test-CapWhatIf -PrincipalId $script:NoMfaUser -NormalizedPolicies $script:Normalized `
            -Enrichment $script:Enrichment -Resource $script:ExchangeApp -ClientApp 'browser' -UserRisk 'high'
        $r.outcome.blocked | Should -BeTrue
        @($r.definitive | Where-Object { $_.policyName -like 'CA003*' }).Count | Should -Be 1
    }
}

Describe 'Test-CapWhatIf - break-glass account exclusions' {
    BeforeAll {
        $script:BG = Test-CapWhatIf -PrincipalId $script:BreakGlass -NormalizedPolicies $script:Normalized `
            -Enrichment $script:Enrichment -Resource $script:ExchangeApp -ClientApp 'browser'
    }

    It 'is excluded from the all-users MFA policy (CA001)' {
        @($script:BG.notApplied | Where-Object { $_.policyName -like 'CA001*' }).Count | Should -Be 1
        $script:BG.outcome.mfaRequired | Should -BeFalse
    }

    It 'matches the admin report-only policy (CA005) via role, tracked as report-only' {
        @($script:BG.definitive | Where-Object { $_.policyName -like 'CA005*' -and $_.reportOnly }).Count | Should -Be 1
        $script:BG.outcome.reportOnlyApplied | Should -Contain ($script:BG.definitive | Where-Object { $_.policyName -like 'CA005*' } | ForEach-Object { $_.policyName })
    }

    It 'flags no definitive enforcement gap for the break-glass sign-in' {
        $script:BG.outcome.noDefinitiveEnforcement | Should -BeTrue
    }
}

Describe 'Test-CapWhatIf - legacy client hits the block policy' {
    It 'blocks an exchangeActiveSync client via CA002' {
        $r = Test-CapWhatIf -PrincipalId $script:NoMfaUser -NormalizedPolicies $script:Normalized `
            -Enrichment $script:Enrichment -Resource $script:ExchangeApp -ClientApp 'exchangeActiveSync'
        $r.outcome.blocked | Should -BeTrue
        @($r.definitive | Where-Object { $_.policyName -like 'CA002*' }).Count | Should -Be 1
    }
}
