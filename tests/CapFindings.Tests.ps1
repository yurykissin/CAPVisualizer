#Requires -Version 7.0
<#
    Pester tests for the Phase 6 risk-scored findings model (CapFindings.psm1).
    Offline against samples/sample-export-enriched.json.
#>

BeforeAll {
    $repo = Split-Path $PSScriptRoot -Parent
    $modules = Join-Path $repo 'scripts/modules'
    foreach ($m in 'CapCommon', 'CapExport', 'CapNormalize', 'CapAudit', 'CapFindings') {
        Import-Module (Join-Path $modules "$m.psm1") -Force
    }

    $export = Import-CapExportJson -Path (Join-Path $repo 'samples/sample-export-enriched.json')
    $grouping = Get-CapAppGroupingMap
    $script:Normalized = @($export.policies | ForEach-Object { ConvertTo-CapNormalizedPolicy -Policy $_ -AppGroupingMap $grouping })
    $script:Enrichment = $export.enrichment
    $script:Result = Invoke-CapFindings -NormalizedPolicies $script:Normalized -Enrichment $script:Enrichment
}

Describe 'Risk scoring model' {
    It 'maps score bands to severities' {
        Get-CapSeverityFromScore -RiskScore 25 | Should -Be 'critical'
        Get-CapSeverityFromScore -RiskScore 16 | Should -Be 'high'
        Get-CapSeverityFromScore -RiskScore 9  | Should -Be 'medium'
        Get-CapSeverityFromScore -RiskScore 4  | Should -Be 'low'
    }

    It 'computes riskScore = impact x likelihood' {
        $f = New-CapFinding -CheckId 'x' -Title 't' -Impact 4 -Likelihood 3 -Description 'd'
        $f.riskScore | Should -Be 12
        $f.severity  | Should -Be 'high'
    }
}

Describe 'Directory findings' {
    It 'flags the ownerless break-glass exclusion group' {
        $f = @($script:Result.findings | Where-Object { $_.checkId -eq 'ownerless-exclusion-group' })
        $f.Count | Should -Be 1
        $f[0].affectedObjects | Should -Contain '33333333-3333-3333-3333-333333333333'
    }

    It 'flags the user that is not MFA-capable' {
        $f = @($script:Result.findings | Where-Object { $_.checkId -eq 'user-not-mfa-capable' })
        $f.Count | Should -Be 1
        $f[0].affectedObjects | Should -Contain '77777777-7777-7777-7777-777777777777'
    }

    It 'flags the inactive privileged (GA) account only' {
        $f = @($script:Result.findings | Where-Object { $_.checkId -eq 'inactive-privileged-account' })
        $f.Count | Should -Be 1
        $f[0].affectedObjects | Should -Contain '66666666-6666-6666-6666-666666666666'
        $f[0].severity | Should -Be 'high'
    }

    It 'gives every finding a generic summary and detection logic' {
        $f = @($script:Result.findings | Where-Object { $_.checkId -eq 'inactive-privileged-account' })
        $f[0].summary | Should -Not -BeNullOrEmpty
        $f[0].logic   | Should -Not -BeNullOrEmpty
    }

    It 'flags a disabled account that still holds a privileged role' {
        $ga = '62e90394-69f5-4237-9190-012177145e10'
        $enr = [ordered]@{
            collectedUtc    = '2026-07-22T00:00:00Z'
            users           = @{ data = @(
                @{ id = 'd1'; displayName = 'Disabled GA'; accountEnabled = $false; lastSignInDateTime = '2026-07-20T00:00:00Z' }
            ) }
            groups          = @{ data = @() }
            mfaCapability   = @{ data = @() }
            roleAssignments = @{ data = @(
                @{ principalId = 'd1'; roleTemplateId = $ga; roleName = 'Global Administrator' }
            ) }
        }
        $f = @(Get-CapDirectoryFindings -NormalizedPolicies @() -Enrichment $enr -InactiveDays 30 |
            Where-Object { $_.checkId -eq 'disabled-privileged-account' })
        $f.Count | Should -Be 1
        $f[0].affectedObjects | Should -Contain 'd1'
        $f[0].summary | Should -Not -BeNullOrEmpty
    }
}

Describe 'Policy-state findings' {
    It 'flags the report-only critical admin policy (CA005)' {
        $f = @($script:Result.findings | Where-Object { $_.checkId -eq 'critical-policy-inactive' })
        $f.Count | Should -BeGreaterThan 0
    }
}

Describe 'Audit issues promoted into findings' {
    It 'includes the app include/exclude overlap as a high finding' {
        $f = @($script:Result.findings | Where-Object { $_.checkId -eq 'app-include-exclude-overlap' })
        $f.Count | Should -Be 1
        $f[0].severity | Should -Be 'high'
        $f[0].references | Should -Contain 'MITRE ATT&CK T1078'
    }
}

Describe 'Findings summary' {
    It 'is sorted by risk score descending' {
        $scores = @($script:Result.findings | ForEach-Object { $_.riskScore })
        $sorted = @($scores | Sort-Object -Descending)
        "$scores" | Should -Be "$sorted"
    }

    It 'reports a severity breakdown consistent with the finding list' {
        $script:Result.summary.total | Should -Be (@($script:Result.findings).Count)
        $script:Result.summary.bySeverity['high'] | Should -Be (@($script:Result.findings | Where-Object { $_.severity -eq 'high' }).Count)
    }
}
