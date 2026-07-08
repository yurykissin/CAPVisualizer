#Requires -Modules Pester
<#
    Pester tests for CapNormalize.psm1 (Phase 1). Pure/offline - no Graph.
#>

BeforeAll {
    $modules = Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/modules'
    Import-Module (Join-Path $modules 'CapNormalize.psm1') -Force
    $script:GroupingMap = Get-CapAppGroupingMap
}

Describe 'Get-CapAppGroupingMap' {
    It 'loads the Office365 grouping with member appIds' {
        $script:GroupingMap.ContainsKey('Office365') | Should -BeTrue
        $script:GroupingMap['Office365'] | Should -Contain '00000002-0000-0ff1-ce00-000000000000'
    }
}

Describe 'Expand-CapAppGrouping' {
    It 'flags includeAll for the All token' {
        $r = Expand-CapAppGrouping -Values @('All') -GroupingMap $script:GroupingMap
        $r.includeAll | Should -BeTrue
        $r.none | Should -BeFalse
    }
    It 'expands Office365 into concrete appIds' {
        $r = Expand-CapAppGrouping -Values @('Office365') -GroupingMap $script:GroupingMap
        $r.groupings | Should -Contain 'Office365'
        $r.appIds | Should -Contain '00000003-0000-0ff1-ce00-000000000000'  # SharePoint Online
    }
    It 'passes through a bare appId unchanged' {
        $r = Expand-CapAppGrouping -Values @('797f4846-ba00-4fd7-ba43-dac1f8f63013') -GroupingMap $script:GroupingMap
        $r.appIds | Should -Contain '797f4846-ba00-4fd7-ba43-dac1f8f63013'
        $r.includeAll | Should -BeFalse
    }
}

Describe 'Get-CapCanonicalClientApps' {
    It 'defaults an empty condition to all four client-app types' {
        $r = Get-CapCanonicalClientApps -ClientAppTypes @()
        $r.isAll | Should -BeTrue
        $r.effective.Count | Should -Be 4
        $r.includesLegacy | Should -BeTrue
    }
    It 'identifies a legacy-only condition' {
        $r = Get-CapCanonicalClientApps -ClientAppTypes @('exchangeActiveSync', 'other')
        $r.isAll | Should -BeFalse
        $r.includesLegacy | Should -BeTrue
        $r.includesModern | Should -BeFalse
    }
    It 'identifies a browser-only condition as non-legacy' {
        $r = Get-CapCanonicalClientApps -ClientAppTypes @('browser')
        $r.includesLegacy | Should -BeFalse
        $r.includesModern | Should -BeTrue
    }
}

Describe 'Get-CapCanonicalPlatforms' {
    It 'returns null when there is no platform constraint' {
        Get-CapCanonicalPlatforms $null | Should -BeNullOrEmpty
    }
    It 'expands all minus excludes' {
        $cond = @{ includePlatforms = @('all'); excludePlatforms = @('linux') }
        $r = Get-CapCanonicalPlatforms $cond
        $r.isAll | Should -BeTrue
        $r.effective | Should -Not -Contain 'linux'
        $r.effective | Should -Contain 'windows'
    }
}

Describe 'ConvertTo-CapNormalizedPolicy over the sample export' {
    BeforeAll {
        $samplePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'samples/sample-export.json'
        $raw = Get-Content -LiteralPath $samplePath -Raw | ConvertFrom-Json -Depth 40 -AsHashtable
        $script:Norm = @($raw.policies | ForEach-Object { ConvertTo-CapNormalizedPolicy -Policy $_ -AppGroupingMap $script:GroupingMap })
    }
    It 'normalizes all sample policies' {
        $script:Norm.Count | Should -Be 3
    }
    It 'marks the MFA policy as enforced with includeAll users/apps and MFA required' {
        $p = $script:Norm | Where-Object { $_.displayName -like '*Require MFA*' }
        $p.enforced | Should -BeTrue
        $p.conditions.users.includeAll | Should -BeTrue
        $p.conditions.applications.includeAll | Should -BeTrue
        $p.grant.requireMfa | Should -BeTrue
    }
    It 'classifies the legacy-auth block policy as legacy client apps + block' {
        $p = $script:Norm | Where-Object { $_.displayName -like '*legacy*' }
        $p.conditions.clientApps.includesLegacy | Should -BeTrue
        $p.grant.block | Should -BeTrue
    }
    It 'flags the report-only policy and its signInRisk signal dependency' {
        $p = $script:Norm | Where-Object { $_.displayName -like '*Report only*' }
        $p.reportOnly | Should -BeTrue
        $p.enforced | Should -BeFalse
        $p.signalsRequired | Should -Contain 'signInRisk'
    }
}
