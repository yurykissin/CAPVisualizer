#Requires -Version 7.0
<#
    Pester tests for the rationalization & consolidation engine
    (CapConsolidate.psm1). Offline against samples/sample-export-enriched.json,
    with a couple of synthesized policies to exercise duplicate/merge clustering
    without mutating the shared fixture.
#>

BeforeAll {
    $repo = Split-Path $PSScriptRoot -Parent
    $modules = Join-Path $repo 'scripts/modules'
    foreach ($m in 'CapCommon', 'CapExport', 'CapNormalize', 'CapConsolidate') {
        Import-Module (Join-Path $modules "$m.psm1") -Force
    }

    $export = Import-CapExportJson -Path (Join-Path $repo 'samples/sample-export-enriched.json')
    $grouping = Get-CapAppGroupingMap
    $script:Normalized = @($export.policies | ForEach-Object { ConvertTo-CapNormalizedPolicy -Policy $_ -AppGroupingMap $grouping })

    # Find CA001 (Require MFA for all users) and build variants for clustering.
    $ca001 = @($script:Normalized | Where-Object { $_.displayName -like 'CA001*' })[0]

    # A true duplicate: same everything, different id/name.
    $dupJson = $ca001 | ConvertTo-Json -Depth 30
    $script:Dup = $dupJson | ConvertFrom-Json -Depth 30 -AsHashtable
    $script:Dup.id = 'dup-0000-0000-0000-000000000001'
    $script:Dup.displayName = 'CA001-COPY duplicate of MFA all users'

    # A merge candidate: same control/target/conditions but scoped to specific apps
    # instead of All (so appSig differs from CA001 but matches a second variant).
    $mergeAJson = $ca001 | ConvertTo-Json -Depth 30
    $script:MergeA = $mergeAJson | ConvertFrom-Json -Depth 30 -AsHashtable
    $script:MergeA.id = 'mrg-0000-0000-0000-00000000000a'
    $script:MergeA.displayName = 'Require MFA - App A only'
    $script:MergeA.conditions.applications.includeAll = $false
    $script:MergeA.conditions.applications.includeAppIds = @('aaaaaaaa-app-a')

    $mergeBJson = $mergeAJson
    $script:MergeB = $mergeBJson | ConvertFrom-Json -Depth 30 -AsHashtable
    $script:MergeB.id = 'mrg-0000-0000-0000-00000000000b'
    $script:MergeB.displayName = 'Require MFA - App B only'
    $script:MergeB.conditions.applications.includeAll = $false
    $script:MergeB.conditions.applications.includeAppIds = @('bbbbbbbb-app-b')

    $script:WithDup   = @($script:Normalized) + @($script:Dup)
    $script:WithMerge = @($script:Normalized) + @($script:MergeA, $script:MergeB)
    $script:Result    = Invoke-CapConsolidate -NormalizedPolicies $script:Normalized
}

Describe 'Get-CapPolicyFingerprint' {
    It 'produces a stable key that is identical for two functionally identical policies' {
        $a = Get-CapPolicyFingerprint -NormalizedPolicy $script:Normalized[0]
        $b = Get-CapPolicyFingerprint -NormalizedPolicy $script:Dup
        $a.key | Should -Be $b.key
    }
    It 'is order-independent for list-valued conditions' {
        $p = $script:Normalized | Where-Object { @($_.conditions.users.excludeGroups).Count -ge 2 } | Select-Object -First 1
        if (-not $p) { Set-ItResult -Skipped -Because 'no policy with >=2 exclude groups in the sample'; return }
        $fp1 = Get-CapPolicyFingerprint -NormalizedPolicy $p
        $shuffled = $p | ConvertTo-Json -Depth 30 | ConvertFrom-Json -Depth 30 -AsHashtable
        $shuffled.conditions.users.excludeGroups = @($p.conditions.users.excludeGroups | Sort-Object -Descending)
        $fp2 = Get-CapPolicyFingerprint -NormalizedPolicy $shuffled
        $fp1.key | Should -Be $fp2.key
    }
}

Describe 'Find-CapDuplicatePolicies' {
    It 'detects an exact duplicate cluster' {
        $d = Find-CapDuplicatePolicies -NormalizedPolicies $script:WithDup
        $cluster = @($d.exact | Where-Object { @($_.members.id) -contains $script:Dup.id })
        $cluster.Count | Should -Be 1
        $cluster[0].count | Should -Be 2
    }
    It 'detects merge candidates that differ only by application' {
        $d = Find-CapDuplicatePolicies -NormalizedPolicies $script:WithMerge
        $cluster = @($d.merge | Where-Object { @($_.members.id) -contains $script:MergeA.id -and @($_.members.id) -contains $script:MergeB.id })
        $cluster.Count | Should -Be 1
    }
    It 'finds no exact duplicates in the clean sample' {
        @($script:Result.duplicates.exact).Count | Should -Be 0
    }
}

Describe 'Get-CapDeadWeight' {
    It 'flags the report-only admin policy (CA005) as dead weight' {
        $dead = Get-CapDeadWeight -NormalizedPolicies $script:Normalized
        $ca005 = @($dead | Where-Object { $_.displayName -like 'CA005*' })
        $ca005.Count | Should -Be 1
        ($ca005[0].reasons -join ' ') | Should -Match 'report-only'
    }
}

Describe 'Test-CapBaselineCompleteness' {
    It 'reports device-code flow as a gap when no policy blocks it' {
        $c = Test-CapBaselineCompleteness -NormalizedPolicies $script:Normalized
        $dc = @($c | Where-Object { $_.control -eq 'Block device-code flow' })[0]
        $dc.present | Should -BeFalse
        $dc.severity | Should -Be 'high'
    }
    It 'credits the user-risk control because CA003 blocks high-risk users' {
        $c = Test-CapBaselineCompleteness -NormalizedPolicies $script:Normalized
        $ur = @($c | Where-Object { $_.control -eq 'User-risk policy' })[0]
        $ur.present | Should -BeTrue
    }
    It 'detects device-code flow even when transferMethods is a comma-joined token' {
        # Graph returns conditions.authenticationFlows.transferMethods as one
        # comma-separated string; the check must split it, not match the whole blob.
        # Deep-clone a real enabled policy so grant/condition shapes are complete,
        # then set the comma-joined transferMethods token + Block.
        $blocker = $script:Normalized[0] | ConvertTo-Json -Depth 40 | ConvertFrom-Json
        $blocker.id = 'dcf-combo'
        $blocker.displayName = 'Block device code (combined flows)'
        $blocker.conditions.authFlows = @('deviceCodeFlow,authenticationTransfer')
        $blocker.grant.block = $true
        $c = Test-CapBaselineCompleteness -NormalizedPolicies (@($script:Normalized) + $blocker)
        $dc = @($c | Where-Object { $_.control -eq 'Block device-code flow' })[0]
        $dc.present | Should -BeTrue
        $tr = @($c | Where-Object { $_.control -eq 'Control authentication transfer' })[0]
        $tr.present | Should -BeTrue
    }
}

Describe 'Invoke-CapConsolidate summary' {
    It 'counts states consistently and estimates a reduced target' {
        $s = $script:Result.summary
        $s.total | Should -Be @($script:Normalized).Count
        ($s.enforced + $s.reportOnly + $s.disabled) | Should -Be $s.total
        $s.estimatedTarget | Should -BeLessOrEqual $s.total
    }
}
