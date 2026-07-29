#Requires -Version 7.0
<#
    Pester tests for name separation (CapNames.psm1): the dictionary, the
    name-free projection, the leak test that backs the safe bundle, and
    re-hydration of an AI-generated report. Offline against
    samples/sample-export-enriched.json.
#>

BeforeAll {
    $repo = Split-Path $PSScriptRoot -Parent
    $modules = Join-Path $repo 'scripts/modules'
    foreach ($m in 'CapCommon', 'CapExport', 'CapNames') {
        Import-Module (Join-Path $modules "$m.psm1") -Force
    }

    $script:Repo = $repo
    $script:Export = Import-CapExportJson -Path (Join-Path $repo 'samples/sample-export-enriched.json')
    $script:NameMap = if ($script:Export.Contains('nameMap')) { $script:Export['nameMap'] } else { @{} }
    $script:Dict = New-CapNameDictionary -Export $script:Export -NameMap $script:NameMap -Snapshot '20260101-000000'
    $script:Safe = ConvertTo-CapSafeObject -InputObject $script:Export -Dictionary $script:Dict
    $script:PseudoDict = New-CapNameDictionary -Export $script:Export -NameMap $script:NameMap -Snapshot '20260101-000000' -Pseudonymize
    $script:PseudoSafe = ConvertTo-CapSafeObject -InputObject $script:Export -Dictionary $script:PseudoDict
}

Describe 'New-CapNameDictionary' {
    It 'collects policy, location, user and group names' {
        $names = @($script:Dict.entries.Values | ForEach-Object { $_.name })
        $names | Should -Contain 'CA001 - Require MFA for all users'
        $names | Should -Contain 'Corporate HQ'
        $names | Should -Contain 'Break Glass Admin'
        $names | Should -Contain 'Break-glass exclusions'
    }

    It 'collects the operator account and user principal names' {
        $names = @($script:Dict.entries.Values | ForEach-Object { $_.name })
        $names | Should -Contain 'admin@contoso.com'
        $names | Should -Contain 'olddba@contoso.com'
    }

    It 'uses the object id as the token when one exists' {
        $policy = @($script:Dict.entries.Values | Where-Object { $_.name -eq 'CA001 - Require MFA for all users' })[0]
        $policy.token | Should -Be 'aaaaaaaa-0000-0000-0000-000000000001'
    }

    It 'does not mask well-known Microsoft role names' {
        $names = @($script:Dict.entries.Values | ForEach-Object { $_.name })
        $names | Should -Not -Contain 'Global Administrator'
    }

    It 'records the snapshot it belongs to' {
        $script:Dict.snapshot | Should -Be '20260101-000000'
    }
}

Describe 'ConvertTo-CapSafeObject' {
    It 'removes every dictionary name from the export' {
        $leaks = @(Test-CapNameLeak -Dictionary $script:Dict -InputObject $script:Safe)
        $leaks.Count | Should -Be 0
    }

    It 'preserves array shape for single-element and empty collections' {
        $json = $script:Safe | ConvertTo-Json -Depth 30
        $round = $json | ConvertFrom-Json -Depth 30 -AsHashtable
        $round.policies.Count | Should -Be $script:Export.policies.Count
        , $round.namedLocations | Should -BeOfType [System.Object[]]
    }

    It 'keeps object ids intact when not pseudonymizing' {
        $script:Safe.policies[0].id | Should -Be $script:Export.policies[0].id
    }

    It 'round-trips back to the original names' {
        $back = ConvertFrom-CapSafeObject -InputObject $script:Safe -Dictionary $script:Dict
        $back.policies[0].displayName | Should -Be $script:Export.policies[0].displayName
    }
}

Describe 'Pseudonymized projection' {
    It 'leaves no tenant-specific GUID behind' {
        $leaks = @(Test-CapNameLeak -Dictionary $script:PseudoDict -InputObject $script:PseudoSafe -RequirePseudonymized)
        @($leaks | Where-Object { $_.kind -eq 'guid' }).Count | Should -Be 0
    }

    It 'keeps well-known Microsoft identifiers readable' {
        $json = $script:PseudoSafe | ConvertTo-Json -Depth 30
        $json | Should -BeLike '*00000002-0000-0ff1-ce00-000000000000*'
    }

    It 'aliases the tenant id as TENANT-001' {
        $script:PseudoSafe.metadata.tenantId | Should -Be 'TENANT-001'
    }
}

Describe 'Test-CapNameLeak' {
    It 'catches a planted display name' {
        $planted = @{ note = 'Reviewed by Break Glass Admin last week' }
        $leaks = @(Test-CapNameLeak -Dictionary $script:Dict -InputObject $planted)
        @($leaks | Where-Object { $_.kind -eq 'name' }).Count | Should -BeGreaterThan 0
    }

    It 'catches an IP-shaped string when pseudonymization is required' {
        $planted = @{ range = '10.20.30.40/24' }
        $leaks = @(Test-CapNameLeak -Dictionary $script:Dict -InputObject $planted -RequirePseudonymized)
        @($leaks | Where-Object { $_.kind -eq 'ip' }).Count | Should -BeGreaterThan 0
    }
}

Describe 'Restore-CapNameText' {
    It 'restores names inside a markdown table' {
        $md = "| High | Inactive | 66666666-6666-6666-6666-666666666666 |"
        $out = Restore-CapNameText -Text $md -Dictionary $script:Dict
        $out | Should -BeLike '*Old DBA*'
    }

    It 'restores names inside a fenced code block' {
        $md = "``````" + "`npolicy: aaaaaaaa-0000-0000-0000-000000000001`n" + "``````"
        $out = Restore-CapNameText -Text $md -Dictionary $script:Dict
        $out | Should -BeLike '*CA001 - Require MFA for all users*'
    }

    It 'resolves an alias through to the real value' {
        $alias = @($script:PseudoDict.idAliases.Keys)[0]
        $token = $script:PseudoDict.idAliases[$alias]
        $out = Restore-CapNameText -Text "Object $token was reviewed" -Dictionary $script:PseudoDict
        $out | Should -Not -BeLike "*$token*"
    }
}

Describe 'Get-CapUnresolvedTokens' {
    It 'reports alias-shaped tokens that were never mapped' {
        $found = @(Get-CapUnresolvedTokens -Text 'See USER-004 and GROUP-009 for detail')
        $found | Should -Contain 'USER-004'
        $found | Should -Contain 'GROUP-009'
    }

    It 'returns nothing for clean text' {
        @(Get-CapUnresolvedTokens -Text 'No tokens here at all').Count | Should -Be 0
    }
}

Describe 'Import-CapNameDictionary' {
    It 'rejects a file that is not a dictionary' {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) "cap-not-a-dict-$([guid]::NewGuid()).json"
        '{ "kind": "somethingElse" }' | Set-Content -LiteralPath $tmp -Encoding utf8
        { Import-CapNameDictionary -Path $tmp } | Should -Throw
        Remove-Item -LiteralPath $tmp -Force
    }

    It 'returns null when no dictionary is present' {
        $dir = Join-Path ([IO.Path]::GetTempPath()) "cap-empty-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        Import-CapNameDictionary -NearExport (Join-Path $dir 'export.json') | Should -BeNullOrEmpty
        Remove-Item -LiteralPath $dir -Recurse -Force
    }
}

Describe 'Structural sweep of non-name fields' {
    BeforeAll {
        $e = Import-CapExportJson -Path (Join-Path $script:Repo 'samples/sample-export-enriched.json')
        $e.namedLocations[0].ipRanges = @(@{ cidrAddress = '203.0.113.0/24' })
        $e.policies[0].conditions.devices = @{ deviceFilter = @{ mode = 'include'; rule = 'device.displayName -startsWith "CONTOSO-"' } }
        $script:SweepDict = New-CapNameDictionary -Export $e -NameMap $e['nameMap'] -Snapshot 'x' -Pseudonymize
        $script:SweepJson = (ConvertTo-CapSafeObject -InputObject $e -Dictionary $script:SweepDict) | ConvertTo-Json -Depth 30
        $script:SweepSafe = $script:SweepJson | ConvertFrom-Json -Depth 30 -AsHashtable
    }

    It 'masks named-location IP ranges' {
        $script:SweepJson | Should -Not -BeLike '*203.0.113*'
    }

    It 'masks device-filter rules that embed naming conventions' {
        $script:SweepJson | Should -Not -BeLike '*CONTOSO-*'
    }

    It 'masks user principal names nested in enrichment payloads' {
        $script:SweepJson | Should -Not -BeLike '*@contoso.com*'
    }

    It 'leaves structural enum values such as policy state alone' {
        $script:SweepSafe.policies[0].state | Should -Be 'enabled'
    }
}

Describe 'Live-tenant shapes and scale' {
    It 'masks scalar types a Graph SDK export carries but the sample does not' {
        $e = Import-CapExportJson -Path (Join-Path $script:Repo 'samples/sample-export-enriched.json')
        $e.policies[0].createdDateTime = [datetimeoffset]::UtcNow
        $e.policies[0].objectGuid = [guid]::NewGuid()
        $e.policies[0].dayEnum = [System.DayOfWeek]::Monday
        $e.policies[0].span = [timespan]::FromMinutes(5)
        $e.policies[0].link = [uri]'https://contoso.example/x'
        $dict = New-CapNameDictionary -Export $e -NameMap $e['nameMap'] -Snapshot 'x'
        # Before the fix this threw: $node.PSObject.Properties.Count does not
        # exist on a scalar under Set-StrictMode -Version Latest.
        { ConvertTo-CapSafeObject -InputObject $e -Dictionary $dict } | Should -Not -Throw
    }

    It 'leaves scalar values structurally intact' {
        $e = Import-CapExportJson -Path (Join-Path $script:Repo 'samples/sample-export-enriched.json')
        $e.policies[0].objectGuid = [guid]::NewGuid()
        $e.policies[0].dayEnum = [System.DayOfWeek]::Monday
        $dict = New-CapNameDictionary -Export $e -NameMap $e['nameMap'] -Snapshot 'x'
        $safe = ConvertTo-CapSafeObject -InputObject $e -Dictionary $dict
        $safe.policies[0].objectGuid | Should -BeOfType [guid]
        "$($safe.policies[0].dayEnum)" | Should -Be 'Monday'
    }

    It 'masks a tenant-sized dictionary in seconds, not minutes' {
        $e = Import-CapExportJson -Path (Join-Path $script:Repo 'samples/sample-export-enriched.json')
        $nm = @{}
        foreach ($k in $e['nameMap'].Keys) { $nm["$k"] = $e['nameMap'][$k] }
        1..8000 | ForEach-Object { $nm["$([guid]::NewGuid())"] = "Synthetic Person $_ Contoso" }
        $dict = New-CapNameDictionary -Export $e -NameMap $nm -Snapshot 'x'
        $doc = @{ findings = @(1..500 | ForEach-Object {
                    @{ id = "f$_"; text = "Policy CA001 - Require MFA for all users excludes Break-glass exclusions; Synthetic Person $_ Contoso affected." } }) }

        $sw = [Diagnostics.Stopwatch]::StartNew()
        $safe = ConvertTo-CapSafeObject -InputObject $doc -Dictionary $dict
        $sw.Stop()

        # A per-name scan made this quadratic (~5 min for a real findings file).
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 60
        @(Test-CapNameLeak -Dictionary $dict -InputObject $safe).Count | Should -Be 0
        $safe.findings[0].text | Should -Not -BeLike '*CA001*'
        $safe.findings[0].text | Should -Not -BeLike '*Synthetic Person 1 Contoso*'
    }
}

Describe 'End-to-end safe bundle' {
    BeforeAll {
        $script:Out = Join-Path ([IO.Path]::GetTempPath()) "cap-safe-$([guid]::NewGuid())"
        & (Join-Path $script:Repo 'scripts/Invoke-CapVisualizer.ps1') `
            -FromJson (Join-Path $script:Repo 'samples/sample-export-enriched.json') `
            -OutputRoot $script:Out -NoOpen -NoTranscript *>$null
        $script:Snap = @(Get-ChildItem -LiteralPath $script:Out -Directory)[0].FullName
    }

    AfterAll {
        if ($script:Out -and (Test-Path -LiteralPath $script:Out)) { Remove-Item -LiteralPath $script:Out -Recurse -Force }
    }

    It 'writes a name-free export and a separate dictionary' {
        Test-Path (Join-Path $script:Snap 'raw/export.json') | Should -BeTrue
        Test-Path (Join-Path $script:Snap 'raw/names.json') | Should -BeTrue
        $raw = Get-Content (Join-Path $script:Snap 'raw/export.json') -Raw
        $raw | Should -Not -BeLike '*Break Glass Admin*'
        $raw | Should -Not -BeLike '*@contoso.com*'
    }

    It 'marks the export as schema 3.0 with names split out' {
        $doc = Get-Content (Join-Path $script:Snap 'raw/export.json') -Raw | ConvertFrom-Json -Depth 30 -AsHashtable
        $doc.metadata.schemaVersion | Should -Be '3.0'
        $doc.Contains('nameMap') | Should -BeFalse
    }

    It 'keeps names in the local report and HTML' {
        (Get-Content (Join-Path $script:Snap 'visual/index.html') -Raw) | Should -BeLike '*Break Glass Admin*'
        (Get-Content (Join-Path $script:Snap 'report/policies.json') -Raw) | Should -BeLike '*CA001*'
    }

    It 'produces a safe bundle that passes the leak test' {
        & (Join-Path $script:Repo 'scripts/Export-CapSafeBundle.ps1') -SnapshotPath $script:Snap -Force *>$null
        Test-Path (Join-Path $script:Snap 'safe/raw/export.json') | Should -BeTrue
        Test-Path (Join-Path $script:Snap 'safe/raw/names.json') | Should -BeFalse
    }

    It 'pseudonymizes the bundle by default and records the aliases locally' {
        $safe = Get-Content (Join-Path $script:Snap 'safe/raw/export.json') -Raw | ConvertFrom-Json -Depth 30 -AsHashtable
        $safe.metadata.tenantId | Should -Be 'TENANT-001'
        $dict = Get-Content (Join-Path $script:Snap 'raw/names.json') -Raw | ConvertFrom-Json -Depth 20 -AsHashtable
        $dict.pseudonymized | Should -BeTrue
        @($dict.idAliases.Values) | Should -Contain 'POL-001'
    }

    It 're-hydrates an alias from the safe bundle back to the real name' {
        $md = Join-Path $script:Snap 'ai-alias.md'
        'Policy POL-001 excludes too much.' | Set-Content -LiteralPath $md -Encoding utf8
        & (Join-Path $script:Repo 'scripts/Restore-CapNames.ps1') -Path $md `
            -Names (Join-Path $script:Snap 'raw/names.json') -InPlace *>$null
        (Get-Content -LiteralPath $md -Raw) | Should -BeLike '*CA001*'
    }

    It 're-hydrates an AI report through the same dictionary' {
        $md = Join-Path $script:Snap 'ai-report.md'
        'Finding affects 22222222-2222-2222-2222-222222222222.' | Set-Content -LiteralPath $md -Encoding utf8
        & (Join-Path $script:Repo 'scripts/Restore-CapNames.ps1') -Path $md `
            -Names (Join-Path $script:Snap 'raw/names.json') -InPlace *>$null
        (Get-Content -LiteralPath $md -Raw) | Should -BeLike '*Break Glass Admin*'
    }

    It 'refuses a dictionary from a different snapshot' {
        $md = Join-Path $script:Snap 'ai-report2.md'
        'Finding affects 22222222-2222-2222-2222-222222222222.' | Set-Content -LiteralPath $md -Encoding utf8
        { & (Join-Path $script:Repo 'scripts/Restore-CapNames.ps1') -Path $md `
            -Names (Join-Path $script:Snap 'raw/names.json') -Snapshot '19990101-000000' -InPlace } |
            Should -Throw
    }

    It 'renders ids instead of names when the dictionary is withheld' {
        $lonely = Join-Path ([IO.Path]::GetTempPath()) "cap-nodict-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Force -Path $lonely | Out-Null
        Copy-Item (Join-Path $script:Snap 'raw/export.json') (Join-Path $lonely 'export.json')
        $out2 = Join-Path $lonely 'out'
        & (Join-Path $script:Repo 'scripts/Invoke-CapVisualizer.ps1') -FromJson (Join-Path $lonely 'export.json') `
            -OutputRoot $out2 -NoOpen -NoTranscript *>$null
        $snap2 = @(Get-ChildItem -LiteralPath $out2 -Directory)[0].FullName
        $html = Get-Content (Join-Path $snap2 'visual/index.html') -Raw
        $html | Should -Not -BeLike '*Break Glass Admin*'
        Remove-Item -LiteralPath $lonely -Recurse -Force
    }
}
