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
        # The name is present, but only as a Microsoft-global constant keyed by
        # its own role template id. What must never happen is a role name being
        # minted an alias token as though it were tenant data.
        $entry = @($script:Dict.entries.Values | Where-Object { $_.name -eq 'Global Administrator' })[0]
        $entry | Should -Not -BeNullOrEmpty
        $entry.token | Should -Be '62e90394-69f5-4237-9190-012177145e10'
        $entry.global | Should -BeTrue
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

Describe 'Get-CapWellKnownIdSet' {
    It 'treats a non-privileged built-in role template id as well-known' {
        $set = Get-CapWellKnownIdSet
        # Directory Synchronization Accounts: a built-in Microsoft role that is
        # absent from privileged-roles.json but is still a global constant.
        $set.ids.Contains('d29b2b05-8046-44ba-8758-1e26182fcf32') | Should -BeTrue
    }

    It 'still recognises the Global Administrator template id' {
        (Get-CapWellKnownIdSet).ids.Contains('62e90394-69f5-4237-9190-012177145e10') | Should -BeTrue
    }

    It 'does not treat a random tenant guid as well-known' {
        (Get-CapWellKnownIdSet).ids.Contains('71b9455a-3054-4ef8-970b-598d42dc6a34') | Should -BeFalse
    }

    It 'treats a first-party app id from the reference pack as well-known' {
        # Device Registration Service: a public Microsoft app id that CA policies
        # reference. It was missing before, so reviews citing it restored as a
        # bare guid.
        (Get-CapWellKnownIdSet).ids.Contains('01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9') | Should -BeTrue
    }
}

Describe 'Microsoft global constants in the dictionary' {
    It 'seeds every first-party app id keyed by its own id' {
        $dict = New-CapNameDictionary -Export @{ policies = @() } -Snapshot 'test'
        foreach ($id in (Get-CapFirstPartyAppMap).Keys) {
            $dict.entries.Contains($id) | Should -BeTrue -Because "$id must be restorable in any tenant"
            $dict.entries[$id].name | Should -Not -BeNullOrEmpty
        }
    }

    It 'names the Device Registration Service even when the tenant never referenced it' {
        $dict = New-CapNameDictionary -Export @{ policies = @() } -Snapshot 'test'
        $dict.entries['01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9'].name | Should -Be 'Device Registration Service'
    }

    It 'does not mint an alias token for a first-party app id' {
        # The old behaviour aliased well-known ids to OBJECT-nnn, which no
        # restore could resolve back to the id cited in a review.
        $export = @{ policies = @() }
        $map = @{ '797f4846-ba00-4fd7-ba43-dac1f8f63013' = 'Windows Azure Service Management API' }
        $dict = New-CapNameDictionary -Export $export -NameMap $map -Snapshot 'test'
        $dict.entries['797f4846-ba00-4fd7-ba43-dac1f8f63013'].token | Should -Be '797f4846-ba00-4fd7-ba43-dac1f8f63013'
        @($dict.entries.Values | Where-Object { $_.name -eq 'Windows Azure Service Management API' }).Count | Should -Be 1
    }

    It 'keeps the shared pack as the single source for both app maps' {
        $common = Get-CapWellKnownAppMap
        $names = Get-CapFirstPartyAppMap
        $common.Count | Should -Be $names.Count
        foreach ($id in $names.Keys) { $common[$id] | Should -Be $names[$id] }
    }

    It 'seeds every built-in role template id keyed by its own id' {
        $dict = New-CapNameDictionary -Export @{ policies = @() } -Snapshot 'test'
        foreach ($id in (Get-CapBuiltinRoleMap).Keys) {
            $dict.entries.Contains($id) | Should -BeTrue -Because "$id must be restorable in any tenant"
            $dict.entries[$id].type | Should -Be 'msrole'
        }
    }

    It 'names built-in roles the tenant never referenced' {
        # Both ids were observed rendering as bare guids in a delivered report.
        $dict = New-CapNameDictionary -Export @{ policies = @() } -Snapshot 'test'
        $dict.entries['62e90394-69f5-4237-9190-012177145e10'].name | Should -Be 'Global Administrator'
        $dict.entries['d29b2b05-8046-44ba-8758-1e26182fcf32'].name | Should -Be 'Directory Synchronization Accounts'
    }

    It 'restores a role template id cited in a review' {
        $dict = New-CapNameDictionary -Export @{ policies = @() } -Snapshot 'test'
        $text = 'Exclusion applies to 62e90394-69f5-4237-9190-012177145e10 across 8 policies.'
        Restore-CapNameText -Text $text -Dictionary $dict |
            Should -Be 'Exclusion applies to Global Administrator across 8 policies.'
    }

    It 'merges role constants into a dictionary saved before the seed existed' {
        $legacy = @{
            kind          = 'nameDictionary'
            schemaVersion = '1.0'
            snapshot      = 'legacy'
            count         = 1
            entries       = @{ 'OBJECT-001' = @{ token = 'OBJECT-001'; type = 'object'; id = 'x'; name = 'Legacy' } }
        }
        $path = Join-Path ([System.IO.Path]::GetTempPath()) "cap-legacy-$([guid]::NewGuid()).json"
        try {
            $legacy | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
            $loaded = Import-CapNameDictionary -Path $path
            $loaded.entries['62e90394-69f5-4237-9190-012177145e10'].name | Should -Be 'Global Administrator'
            # The binding fingerprint is built from count, so the merge must not move it.
            $loaded.count | Should -Be 1
        }
        finally { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Objects that share a display name' {
    BeforeAll {
        $script:DupMap = @{
            '03efba08-f7c4-4079-87f0-610f3efe6594' = 'VPN and SAW IP Ranges'
            '0c0dd17a-f0e7-4fe9-a557-a6fa9608d742' = 'VPN and SAW IP Ranges'
            '1a17052b-7d68-45f5-adb1-0aeedb75ee10' = 'Israel Offices'
        }
    }

    It 'gives every distinct id an entry so a review can be restored' {
        # The name dedupe used to drop the second object outright, leaving its id
        # with nothing to restore from. It read as a raw guid in the deliverable.
        $dict = New-CapNameDictionary -Export @{ policies = @() } -NameMap $script:DupMap -Snapshot 'test'
        foreach ($id in $script:DupMap.Keys) {
            $dict.entries.Contains($id) | Should -BeTrue -Because "$id must resolve to a name"
            $dict.entries[$id].name | Should -Be $script:DupMap[$id]
        }
    }

    It 'marks the duplicate so the two are distinguishable' {
        $dict = New-CapNameDictionary -Export @{ policies = @() } -NameMap $script:DupMap -Snapshot 'test'
        $dupes = @($dict.entries.Values | Where-Object { $_.Contains('duplicateOf') })
        $dupes.Count | Should -Be 1
        $dupes[0].id | Should -Be '0c0dd17a-f0e7-4fe9-a557-a6fa9608d742'
        $dupes[0].duplicateOf | Should -Be '03efba08-f7c4-4079-87f0-610f3efe6594'
    }

    It 'picks the same masking token on every run' {
        # $NameMap is an unordered hashtable, so without an explicit sort the
        # winning token varied between runs on identical input.
        $tokens = 1..5 | ForEach-Object {
            $d = New-CapNameDictionary -Export @{ policies = @() } -NameMap $script:DupMap -Snapshot 'test'
            @($d.entries.Values | Where-Object { $_.name -eq 'VPN and SAW IP Ranges' -and -not $_.Contains('duplicateOf') })[0].token
        }
        @($tokens | Sort-Object -Unique).Count | Should -Be 1
    }

    It 'still masks the shared name to a single token' {
        # Masking is name driven and cannot distinguish the two, so it must keep
        # collapsing them. The extra restore entries must not introduce a second
        # replacement for the same string.
        $dict = New-CapNameDictionary -Export @{ policies = @() } -NameMap $script:DupMap -Snapshot 'test'
        $safe = ConvertTo-CapSafeObject -Dictionary $dict -InputObject @{
            a = 'Scoped to VPN and SAW IP Ranges only.'
            b = 'Also VPN and SAW IP Ranges.'
        }
        $safe.a | Should -Not -Match 'VPN and SAW IP Ranges'
        $safe.b | Should -Not -Match 'VPN and SAW IP Ranges'
        $tokens = @($safe.a, $safe.b) | ForEach-Object {
            [regex]::Match($_, '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}').Value
        }
        @($tokens | Sort-Object -Unique).Count | Should -Be 1
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

    It 'reports the surrounding context for a violation' {
        # Without context an operator cannot tell a real leak from a collision.
        $planted = @{ note = 'Reviewed by Break Glass Admin last week' }
        $leak = @(Test-CapNameLeak -Dictionary $script:Dict -InputObject $planted |
            Where-Object { $_.kind -eq 'name' })[0]
        $leak.context | Should -Not -BeNullOrEmpty
        $leak.context | Should -BeLike '*Break Glass Admin*'
    }

    Context 'short names colliding with Microsoft constants' {
        BeforeAll {
            # A real tenant names service principals things like "Bill", "box",
            # "User" and "MDI". Substring matching then flagged Microsoft's own
            # constants and every safe bundle was rejected on false positives,
            # which silently removed the "Export safely" button.
            #
            # "User" stays in this fixture on purpose: it must not be flagged
            # inside "User.Read.All", and it is also schema vocabulary, so it is
            # never masked and never reported (see the schema vocabulary tests).
            $script:ShortDict = @{
                kind = 'nameDictionary'; snapshot = 's'; count = 4
                entries = [ordered]@{
                    'OBJ-1' = @{ name = 'Bill'; type = 'object' }
                    'OBJ-2' = @{ name = 'box';  type = 'object' }
                    'OBJ-3' = @{ name = 'User'; type = 'object' }
                    'OBJ-4' = @{ name = 'mDi';  type = 'object' }
                }
                idAliases = @{}; pseudonymized = $false
            }
        }

        It 'does not flag a short name inside a Microsoft constant' {
            foreach ($constant in @(
                '"roleName": "Billing Administrator"'
                '"scope": "MailboxSettings.ReadWrite"'
                '"scope": "User.Read.All"'
                '"a": "urn:user:registerdevice"'
                '"p": "OnPremDirectorySynchronization.Read"'
            )) {
                @(Test-CapNameLeak -Dictionary $script:ShortDict -InputObject @{ x = $constant }).Count |
                    Should -Be 0 -Because "'$constant' is a Microsoft constant, not tenant data"
            }
        }

        It 'still flags a short name that appears as a standalone value' {
            foreach ($leak in @(
                '"owner": "Bill"'
                '"n": "box"'
                '"n": "mDi"'
                'policy excludes Bill from MFA'
                'escalate to Bill, then review'
                'contact (Bill) urgently'
            )) {
                @(Test-CapNameLeak -Dictionary $script:ShortDict -InputObject @{ x = $leak }).Count |
                    Should -BeGreaterThan 0 -Because "'$leak' is a genuine leak"
            }
        }

        It 'still matches a long name inside a larger word' {
            # Names at or above the masking threshold keep unbounded matching,
            # because the masker substitutes them anywhere in free text.
            $d = @{ kind='nameDictionary'; snapshot='s'; count=1
                    entries=[ordered]@{ 'OBJ-9' = @{ name='Contoso'; type='object' } }
                    idAliases=@{}; pseudonymized=$false }
            @(Test-CapNameLeak -Dictionary $d -InputObject @{ x = 'host CONTOSOFIN07 reported' }).Count |
                Should -BeGreaterThan 0
        }
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

    It 'detects tokens past 999, where aliases grow beyond three digits' {
        # Aliases are minted with {0:d3}, a *minimum* width, so object 1000 of a
        # class becomes USER-1000. A \d{3} detector missed those entirely, and
        # every enterprise tenant passes 999 users.
        foreach ($token in 'USER-999', 'USER-1000', 'USER-1234', 'USER-99999') {
            @(Get-CapUnresolvedTokens -Text "report mentions $token here") |
                Should -Contain $token
        }
    }

    It 'detects every alias prefix either minting site can produce' {
        # _NextAlias emits the long forms, _CapBuildIdAliases the short ones.
        # The detector previously knew only the short list, so OBJECT-, POLICY-,
        # LOCATION-, AUTHSTRENGTH- and AUTHCONTEXT- tokens were never reported.
        $types = @(Get-CapAliasTypes)
        $types.Count | Should -BeGreaterThan 10
        foreach ($type in $types) {
            @(Get-CapUnresolvedTokens -Text "value $type-001 appears") |
                Should -Contain "$type-001"
        }
    }

    It 'covers every prefix the minting sites actually emit' {
        # Guards the drift itself: if a new type is minted without being added
        # to CapAliasTypes, its tokens become undetectable and this fails.
        $types = @(Get-CapAliasTypes)
        foreach ($minted in 'OBJ', 'POL', 'LOC', 'STR', 'CTX', 'TENANT',
                            'OBJECT', 'POLICY', 'LOCATION', 'AUTHSTRENGTH',
                            'AUTHCONTEXT', 'IPRANGE', 'COUNTRY', 'ACCOUNT',
                            'DESCRIPTION', 'DEVICERULE', 'UPN') {
            $types | Should -Contain $minted
        }
    }

    It 'does not match short numbers, unknown prefixes or embedded text' {
        foreach ($noise in 'USER-12', 'ABC-001', 'USER-1000x') {
            @(Get-CapUnresolvedTokens -Text "text $noise here").Count | Should -Be 0
        }
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

Describe 'Safe review bundle' {
    BeforeAll {
        $script:BundleDict = New-CapNameDictionary -Export $script:Export -NameMap $script:NameMap -Snapshot '20260101-000000'
        $script:BundleSafe = ConvertTo-CapSafeObject -InputObject $script:Export -Dictionary $script:BundleDict
        $script:Bundle = New-CapSafeReviewBundle -SafeExport $script:BundleSafe -Dictionary $script:BundleDict `
            -Analysis ([ordered]@{ findings = @{ findings = @(@{ message = 'Break Glass Admin is excluded' }) } }) `
            -Snapshot '20260101-000000'
        $script:BundleJson = $script:Bundle | ConvertTo-Json -Depth 30
    }

    It 'merges export and analysis into one document' {
        $script:Bundle.Contains('policies') | Should -BeTrue
        $script:Bundle.Contains('findings') | Should -BeTrue
        $script:Bundle.Contains('metadata') | Should -BeTrue
    }

    It 'declares itself so a consumer knows what it is holding' {
        $script:Bundle['safeBundle']['kind'] | Should -Be 'safeReviewBundle'
        $script:Bundle['safeBundle']['pseudonymized'] | Should -BeTrue
        $script:Bundle['safeBundle']['snapshot'] | Should -Be '20260101-000000'
    }

    It 'aliases ids so nothing tenant-correlatable ships' {
        # Well-known Microsoft app and role ids are global constants and stay
        # readable on purpose; the leak test knows the difference.
        @(Test-CapNameLeak -Dictionary $script:BundleDict -InputObject $script:Bundle -RequirePseudonymized).Count |
            Should -Be 0
        $script:Bundle['policies'][0]['id'] | Should -Match '^POL-\d+$'
        $script:BundleJson | Should -BeLike '*62e90394-69f5-4237-9190-012177145e10*'
    }

    It 'masks names that analysis text carried in' {
        $script:BundleJson | Should -Not -BeLike '*Break Glass Admin*'
    }

    It 'leaves the dictionary able to reverse the aliases it introduced' {
        $script:BundleDict['idAliases'].Count | Should -BeGreaterThan 0
    }

    It 'refuses to return a document that still contains a name' {
        $d = New-CapNameDictionary -Export $script:Export -NameMap $script:NameMap -Snapshot 's'
        $planted = ConvertTo-CapSafeObject -InputObject $script:Export -Dictionary $d
        # Bypass masking: inject after the safe copy is made, as a regression
        # would, and confirm the bundle refuses rather than returning it.
        Mock -CommandName ConvertTo-CapSafeObject -MockWith {
            @{ metadata = @{ leaked = 'Break Glass Admin' } }
        } -ModuleName CapNames
        { New-CapSafeReviewBundle -SafeExport $planted -Dictionary $d -Snapshot 's' } | Should -Throw '*leak*'
    }
}

Describe 'Export safely button' {
    BeforeAll {
        $script:BtnRoot = Join-Path ([IO.Path]::GetTempPath()) "cap-btn-$([guid]::NewGuid())"
        & (Join-Path $script:Repo 'scripts/Invoke-CapVisualizer.ps1') `
            -FromJson (Join-Path $script:Repo 'samples/sample-export-enriched.json') `
            -OutputRoot $script:BtnRoot -NoOpen -NoTranscript *>$null
        $script:BtnSnap = @(Get-ChildItem -LiteralPath $script:BtnRoot -Directory)[0].FullName
        $script:BtnHtml = Get-Content (Join-Path $script:BtnSnap 'visual/index.html') -Raw
        if ($script:BtnHtml -match '(?s)window\.__CAP_SAFE__ = (.*?);\r?\nwindow\.__CAP_SNAPSHOT__') {
            $script:BtnPayload = $Matches[1] | ConvertFrom-Json -Depth 30 -AsHashtable
        }
    }

    AfterAll {
        if ($script:BtnRoot -and (Test-Path -LiteralPath $script:BtnRoot)) {
            Remove-Item -LiteralPath $script:BtnRoot -Recurse -Force
        }
    }

    It 'embeds a payload for the button to hand out' {
        $script:BtnHtml | Should -BeLike '*id="safeExportBtn"*'
        $script:BtnPayload | Should -Not -BeNullOrEmpty
        $script:BtnPayload['capExport']['kind'] | Should -Be 'policyOnlyExport'
    }

    It 'exports the Conditional Access policies and what they reference, and nothing else' {
        # An allowlist, so the assertion is on what is absent. Enrichment is
        # user inventory rather than Conditional Access, and it is 98% of the
        # bytes of a real export.
        # The analysis sections are here on purpose: the deterministic engine
        # already established what is true, and dropping it forced the reviewer
        # to re-derive it and disagree with the engine's own numbers.
        $allowed = @('capExport', 'policies', 'authenticationStrengths', 'authenticationContexts',
                     'consolidation', 'compliance', 'audit', 'findings', 'analysisExposure')
        foreach ($k in @($script:BtnPayload.Keys)) {
            $allowed | Should -Contain $k -Because "$k is not on the allowlist"
        }
        @($script:BtnPayload['policies']).Count | Should -BeGreaterThan 0
        foreach ($k in 'enrichment', 'nameMap', 'metadata') {
            $script:BtnPayload.Contains($k) | Should -BeFalse -Because "$k is not a policy definition"
        }
    }

    It 'keeps authentication strengths reviewable without naming them' {
        # A policy gated on a custom auth strength is unreviewable without the
        # strength definition: there is no way to tell phishing-resistant from
        # SMS. allowedCombinations is Microsoft's own method vocabulary, so it
        # conveys strength without conveying tenant identity.
        $src = @{
            metadata                = @{ generatedUtc = 'x' }
            policies                = @()
            authenticationStrengths = @(
                @{ id = 'str-1'; displayName = 'CONTOSO phishing-resistant'; description = 'internal note'
                   policyType = 'custom'; allowedCombinations = @('fido2', 'x509CertificateMultiFactor') }
            )
        }
        $out = New-CapPolicyOnlyExport -Export $src -Snapshot 'x'
        $s = @($out.authenticationStrengths)[0]
        $s.Contains('displayName')         | Should -BeFalse
        $s.Contains('description')         | Should -BeFalse
        $s.Contains('allowedCombinations') | Should -BeTrue
        $s['allowedCombinations']          | Should -Contain 'fido2'
        $s['policyType']                   | Should -Be 'custom'
    }

    It 'withholds named locations entirely, and says so' {
        # Deliberately not summarised. A range count or a cidr prefix is another
        # field to reason about in a document whose strength is that it starts
        # empty, and it invites judgements a reviewer cannot verify: a /24 reads
        # as overly broad until you know it is a datacentre egress block.
        $src = @{
            metadata       = @{ generatedUtc = 'x' }
            policies       = @(
                @{ id = 'p-1'; conditions = @{ locations = @{ includeLocations = 'All'; excludeLocations = @('loc-1') } } }
            )
            namedLocations = @(
                @{ id = 'loc-1'; displayName = 'CONTOSO HQ'; isTrusted = $true
                   ipRanges = @(@{ cidrAddress = '203.0.113.0/24' }, @{ cidrAddress = '198.51.100.0/24' }) }
            )
        }
        $out  = New-CapPolicyOnlyExport -Export $src -Snapshot 'x'
        $json = $out | ConvertTo-Json -Depth 20

        $out.Contains('namedLocations') | Should -BeFalse
        $json | Should -Not -BeLike '*203.0.113*'
        $json | Should -Not -BeLike '*CONTOSO HQ*'
        $json | Should -Not -BeLike '*ipRangeCount*'
        $json | Should -Not -BeLike '*isTrusted*'

        # The reference itself stays. Every location finding worth making is
        # referential and needs only the id, and the requester restores the real
        # name locally with Restore-CapNames.ps1.
        @($out.policies)[0].conditions.locations.excludeLocations | Should -Contain 'loc-1'
    }

    It 'tells the reviewer that a withheld location is not a passed location' {
        # Absence reads as cleanliness unless it is declared: a policy with a
        # location exclusion looks tidier than one without, because there is
        # nothing left to criticise.
        $out = New-CapPolicyOnlyExport -Export @{ metadata = @{ generatedUtc = 'x' }; policies = @() } -Snapshot 'x'
        $hdr = $out['capExport']
        # No analysis was supplied, so this is still the 1.2 shape.
        $hdr['schemaVersion'] | Should -Be '1.2'
        $hdr['notAssessable'] | Should -Contain 'namedLocations'
        ($hdr['reviewerGuidance'] -join ' ') | Should -BeLike '*requires local verification*'
        # The round trip only works if ids come back verbatim.
        ($hdr['reviewerGuidance'] -join ' ') | Should -BeLike '*verbatim*'
    }

    It 'keeps single-item collections as arrays' {
        # PowerShell unrolls a one-item array, so a rebuilt object graph used to
        # serialize allowedCombinations ["fido2"] as the bare string "fido2".
        # A consumer iterating it then walked the string character by character,
        # which is how a delivered review described a FIDO2-only strength as
        # "fragmented single characters". excludeGroups had the same fault, so
        # this changed how the scope of a policy read.
        $src = @{
            metadata = @{ generatedUtc = 'x' }
            policies = @(
                @{ id = 'p-1'
                   # Scalars, because that is what the upstream masked export
                   # actually contains once a one-item array has been unrolled.
                   conditions = @{
                       users = @{ includeUsers = 'All'; excludeGroups = 'g-1' }
                       clientAppTypes = 'all'
                   }
                   grantControls = @{ builtInControls = 'mfa' }
                }
            )
            authenticationStrengths = @(
                @{ id = 's-1'; displayName = 'Phishing resistant'; allowedCombinations = 'fido2' }
            )
        }
        $out = New-CapPolicyOnlyExport -Export $src -Snapshot 'x'
        $doc = $out | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20 -AsHashtable

        foreach ($pair in @(
            @{ node = $doc.policies[0].conditions.users; key = 'excludeGroups'; value = 'g-1' }
            @{ node = $doc.policies[0].conditions.users; key = 'includeUsers';  value = 'All' }
            @{ node = $doc.policies[0].conditions;       key = 'clientAppTypes'; value = 'all' }
            @{ node = $doc.policies[0].grantControls;    key = 'builtInControls'; value = 'mfa' }
            @{ node = $doc.authenticationStrengths[0];   key = 'allowedCombinations'; value = 'fido2' }
        )) {
            $actual = $pair.node[$pair.key]
            $actual -is [string] | Should -BeFalse -Because "$($pair.key) is a collection in the Graph schema"
            @($actual).Count | Should -Be 1
            @($actual)[0] | Should -Be $pair.value
        }
    }

    It 'drops odata context urls but keeps odata type' {
        $src = @{
            metadata = @{ generatedUtc = 'x' }
            policies = @(
                [ordered]@{
                    id = 'p-1'
                    'grantControls@odata.context' = 'https://graph.microsoft.com/beta/$metadata#x'
                    grantControls = [ordered]@{ '@odata.type' = '#microsoft.graph.conditionalAccessGrantControls'; operator = 'OR' }
                }
            )
        }
        $json = New-CapPolicyOnlyExport -Export $src -Snapshot 'x' | ConvertTo-Json -Depth 20
        $json | Should -Not -BeLike '*@odata.context*'
        $json | Should -BeLike '*@odata.type*'
    }

    It 'hands out no name, even though the page itself shows names' {
        $dict = Import-CapNameDictionary -Path (Join-Path $script:BtnSnap 'raw/names.json')
        @(Test-CapNameLeak -Dictionary $dict -InputObject $script:BtnPayload).Count | Should -Be 0
    }

    It 'keeps every policy id a guid rather than a display name' {
        # Regression: re-hydration is a blind text substitution, so building the
        # payload from the re-hydrated export put the display name into the id
        # field and shipped real names.
        foreach ($p in $script:BtnPayload['policies']) {
            "$($p.id)" | Should -Match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
            $p.Contains('displayName') | Should -BeFalse
        }
    }

    It 'carries no tenant id or operator account' {
        $raw = $script:BtnPayload | ConvertTo-Json -Depth 30
        $raw | Should -Not -BeLike '*tenantId*'
        $raw | Should -Not -BeLike '*"account"*'
        $raw | Should -Not -BeLike '*"scopes"*'
    }

    It 'names the file after the snapshot so exports stay distinguishable' {
        $script:BtnHtml | Should -BeLike '*cap-safe-review-*'
        $script:BtnHtml | Should -BeLike "*__CAP_SNAPSHOT__ = `"$(Split-Path -Leaf $script:BtnSnap)`"*"
    }

    It 'ships guids and no names even when re-rendering a masked export with its dictionary' {
        # The reported bug: re-running -FromJson against raw/export.json finds
        # raw/names.json beside it and re-hydrates, which put real display names
        # and user principal names into the shared file. The payload must be
        # built from the on-disk masked export, not the re-hydrated copy.
        $root = Join-Path ([IO.Path]::GetTempPath()) "cap-rehydrate-$([guid]::NewGuid())"
        try {
            & (Join-Path $script:Repo 'scripts/Invoke-CapVisualizer.ps1') `
                -FromJson (Join-Path $script:BtnSnap 'raw/export.json') `
                -OutputRoot $root -NoOpen -NoTranscript *>$null
            $snap = @(Get-ChildItem -LiteralPath $root -Directory)[0].FullName
            $html = Get-Content (Join-Path $snap 'visual/index.html') -Raw

            # The local report must still show real names.
            $html | Should -BeLike '*Require MFA for all users*'

            $html -match '(?s)window\.__CAP_SAFE__ = (.*?);\r?\nwindow\.__CAP_SNAPSHOT__' | Should -BeTrue
            $payload = $Matches[1] | ConvertFrom-Json -Depth 30 -AsHashtable
            $shared = $payload | ConvertTo-Json -Depth 30

            # ... while the shared payload must not.
            $shared | Should -Not -BeLike '*Require MFA for all users*'
            foreach ($p in $payload['policies']) {
                "$($p.id)" | Should -Match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
            }
            $dict = Import-CapNameDictionary -Path (Join-Path $script:BtnSnap 'raw/names.json')
            @(Test-CapNameLeak -Dictionary $dict -InputObject $payload).Count | Should -Be 0
        }
        finally {
            if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
        }
    }
}

Describe 'Report id round trip' {
    BeforeAll {
        # A dictionary small enough to reason about, shaped exactly like a real
        # names.json so the test exercises the production import path.
        $script:RtIds = @{
            group = '71b9455a-3054-4ef8-970b-598d42dc6a34'
            user  = '5b33e4b3-f9dd-47f9-a417-6882bf4b84c3'
            pol   = '007dce69-1c4f-4b0e-9c8a-3f2d5a6b7c8d'
        }
        $entries = @{}
        $entries[$script:RtIds.group] = @{ token = $script:RtIds.group; type = 'object'; id = $script:RtIds.group; name = 'MFA_Demo_Exclusion' }
        $entries[$script:RtIds.user]  = @{ token = $script:RtIds.user;  type = 'object'; id = $script:RtIds.user;  name = 'breakglass@contoso.com' }
        $entries[$script:RtIds.pol]   = @{ token = $script:RtIds.pol;   type = 'object'; id = $script:RtIds.pol;   name = 'MFA baseline' }

        $script:RtDictPath = Join-Path ([IO.Path]::GetTempPath()) "cap-rt-names-$([guid]::NewGuid()).json"
        @{
            tool = 'CAPVisualizer'; kind = 'nameDictionary'; schemaVersion = '1.0'
            pseudonymized = $true; count = $entries.Count; entries = $entries
        } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $script:RtDictPath -Encoding utf8

        $script:RtRestore = Join-Path $script:Repo 'scripts/Restore-CapNames.ps1'
    }

    AfterAll {
        if ($script:RtDictPath -and (Test-Path -LiteralPath $script:RtDictPath)) {
            Remove-Item -LiteralPath $script:RtDictPath -Force
        }
    }

    It 'leaves no tenant id behind when every id is written in full' {
        $report = Join-Path ([IO.Path]::GetTempPath()) "cap-rt-good-$([guid]::NewGuid()).md"
        try {
            # 62e90394 is the Global Administrator role template, a Microsoft
            # public constant. It is expected to survive as a raw id.
            @(
                "# Review"
                "Remove $($script:RtIds.group) and $($script:RtIds.user) from $($script:RtIds.pol)."
                "Holders of 62e90394-69f5-4237-9190-012177145e10 are in scope."
            ) -join "`n" | Set-Content -LiteralPath $report -Encoding utf8

            & $script:RtRestore -Path $report -Names $script:RtDictPath *>$null
            $LASTEXITCODE | Should -Be 0

            $named = [IO.Path]::ChangeExtension($report, $null) + 'named.md'
            $named = $report -replace '\.md$', '.named.md'
            $text = Get-Content -LiteralPath $named -Raw

            $text | Should -BeLike '*MFA_Demo_Exclusion*'
            $text | Should -BeLike '*breakglass@contoso.com*'
            $text | Should -BeLike '*MFA baseline*'
            @(Get-CapUnresolvedIds -Text $text).Count | Should -Be 0
            @(Get-CapTruncatedIds -Text $text).Count | Should -Be 0
            Remove-Item -LiteralPath $named -Force -ErrorAction SilentlyContinue
        }
        finally { Remove-Item -LiteralPath $report -Force -ErrorAction SilentlyContinue }
    }

    It 'recovers abbreviated ids rather than leaving them dead' {
        $report = Join-Path ([IO.Path]::GetTempPath()) "cap-rt-trunc-$([guid]::NewGuid()).md"
        try {
            "Remove 71b9455a-... from the baseline ``007dce69-...``." |
                Set-Content -LiteralPath $report -Encoding utf8

            & $script:RtRestore -Path $report -Names $script:RtDictPath *>$null
            $LASTEXITCODE | Should -Be 0

            $named = $report -replace '\.md$', '.named.md'
            $text = Get-Content -LiteralPath $named -Raw
            $text | Should -BeLike '*MFA_Demo_Exclusion*'
            $text | Should -BeLike '*MFA baseline*'
            @(Get-CapTruncatedIds -Text $text).Count | Should -Be 0
            Remove-Item -LiteralPath $named -Force -ErrorAction SilentlyContinue
        }
        finally { Remove-Item -LiteralPath $report -Force -ErrorAction SilentlyContinue }
    }

    It 'fails the run when an id cannot be resolved' {
        $report = Join-Path ([IO.Path]::GetTempPath()) "cap-rt-bad-$([guid]::NewGuid()).md"
        try {
            "Audit d29b2b05-8046-44ba-8758-1e26182fcf99 before the change." |
                Set-Content -LiteralPath $report -Encoding utf8

            & $script:RtRestore -Path $report -Names $script:RtDictPath *>$null
            $LASTEXITCODE | Should -Be 1

            & $script:RtRestore -Path $report -Names $script:RtDictPath -AllowUnresolved *>$null
            $LASTEXITCODE | Should -Be 0

            $named = $report -replace '\.md$', '.named.md'
            Remove-Item -LiteralPath $named -Force -ErrorAction SilentlyContinue
        }
        finally { Remove-Item -LiteralPath $report -Force -ErrorAction SilentlyContinue }
    }

    It 'refuses to guess when an abbreviation matches more than one id' {
        # Two ids sharing a 9-character prefix. Guessing would put the wrong
        # object into a report, which is worse than an unresolved reference.
        $a = 'abcdef12-1111-4111-8111-111111111111'
        $b = 'abcdef12-2222-4222-8222-222222222222'
        $dict = @{ entries = @{
            $a = @{ token = $a; type = 'object'; id = $a; name = 'Alpha' }
            $b = @{ token = $b; type = 'object'; id = $b; name = 'Beta' }
        } }

        $res = Resolve-CapTruncatedIds -Text 'Review abcdef12-... now.' -Dictionary $dict
        $res['text'] | Should -BeLike '*abcdef12-...*'
        @($res['resolved']).Count | Should -Be 0
        @($res['ambiguous']).Count | Should -Be 1
    }
}

Describe 'Structural leak detectors' {
    It 'does not report a Graph OData annotation key as an email' {
        $dict = New-CapNameDictionary -Export @{ policies = @() } -Snapshot 'test'
        $doc = @{ 'authenticationStrength@odata.context' = 'https://graph.microsoft.com/beta/$metadata#x' }
        @(Test-CapNameLeak -Dictionary $dict -InputObject $doc).Count | Should -Be 0
    }

    It 'still reports a real address' {
        $dict = New-CapNameDictionary -Export @{ policies = @() } -Snapshot 'test'
        $doc = @{ owner = 'admin@contoso.com' }
        @(Test-CapNameLeak -Dictionary $dict -InputObject $doc |
            Where-Object { $_.kind -eq 'email' }).Count | Should -Be 1
    }
}

Describe 'Schema vocabulary is never masked' {
    It 'leaves a structural value alone when a tenant object shares its name' {
        # A real tenant had a group named "User". Masking rewrote every
        # "type": "user" in the analysis to that group's guid, so the safe
        # bundle described a type that does not exist.
        $export = @{ policies = @() }
        $map = @{ 'a0b1b346-4d3e-4e8b-98f8-753987be4970' = 'User' }
        $dict = New-CapNameDictionary -Export $export -NameMap $map -Snapshot 'test'
        $doc = @{ exclusionConcentration = @(@{ id = 'x'; type = 'user' }) }
        $safe = ConvertTo-CapSafeObject -InputObject $doc -Dictionary $dict
        $safe.exclusionConcentration[0].type | Should -Be 'user'
    }

    It 'does not report an unmasked schema word as a leak' {
        $map = @{ 'a0b1b346-4d3e-4e8b-98f8-753987be4970' = 'User' }
        $dict = New-CapNameDictionary -Export @{ policies = @() } -NameMap $map -Snapshot 'test'
        @(Test-CapNameLeak -Dictionary $dict -InputObject @{ type = 'user' }).Count | Should -Be 0
    }

    It 'still masks a name that merely contains a schema word' {
        $map = @{ 'bbbbbbbb-0000-0000-0000-000000000001' = 'User Admins Contoso' }
        $dict = New-CapNameDictionary -Export @{ policies = @() } -NameMap $map -Snapshot 'test'
        $safe = ConvertTo-CapSafeObject -InputObject @{ displayName = 'User Admins Contoso' } -Dictionary $dict
        $safe.displayName | Should -Not -Be 'User Admins Contoso'
    }

    It 'keeps the dictionary entry so the id still restores to the name' {
        $map = @{ 'a0b1b346-4d3e-4e8b-98f8-753987be4970' = 'User' }
        $dict = New-CapNameDictionary -Export @{ policies = @() } -NameMap $map -Snapshot 'test'
        Restore-CapNameText -Text 'Group a0b1b346-4d3e-4e8b-98f8-753987be4970 is excluded.' -Dictionary $dict |
            Should -Be 'Group User is excluded.'
    }
}

Describe 'Built-in authentication strengths are global constants' {
    It 'seeds the three built-in strengths into every dictionary' {
        $dict = New-CapNameDictionary -Export @{ policies = @() } -NameMap @{} -Snapshot 'test'
        $dict.entries['00000000-0000-0000-0000-000000000004'].name | Should -Be 'Phishing-resistant MFA'
        $dict.entries['00000000-0000-0000-0000-000000000004'].global | Should -BeTrue
    }

    It 'does not rewrite the strength name inside standards text' {
        # The name appears verbatim in CISA SCuBA control statements. Masking it
        # there rewrites the standard rather than tenant data, and the leak test
        # then rejects a bundle that was never unsafe.
        $map = @{ 'str-1' = 'Phishing-resistant MFA' }
        $dict = New-CapNameDictionary -Export @{ policies = @() } -NameMap $map -Snapshot 'test'
        $doc = @{ statement = 'Phishing-resistant MFA SHALL be enforced for all users.' }
        $safe = ConvertTo-CapSafeObject -InputObject $doc -Dictionary $dict
        $safe.statement | Should -Be 'Phishing-resistant MFA SHALL be enforced for all users.'
        @(Test-CapNameLeak -Dictionary $dict -InputObject $safe).Count | Should -Be 0
    }
}

Describe 'Repair-CapRestoredIds' {
    It 'puts back an id that re-hydration overwrote with a name' {
        # Restoring is a blind text substitution: a policy whose displayName was
        # masked to its own id comes back with the name in both fields.
        $masked   = @{ policies = @(@{ id = 'aaaaaaaa-0000-0000-0000-000000000001'; displayName = 'aaaaaaaa-0000-0000-0000-000000000001' }) }
        $restored = @{ policies = @(@{ id = 'CA001'; displayName = 'CA001' }) }
        $n = Repair-CapRestoredIds -Restored $restored -Masked $masked
        $n | Should -Be 1
        $restored.policies[0].id | Should -Be 'aaaaaaaa-0000-0000-0000-000000000001'
        $restored.policies[0].displayName | Should -Be 'CA001'
    }

    It 'leaves an id alone when re-hydration did not touch it' {
        $masked   = @{ policies = @(@{ id = 'aaaaaaaa-0000-0000-0000-000000000001'; displayName = 'x' }) }
        $restored = @{ policies = @(@{ id = 'aaaaaaaa-0000-0000-0000-000000000001'; displayName = 'CA001' }) }
        Repair-CapRestoredIds -Restored $restored -Masked $masked | Should -Be 0
    }

    It 'does nothing when the two shapes disagree' {
        $masked   = @{ policies = @(@{ id = 'aaaaaaaa-0000-0000-0000-000000000001' }) }
        $restored = @{ policies = @(@{ id = 'CA001' }, @{ id = 'CA002' }) }
        Repair-CapRestoredIds -Restored $restored -Masked $masked | Should -Be 0
    }
}

Describe 'Analysis exposure classification' {
    BeforeAll {
        $script:RawAnalysis = @{
            consolidation = @{
                deadWeight = @(@{ id = 'p1'; displayName = 'CA001 - secret'; reasons = @('disabled') })
                summary    = @{ total = 1; targetTotal = 1; unexpectedField = 'should not travel' }
            }
            findings = @{
                summary  = @{ total = 3; bySeverity = @{ high = 3 } }
                findings = @(
                    @{ id = 'f1'; checkId = 'legacy-auth-not-blocked'; title = 'Legacy auth'; severity = 'high'; affectedObjects = @('p1') },
                    @{ id = 'f2'; checkId = 'user-not-mfa-capable'; title = 'Not MFA capable'; severity = 'high'; affectedObjects = @('u1'); description = 'OBJECT-1 cannot do MFA' },
                    @{ id = 'f3'; checkId = 'user-not-mfa-capable'; title = 'Not MFA capable'; severity = 'high'; affectedObjects = @('u2') }
                )
            }
            tests = @{ passed = 1 }
        }
        $script:Exportable = New-CapExportableAnalysis -Analysis $script:RawAnalysis
    }

    It 'drops a field that the allowlist does not name' {
        $script:Exportable.consolidation.summary.Contains('unexpectedField') | Should -BeFalse
        $script:Exportable.consolidation.summary.total | Should -Be 1
    }

    It 'never carries a display name out of the tenant' {
        $script:Exportable.consolidation.deadWeight[0].Contains('displayName') | Should -BeFalse
        $script:Exportable.consolidation.deadWeight[0].id | Should -Be 'p1'
    }

    It 'ships a policy-scoped finding in full' {
        @($script:Exportable.findings.findings).Count | Should -Be 1
        $script:Exportable.findings.findings[0].checkId | Should -Be 'legacy-auth-not-blocked'
    }

    It 'reduces a person-scoped check to a count' {
        # Two records naming individuals become one number. Shipping them in
        # full would publish a ranked list of who to attack.
        $agg = @($script:Exportable.findings.aggregated | Where-Object { $_.checkId -eq 'user-not-mfa-capable' })
        $agg.Count | Should -Be 1
        $agg[0].count | Should -Be 2
        ($agg[0] | ConvertTo-Json -Depth 5) | Should -Not -BeLike '*u1*'
    }

    It 'records why a section was aggregated' {
        $script:Exportable.analysisExposure | Should -Not -BeNullOrEmpty
        ($script:Exportable.analysisExposure | ConvertTo-Json -Depth 5) | Should -BeLike '*user-not-mfa-capable*'
    }

    It 'excludes a section the classification does not cover' {
        $script:Exportable.Contains('tests') | Should -BeFalse
    }
}

Describe 'Safe export stays backward compatible' {
    It 'produces the 1.2 shape when no analysis is supplied' {
        $bundle = New-CapPolicyOnlyExport -Export $script:Safe
        $bundle.capExport.schemaVersion | Should -Be '1.2'
        $bundle.Contains('consolidation') | Should -BeFalse
        $bundle.Contains('analysisExposure') | Should -BeFalse
    }

    It 'moves to 1.3 and carries the analysis when one is supplied' {
        $analysis = @{ consolidation = @{ summary = @{ total = 1 } } }
        $bundle = New-CapPolicyOnlyExport -Export $script:Safe -Analysis $analysis
        $bundle.capExport.schemaVersion | Should -Be '1.3'
        $bundle.consolidation.summary.total | Should -Be 1
        $bundle.analysisExposure | Should -Not -BeNullOrEmpty
    }
}
