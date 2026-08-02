#Requires -Version 7.0
<#
    Pester tests for Graph shape drift.

    When Microsoft adds a new shape for an existing condition, a tool that reads
    only the old shape does not fail loudly: it reports the condition as absent.
    Absent targeting reads as "this policy does nothing", which reads as dead
    weight, which reads as "delete it". That is how two live managed-provider
    policies named "DO NOT DELETE OR MODIFY" were put on a customer's deletion
    list while the visual report, which reads the raw Graph object, showed them
    targeting the provider correctly.

    These tests pin the shapes that caused it and the guard that is meant to
    catch the next one.
#>

BeforeAll {
    $repo = Split-Path $PSScriptRoot -Parent
    $modules = Join-Path $repo 'scripts/modules'
    foreach ($m in 'CapCommon', 'CapExport', 'CapNormalize', 'CapConsolidate', 'CapNames') {
        Import-Module (Join-Path $modules "$m.psm1") -Force
    }

    $script:Repo = $repo

    function New-ShapePolicy {
        param([hashtable]$Conditions, [string]$Name = 'Provider access policy', [string]$Id = '00000000-0000-0000-0000-00000000000a')
        $base = @{
            id          = $Id
            displayName = $Name
            state       = 'enabled'
            conditions  = $Conditions
            grantControls = @{ operator = 'OR'; builtInControls = @('mfa') }
        }
        return $base
    }

    # The exact shape Graph returns for a policy scoped to one managed provider:
    # a comma separated type list, and a single member unrolled to a bare string.
    $script:MsspConditions = @{
        users = @{
            includeUsers  = @()
            excludeUsers  = @()
            includeGroups = @()
            includeRoles  = @()
            includeGuestsOrExternalUsers = @{
                guestOrExternalUserTypes = 'serviceProvider'
                externalTenants = @{
                    membershipKind = 'enumerated'
                    members        = '37ac251a-9341-4ae8-b2a2-aa7febf5ce05'
                }
            }
        }
        applications = @{ includeApplications = @('All') }
    }
}

Describe 'Guest and external user targeting' {

    It 'reads the modern guest selector, not just the legacy literal' {
        $n = ConvertTo-CapNormalizedPolicy -Policy (New-ShapePolicy -Conditions $script:MsspConditions)
        $n.conditions.users.includeGuests | Should -BeTrue
    }

    It 'still reads the legacy GuestsOrExternalUsers literal in includeUsers' {
        $legacy = @{
            users = @{ includeUsers = @('GuestsOrExternalUsers') }
            applications = @{ includeApplications = @('All') }
        }
        $n = ConvertTo-CapNormalizedPolicy -Policy (New-ShapePolicy -Conditions $legacy)
        $n.conditions.users.includeGuests | Should -BeTrue
    }

    It 'splits comma separated guest types into a list' {
        $c = @{
            users = @{
                excludeGuestsOrExternalUsers = @{
                    guestOrExternalUserTypes = 'b2bDirectConnectUser,otherExternalUser,serviceProvider'
                    externalTenants = @{ membershipKind = 'all' }
                }
            }
            applications = @{ includeApplications = @('All') }
        }
        $n = ConvertTo-CapNormalizedPolicy -Policy (New-ShapePolicy -Conditions $c)
        @($n.conditions.users.excludeGuestTypes).Count | Should -Be 3
        $n.conditions.users.excludeGuestTypes | Should -Contain 'serviceProvider'
    }

    It 'reads a single partner tenant that Graph unrolled to a scalar' {
        $n = ConvertTo-CapNormalizedPolicy -Policy (New-ShapePolicy -Conditions $script:MsspConditions)
        $n.conditions.users.includeGuestTenantMode | Should -Be 'enumerated'
        @($n.conditions.users.includeGuestTenants).Count | Should -Be 1
        $n.conditions.users.includeGuestTenants[0] | Should -Be '37ac251a-9341-4ae8-b2a2-aa7febf5ce05'
    }

    It 'reads several partner tenants passed as an array' {
        $c = @{
            users = @{
                includeGuestsOrExternalUsers = @{
                    guestOrExternalUserTypes = 'serviceProvider'
                    externalTenants = @{
                        membershipKind = 'enumerated'
                        members = @('11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222')
                    }
                }
            }
            applications = @{ includeApplications = @('All') }
        }
        $n = ConvertTo-CapNormalizedPolicy -Policy (New-ShapePolicy -Conditions $c)
        @($n.conditions.users.includeGuestTenants).Count | Should -Be 2
    }

    It 'does not treat a guest-only policy as targeting nobody' {
        $n = ConvertTo-CapNormalizedPolicy -Policy (New-ShapePolicy -Conditions $script:MsspConditions)
        $dead = Get-CapDeadWeight -NormalizedPolicies @($n)
        @($dead).Count | Should -Be 0
    }

    It 'does not fingerprint two different partner tenants as the same target' {
        $a = ConvertTo-CapNormalizedPolicy -Policy (New-ShapePolicy -Conditions $script:MsspConditions -Id '00000000-0000-0000-0000-0000000000a1')
        $bCond = @{
            users = @{
                includeGuestsOrExternalUsers = @{
                    guestOrExternalUserTypes = 'serviceProvider'
                    externalTenants = @{ membershipKind = 'enumerated'; members = '99999999-9999-9999-9999-999999999999' }
                }
            }
            applications = @{ includeApplications = @('All') }
        }
        $b = ConvertTo-CapNormalizedPolicy -Policy (New-ShapePolicy -Conditions $bCond -Id '00000000-0000-0000-0000-0000000000a2')
        $clusters = Find-CapDuplicatePolicies -NormalizedPolicies @($a, $b)
        @($clusters.exact).Count | Should -Be 0
    }
}

Describe 'Retire heuristic on policy names' {

    It 'does not call a DO NOT DELETE policy dead weight on its name' {
        $n = ConvertTo-CapNormalizedPolicy -Policy (New-ShapePolicy -Conditions $script:MsspConditions -Name 'Microsoft Security Experts-Require MFA -DO NOT DELETE OR MODIFY')
        $dead = Get-CapDeadWeight -NormalizedPolicies @($n)
        @($dead).Count | Should -Be 0
    }

    It 'still flags an obvious test policy' {
        $n = ConvertTo-CapNormalizedPolicy -Policy (New-ShapePolicy -Conditions $script:MsspConditions -Name 'TEST - remove me')
        $dead = Get-CapDeadWeight -NormalizedPolicies @($n)
        @($dead).Count | Should -Be 1
    }

    It 'still flags a policy whose name says do not use' {
        $n = ConvertTo-CapNormalizedPolicy -Policy (New-ShapePolicy -Conditions $script:MsspConditions -Name 'Legacy baseline - DO NOT USE')
        $dead = Get-CapDeadWeight -NormalizedPolicies @($n)
        @($dead).Count | Should -Be 1
    }
}

Describe 'Resource targeting beyond application ids' {

    It 'reads a Global Secure Access traffic profile as a targeted resource' {
        $c = @{
            users = @{ includeUsers = @('All') }
            applications = @{
                includeApplications = @()
                globalSecureAccess = @{ includeTrafficProfiles = 'internet' }
            }
        }
        $n = ConvertTo-CapNormalizedPolicy -Policy (New-ShapePolicy -Conditions $c)
        $n.conditions.applications.trafficProfiles | Should -Contain 'internet'
    }

    It 'reads the same profile from the older networkAccess shape' {
        $c = @{
            users = @{ includeUsers = @('All') }
            applications = @{
                includeApplications = @()
                networkAccess = @{ includeTrafficProfiles = 'internet' }
            }
        }
        $n = ConvertTo-CapNormalizedPolicy -Policy (New-ShapePolicy -Conditions $c)
        $n.conditions.applications.trafficProfiles | Should -Contain 'internet'
    }

    It 'reads an application filter' {
        $c = @{
            users = @{ includeUsers = @('All') }
            applications = @{ includeApplications = @(); applicationFilter = @{ mode = 'include'; rule = 'app.tag -eq "hr"' } }
        }
        $n = ConvertTo-CapNormalizedPolicy -Policy (New-ShapePolicy -Conditions $c)
        $n.conditions.applications.appFilter.rule | Should -Be 'app.tag -eq "hr"'
    }

    It 'reads agent identity targeting' {
        $c = @{
            users = @{ includeUsers = @('All') }
            applications = @{ includeApplications = @('All') }
            clientApplications = @{ includeAgentIdServicePrincipals = @('All') }
        }
        $n = ConvertTo-CapNormalizedPolicy -Policy (New-ShapePolicy -Conditions $c)
        $n.conditions.workloadIdentities.present | Should -BeTrue
    }

    It 'reads the deprecated top-level deviceStates block' {
        $c = @{
            users = @{ includeUsers = @('All') }
            applications = @{ includeApplications = @('All') }
            deviceStates = @{ includeStates = @('All'); excludeStates = @('compliant') }
        }
        $n = ConvertTo-CapNormalizedPolicy -Policy (New-ShapePolicy -Conditions $c)
        $n.conditions.devices.present | Should -BeTrue
        $n.conditions.devices.excludeDeviceStates | Should -Contain 'compliant'
    }
}

Describe 'Shape coverage guard' {

    It 'reports nothing unread for the sample export' {
        $export = Import-CapExportJson -Path (Join-Path $script:Repo 'samples/sample-export-enriched.json')
        $unread = Test-CapShapeCoverage -Policies $export.policies
        @($unread).Count | Should -Be 0
    }

    It 'reports a populated condition shape the normalizer does not read' {
        $c = @{
            users = @{ includeUsers = @('All') }
            applications = @{ includeApplications = @('All') }
            # Stand-in for whatever Microsoft ships next.
            quantumEntanglementLevels = @('spooky')
        }
        $unread = Test-CapShapeCoverage -Policies @((New-ShapePolicy -Conditions $c))
        @($unread).Count | Should -Be 1
        @($unread)[0].path | Should -Be 'quantumEntanglementLevels'
        @($unread)[0].sample | Should -Be 'spooky'
    }

    It 'names the policies carrying the unread shape' {
        $c = @{
            users = @{ includeUsers = @('All') }
            applications = @{ includeApplications = @('All') }
            somethingNew = @{ nested = 'value' }
        }
        $unread = Test-CapShapeCoverage -Policies @((New-ShapePolicy -Conditions $c -Id 'abc'))
        @($unread)[0].policyIds | Should -Contain 'abc'
    }

    It 'does not report a shape that is present but empty' {
        $c = @{
            users = @{ includeUsers = @('All') }
            applications = @{ includeApplications = @('All') }
            futureThing = @()
        }
        $unread = Test-CapShapeCoverage -Policies @((New-ShapePolicy -Conditions $c))
        @($unread).Count | Should -Be 0
    }
}

Describe 'Partner tenant ids in the shareable export' {

    BeforeAll {
        $script:ExtExport = @{
            metadata = @{ tenantId = '00000000-0000-0000-0000-0000000000ff' }
            policies = @((New-ShapePolicy -Conditions $script:MsspConditions -Name 'Provider access'))
        }
    }

    It 'registers the partner tenant id in the dictionary' {
        $dict = New-CapNameDictionary -Export $script:ExtExport -Snapshot 'shape-test'
        $ext = @($dict.entries.Values | Where-Object { $_.type -eq 'exttenant' })
        @($ext).Count | Should -Be 1
        $ext[0].name | Should -Be '37ac251a-9341-4ae8-b2a2-aa7febf5ce05'
    }

    It 'removes the partner tenant id from the shareable export' {
        $dict = New-CapNameDictionary -Export $script:ExtExport -Snapshot 'shape-test'
        $masked = ConvertTo-CapSafeObject -InputObject $script:ExtExport -Dictionary $dict
        $safe = New-CapPolicyOnlyExport -Export $masked -Snapshot 'shape-test'
        $json = $safe | ConvertTo-Json -Depth 40
        $json | Should -Not -Match '37ac251a'
        $json | Should -Match 'EXTTENANT-'
    }

    It 'keeps the partner tenant id restorable from the dictionary' {
        $dict = New-CapNameDictionary -Export $script:ExtExport -Snapshot 'shape-test'
        $ext = @($dict.entries.Values | Where-Object { $_.type -eq 'exttenant' })[0]
        $restored = Restore-CapNameText -Text "Policy admits $($ext.token) only." -Dictionary $dict
        $restored | Should -Match '37ac251a-9341-4ae8-b2a2-aa7febf5ce05'
    }
}

Describe 'Guid-valued display names do not corrupt ids' {

    It 'does not rewrite one policy id into another when a name is a bare guid' {
        # Seen on a real snapshot: a policy whose display name is another
        # policy's id. Registering that name mints the second policy's own id as
        # the token, so masking replaced every occurrence of the first policy's
        # id with the second's. The duplicate cluster then listed one policy
        # twice and the other vanished.
        $a = '11111111-1111-1111-1111-111111111111'
        $b = '22222222-2222-2222-2222-222222222222'
        $export = @{
            metadata = @{ tenantId = '00000000-0000-0000-0000-0000000000ff' }
            policies = @(
                @{ id = $a; displayName = 'Require MFA for admins'; state = 'enabled' },
                @{ id = $b; displayName = $a; state = 'enabled' }
            )
        }
        $dict = New-CapNameDictionary -Export $export -Snapshot 'guid-name-test'
        $masked = ConvertTo-CapSafeObject -InputObject $export -Dictionary $dict
        $ids = @($masked.policies | ForEach-Object { "$($_.id)" })
        $ids | Should -Contain $a
        $ids | Should -Contain $b
        (@($ids | Select-Object -Unique)).Count | Should -Be 2
    }
}

Describe 'Restore refuses the shareable export' {

    It 'exits non-zero and leaves the bundle untouched' {
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("cap-shape-" + [guid]::NewGuid().ToString('n'))
        New-Item -ItemType Directory -Path $tmp | Out-Null
        try {
            $bundle = Join-Path $tmp 'bundle.json'
            @{ capExport = @{ tool = 'CAPVisualizer'; kind = 'policyOnlyExport'; schemaVersion = '1.3' }
              policies = @() } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $bundle

            $names = Join-Path $tmp 'names.json'
            @{ snapshot = 'x'; count = 0; entries = @{} } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $names

            $before = Get-Content -LiteralPath $bundle -Raw
            $script = Join-Path $script:Repo 'scripts/Restore-CapNames.ps1'
            & pwsh -NoProfile -File $script -Path $bundle -Names $names -InPlace *> $null
            $LASTEXITCODE | Should -Be 1
            (Get-Content -LiteralPath $bundle -Raw) | Should -Be $before
        }
        finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Compiled matcher cache' {

    BeforeAll {
        $script:CacheExport = @{
            metadata = @{ tenantId = '00000000-0000-0000-0000-0000000000ff' }
            policies = @(
                @{ id = '11111111-1111-1111-1111-111111111111'; displayName = 'Require MFA for Contoso admins'; state = 'enabled' }
            )
        }
    }

    It 'produces the same masking on a second call with the same dictionary' {
        $dict = New-CapNameDictionary -Export $script:CacheExport -Snapshot 'cache-test'
        $first  = ConvertTo-CapSafeObject -InputObject $script:CacheExport -Dictionary $dict | ConvertTo-Json -Depth 20
        $second = ConvertTo-CapSafeObject -InputObject $script:CacheExport -Dictionary $dict | ConvertTo-Json -Depth 20
        $second | Should -Be $first
        $first | Should -Not -Match 'Contoso'
    }

    It 'rebuilds after the dictionary gains id aliases part way through a run' {
        # The cache is keyed by dictionary instance, and pseudonymization mutates
        # that instance rather than replacing it. An earlier version stamped the
        # cache on the wrong key, so masking after this point kept serving
        # matchers that did not alias ids and the object ids shipped in clear.
        $dict = New-CapNameDictionary -Export $script:CacheExport -Snapshot 'cache-test'
        ConvertTo-CapSafeObject -InputObject $script:CacheExport -Dictionary $dict | Out-Null

        Add-CapIdAliases -Dictionary $dict -Source $script:CacheExport
        $after = ConvertTo-CapSafeObject -InputObject $script:CacheExport -Dictionary $dict | ConvertTo-Json -Depth 20
        $after | Should -Not -Match '11111111-1111-1111-1111-111111111111'
    }

    It 'does not serve one dictionary matchers built for another' {
        $otherExport = @{
            metadata = @{ tenantId = '00000000-0000-0000-0000-0000000000ee' }
            policies = @(@{ id = '22222222-2222-2222-2222-222222222222'; displayName = 'Block legacy auth at Fabrikam'; state = 'enabled' })
        }
        $d1 = New-CapNameDictionary -Export $script:CacheExport -Snapshot 'cache-a'
        $d2 = New-CapNameDictionary -Export $otherExport -Snapshot 'cache-b'
        ConvertTo-CapSafeObject -InputObject $script:CacheExport -Dictionary $d1 | Out-Null
        $out = ConvertTo-CapSafeObject -InputObject $otherExport -Dictionary $d2 | ConvertTo-Json -Depth 20
        $out | Should -Not -Match 'Fabrikam'
    }
}
