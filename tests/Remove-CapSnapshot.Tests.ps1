#Requires -Modules Pester

BeforeAll {
    $repo = Split-Path -Parent $PSScriptRoot
    $script:ScriptPath = Join-Path $repo 'scripts/Remove-CapSnapshot.ps1'
}

Describe 'Remove-CapSnapshot' {
    BeforeEach {
        $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) ("cap-retention-{0}" -f ([guid]::NewGuid()))
        New-Item -ItemType Directory -Path $script:Root | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $script:Root '20260101-000000') | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $script:Root '20261001-000000') | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $script:Root 'manual-backup') | Out-Null
    }

    AfterEach {
        if (Test-Path -LiteralPath $script:Root) {
            Remove-Item -LiteralPath $script:Root -Recurse -Force
        }
    }

    It 'is a dry run by default' {
        $result = @(& $script:ScriptPath -OutputRoot $script:Root -RetainDays 90 -AsOf ([datetime]'2026-10-05'))

        $result.Count | Should -Be 1
        $result[0].Action | Should -Be 'WouldRemove'
        $result[0].Snapshot | Should -Be '20260101-000000'
        Test-Path -LiteralPath (Join-Path $script:Root '20260101-000000') | Should -BeTrue
    }

    It 'removes only eligible timestamped direct children with Apply' {
        $result = @(& $script:ScriptPath -OutputRoot $script:Root -RetainDays 90 -AsOf ([datetime]'2026-10-05') -Apply)

        $result.Count | Should -Be 1
        $result[0].Action | Should -Be 'Removed'
        Test-Path -LiteralPath (Join-Path $script:Root '20260101-000000') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $script:Root '20261001-000000') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:Root 'manual-backup') | Should -BeTrue
    }

    It 'rejects a missing output root' {
        { & $script:ScriptPath -OutputRoot (Join-Path $script:Root 'missing') -RetainDays 90 } |
            Should -Throw '*does not exist*'
    }

    It 'rejects the repository root' {
        $repo = Split-Path -Parent $PSScriptRoot
        { & $script:ScriptPath -OutputRoot $repo -RetainDays 90 } |
            Should -Throw '*broad root*'
    }

    It 'never follows a timestamped symbolic link' -Skip:$IsWindows {
        $outside = Join-Path ([System.IO.Path]::GetTempPath()) ("cap-retention-outside-{0}" -f ([guid]::NewGuid()))
        New-Item -ItemType Directory -Path $outside | Out-Null
        $link = Join-Path $script:Root '20200101-000000'
        New-Item -ItemType SymbolicLink -Path $link -Target $outside | Out-Null
        try {
            $result = @(& $script:ScriptPath -OutputRoot $script:Root -RetainDays 90 -AsOf ([datetime]'2026-10-05') -Apply -WarningAction SilentlyContinue)
            $result.Snapshot | Should -Not -Contain '20200101-000000'
            Test-Path -LiteralPath $outside | Should -BeTrue
        }
        finally {
            if (Test-Path -LiteralPath $outside) { Remove-Item -LiteralPath $outside -Recurse -Force }
        }
    }
}
