#Requires -Modules Pester

BeforeAll {
    $repo = Split-Path -Parent $PSScriptRoot
    $script:Register = Join-Path $repo 'scripts/Register-CapSchedule.ps1'
    $script:Runner = Join-Path $repo 'scripts/Invoke-CapScheduledRun.ps1'
}

Describe 'Scheduled run safety' {
    It 'generates a marked cron entry through the overlap-safe wrapper' -Skip:$IsWindows {
        $text = (& $script:Register -TenantId tenant -ClientId client -CertificatePath $PSHOME/pwsh -Time 03:00 6>&1) -join "`n"
        $text | Should -Match 'Invoke-CapScheduledRun\.ps1'
        $text | Should -Match '# CAPVisualizer-Daily'
    }

    It 'rejects a PFX readable by group or other users' -Skip:$IsWindows {
        $root = Join-Path ([IO.Path]::GetTempPath()) "cap-schedule-$([guid]::NewGuid())"
        $pfx = Join-Path $root 'credential.pfx'
        try {
            New-Item -ItemType Directory -Path $root | Out-Null
            Set-Content -LiteralPath $pfx -Value 'not a real pfx'
            chmod 644 $pfx
            { & $script:Runner -TenantId tenant -ClientId client -CertificatePath $pfx -OutputRoot $root } |
                Should -Throw '*permissions are too broad*'
        }
        finally {
            if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
        }
    }

    It 'rejects an overlapping run before authentication' {
        $root = Join-Path ([IO.Path]::GetTempPath()) "cap-schedule-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Path $root | Out-Null
        $lockPath = Join-Path $root '.capvisualizer.lock'
        $lock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        try {
            { & $script:Runner -TenantId tenant -ClientId client -CertificateThumbprint thumb -OutputRoot $root } |
                Should -Throw '*already holds the lock*'
        }
        finally {
            $lock.Dispose()
            Remove-Item -LiteralPath $root -Recurse -Force
        }
    }
}
