#Requires -Modules Pester

BeforeAll {
    $repo = Split-Path -Parent $PSScriptRoot
    $script:InvokePath = Join-Path $repo 'scripts/Invoke-CapVisualizer.ps1'
    $script:VerifyPath = Join-Path $repo 'scripts/Test-CapManifest.ps1'
}

Describe 'Snapshot integrity' {
    BeforeEach {
        $script:Root = Join-Path ([IO.Path]::GetTempPath()) "cap-manifest-$([guid]::NewGuid())"
        & $script:InvokePath -FromJson (Join-Path (Split-Path -Parent $PSScriptRoot) 'samples/sample-export-enriched.json') `
            -OutputRoot $script:Root -NoOpen -NoTranscript *>$null
        $script:Snapshot = @(Get-ChildItem -LiteralPath $script:Root -Directory)[0].FullName
    }

    AfterEach {
        if (Test-Path -LiteralPath $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force }
    }

    It 'uses a collision-safe timestamp name' {
        (Split-Path -Leaf $script:Snapshot) | Should -Match '^\d{8}-\d{6}-\d{3}(?:-[0-9a-f]{6})?$'
    }

    It 'verifies an unchanged snapshot' {
        $result = & $script:VerifyPath -SnapshotPath $script:Snapshot
        $result.Valid | Should -BeTrue
        $result.FileCount | Should -BeGreaterThan 0
    }

    It 'stamps the export, manifest, and viewer with tool provenance' {
        $version = (Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) 'VERSION') -Raw).Trim()
        $export = Get-Content (Join-Path $script:Snapshot 'raw/export.json') -Raw | ConvertFrom-Json -Depth 30 -AsHashtable
        $manifest = Get-Content (Join-Path $script:Snapshot 'manifest.json') -Raw | ConvertFrom-Json -Depth 30 -AsHashtable
        $html = Get-Content (Join-Path $script:Snapshot 'visual/index.html') -Raw

        $export.metadata.toolVersion | Should -Be $version
        $export.metadata.toolCommit | Should -Match '^[0-9a-f]{12}$'
        $manifest.toolVersion | Should -Be $version
        $manifest.toolCommit | Should -Be $export.metadata.toolCommit
        $html | Should -BeLike "*v$version*"
        $html | Should -BeLike "*$($export.metadata.toolCommit)*"
    }

    It 'rejects a changed file' {
        Add-Content -LiteralPath (Join-Path $script:Snapshot 'report/summary.json') -Value 'changed'
        { & $script:VerifyPath -SnapshotPath $script:Snapshot -ErrorAction SilentlyContinue } |
            Should -Throw '*verification failed*'
    }

    It 'rejects an unexpected file' {
        Set-Content -LiteralPath (Join-Path $script:Snapshot 'raw/injected.txt') -Value 'x'
        { & $script:VerifyPath -SnapshotPath $script:Snapshot -ErrorAction SilentlyContinue } |
            Should -Throw '*verification failed*'
    }

    It 'checks an external manifest hash' {
        Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/modules/CapCommon.psm1') -Force
        $hash = Get-CapFileSha256 -Path (Join-Path $script:Snapshot 'manifest.json')
        (& $script:VerifyPath -SnapshotPath $script:Snapshot -ExpectedManifestHash $hash).Valid | Should -BeTrue
        { & $script:VerifyPath -SnapshotPath $script:Snapshot -ExpectedManifestHash ('0' * 64) -ErrorAction SilentlyContinue } |
            Should -Throw '*verification failed*'
    }

    It 'verifies a keyed HMAC and rejects the wrong key' {
        Remove-Item -LiteralPath $script:Root -Recurse -Force
        $key = ConvertTo-SecureString 'correct horse battery staple' -AsPlainText -Force
        & $script:InvokePath -FromJson (Join-Path (Split-Path -Parent $PSScriptRoot) 'samples/sample-export-enriched.json') `
            -OutputRoot $script:Root -NoOpen -NoTranscript -ManifestKey $key *>$null
        $script:Snapshot = @(Get-ChildItem -LiteralPath $script:Root -Directory)[0].FullName

        (& $script:VerifyPath -SnapshotPath $script:Snapshot -ManifestKey $key).HmacVerified | Should -BeTrue
        $wrong = ConvertTo-SecureString 'wrong key' -AsPlainText -Force
        { & $script:VerifyPath -SnapshotPath $script:Snapshot -ManifestKey $wrong -ErrorAction SilentlyContinue } |
            Should -Throw '*verification failed*'
    }
}
