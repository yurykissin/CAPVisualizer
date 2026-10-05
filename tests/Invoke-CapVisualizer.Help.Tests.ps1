#Requires -Version 7.0

BeforeAll {
    $script:EntryPoint = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts/Invoke-CapVisualizer.ps1'
    $script:Help = Get-Help $script:EntryPoint -Full
}

Describe 'Invoke-CapVisualizer comment-based help' {
    It 'documents every public parameter' {
        $undocumented = @(
            $script:Help.parameters.parameter |
                Where-Object { [string]::IsNullOrWhiteSpace(($_.description | Out-String)) } |
                Select-Object -ExpandProperty name
        )

        $undocumented | Should -BeNullOrEmpty
    }

    It 'keeps examples intact instead of treating placeholders as markup' {
        $examples = Get-Help $script:EntryPoint -Examples | Out-String -Width 240

        $examples | Should -Match '-ClientId 11111111-2222-3333-4444-555555555555 -CertificateThumbprint A1B2C3D4E5F6'
        $examples | Should -Match '-FromJson ./cap-safe-review.json -Names ./names.json'
        $examples | Should -Match '-Pseudonymize -Delta'
    }

    It 'states the minimum and enrichment permissions' {
        $full = $script:Help | Out-String -Width 240

        $full | Should -Match 'Interactive minimum: Policy.Read.All'
        $full | Should -Match 'UserAuthenticationMethod.Read.All'
    }
}
