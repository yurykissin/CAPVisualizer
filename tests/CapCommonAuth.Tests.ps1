#Requires -Modules Pester

BeforeAll {
    $repo = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repo 'scripts/modules/CapCommon.psm1') -Force
}

Describe 'Connect-CapGraph certificate file authentication' {
    BeforeEach {
        $script:CertificatePath = Join-Path ([System.IO.Path]::GetTempPath()) ("cap-cert-{0}.pfx" -f ([guid]::NewGuid()))
        Set-Content -LiteralPath $script:CertificatePath -Value 'test'
        $script:Rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=CAPVisualizer-Test',
            $script:Rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $script:Certificate = $request.CreateSelfSigned((Get-Date).AddMinutes(-1), (Get-Date).AddDays(1))

        Mock Get-Module { [pscustomobject]@{ Name = 'Microsoft.Graph.Authentication' } } -ParameterFilter { $ListAvailable } -ModuleName CapCommon
        Mock Import-Module {} -ModuleName CapCommon
        Mock Get-PfxCertificate { $script:Certificate } -ModuleName CapCommon
        Mock Connect-MgGraph {} -ModuleName CapCommon
        Mock Get-MgContext { [pscustomobject]@{ TenantId = 'tenant'; ClientId = 'client'; Account = $null } } -ModuleName CapCommon
        Mock Write-CapLog {} -ModuleName CapCommon
    }

    AfterEach {
        if (Test-Path -LiteralPath $script:CertificatePath) {
            Remove-Item -LiteralPath $script:CertificatePath -Force
        }
        $script:Certificate.Dispose()
        $script:Rsa.Dispose()
    }

    It 'loads a PFX and passes the certificate object to Microsoft Graph' {
        Connect-CapGraph -TenantId 'tenant' -ClientId 'client' -CertificatePath $script:CertificatePath | Out-Null

        Should -Invoke Get-PfxCertificate -Times 1 -ModuleName CapCommon -ParameterFilter {
            $LiteralPath -eq $script:CertificatePath -and $NoPromptForPassword
        }
        Should -Invoke Connect-MgGraph -Times 1 -ModuleName CapCommon -ParameterFilter {
            $TenantId -eq 'tenant' -and $ClientId -eq 'client' -and $null -ne $Certificate
        }
    }

    It 'rejects a PFX without an accessible private key' {
        Mock Get-PfxCertificate { [pscustomobject]@{ HasPrivateKey = $false } } -ModuleName CapCommon

        { Connect-CapGraph -TenantId 'tenant' -ClientId 'client' -CertificatePath $script:CertificatePath } |
            Should -Throw '*private key*'
        Should -Invoke Connect-MgGraph -Times 0 -ModuleName CapCommon
    }
}
