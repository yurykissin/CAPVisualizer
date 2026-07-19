#Requires -Version 7.0
<#
    Pester tests for the authentication-methods audit engine (CapAuthMethods.psm1).
    Offline against samples/sample-export-enriched.json.
#>

BeforeAll {
    $repo = Split-Path $PSScriptRoot -Parent
    $modules = Join-Path $repo 'scripts/modules'
    foreach ($m in 'CapCommon', 'CapExport', 'CapAuthMethods') {
        Import-Module (Join-Path $modules "$m.psm1") -Force
    }

    $export = Import-CapExportJson -Path (Join-Path $repo 'samples/sample-export-enriched.json')
    $script:Result = Invoke-CapAuthMethods -Enrichment $export.enrichment
}

Describe 'Availability' {
    It 'is available when mfaCapability data is present' {
        $script:Result.available | Should -BeTrue
    }

    It 'reports unavailable and a reason when enrichment is missing' {
        $r = Invoke-CapAuthMethods -Enrichment $null
        $r.available | Should -BeFalse
        $r.reason | Should -Not -BeNullOrEmpty
        @($r.users).Count | Should -Be 0
        @($r.gaps).Count  | Should -Be 0
    }

    It 'reports unavailable when mfaCapability was not collected' {
        $enr = [pscustomobject]@{ mfaCapability = [pscustomobject]@{ available = $false; data = @() } }
        $r = Invoke-CapAuthMethods -Enrichment $enr
        $r.available | Should -BeFalse
    }
}

Describe 'Summary rollup' {
    It 'counts every user' {
        $script:Result.summary.totalUsers | Should -Be 6
    }

    It 'computes MFA registration count and percentage' {
        $script:Result.summary.mfaRegistered | Should -Be 4
        $script:Result.summary.mfaRegisteredPct | Should -Be 66.7
    }

    It 'identifies admins and their MFA / phishing-resistant posture' {
        $script:Result.summary.admins | Should -Be 2
        $script:Result.summary.adminsMfaRegistered | Should -Be 2
        $script:Result.summary.adminsPhishResistant | Should -Be 1
    }

    It 'counts phishing-resistant and passwordless capable users' {
        $script:Result.summary.phishResistant | Should -Be 2
        $script:Result.summary.passwordlessCapable | Should -Be 2
    }

    It 'counts users still registered for SMS/voice (telephony) MFA' {
        $script:Result.summary.smsVoiceUsers | Should -Be 2
        $script:Result.summary.adminsSmsVoice | Should -Be 1
    }

    It 'produces a method breakdown sorted by count' {
        $mb = @($script:Result.summary.methodBreakdown)
        @($mb).Count | Should -BeGreaterThan 0
        $mb[0].method | Should -Be 'microsoftAuthenticatorPush'
        $mb[0].count  | Should -Be 4
        $mb[0].label  | Should -Be 'Microsoft Authenticator (push)'
    }
}

Describe 'Gap findings' {
    It 'flags an admin without a phishing-resistant method as high' {
        $g = @($script:Result.gaps | Where-Object { $_.id -eq 'admin-no-phishing-resistant' })
        @($g).Count | Should -Be 1
        $g[0].severity | Should -Be 'high'
        $g[0].count | Should -Be 1
    }

    It 'flags a user with no MFA-capable method as high' {
        $g = @($script:Result.gaps | Where-Object { $_.id -eq 'user-no-mfa-method' })
        @($g).Count | Should -Be 1
        $g[0].severity | Should -Be 'high'
    }

    It 'flags MFA-capable-but-not-registered users' {
        $g = @($script:Result.gaps | Where-Object { $_.id -eq 'user-mfa-capable-not-registered' })
        @($g).Count | Should -Be 1
        @($g[0].users).Count | Should -Be 1
    }

    It 'flags SSPR-capable-but-not-registered users' {
        $g = @($script:Result.gaps | Where-Object { $_.id -eq 'user-sspr-not-registered' })
        @($g).Count | Should -Be 1
        $g[0].severity | Should -Be 'low'
    }

    It 'flags an admin still using SMS/voice MFA as high' {
        $g = @($script:Result.gaps | Where-Object { $_.id -eq 'admin-uses-sms-voice-mfa' })
        @($g).Count | Should -Be 1
        $g[0].severity | Should -Be 'high'
        $g[0].count | Should -Be 1
        @($g[0].users).userPrincipalName | Should -Contain 'olddba@contoso.com'
    }

    It 'flags a non-admin still using SMS/voice MFA as medium' {
        $g = @($script:Result.gaps | Where-Object { $_.id -eq 'user-uses-sms-voice-mfa' })
        @($g).Count | Should -Be 1
        $g[0].severity | Should -Be 'medium'
        @($g[0].users).userPrincipalName | Should -Contain 'bob@contoso.com'
        @($g[0].users).userPrincipalName | Should -Not -Contain 'olddba@contoso.com'
    }

    It 'does not emit a gap group with zero matched users' {
        foreach ($g in $script:Result.gaps) { $g.count | Should -BeGreaterThan 0 }
    }
}

Describe 'Per-user rows' {
    It 'normalizes one row per user' {
        @($script:Result.users).Count | Should -Be 6
    }

    It 'derives hasPhishResistant from registered methods' {
        $bg = @($script:Result.users | Where-Object { $_.userPrincipalName -eq 'breakglass@contoso.com' })[0]
        $bg.hasPhishResistant | Should -BeTrue
        $dba = @($script:Result.users | Where-Object { $_.userPrincipalName -eq 'olddba@contoso.com' })[0]
        $dba.hasPhishResistant | Should -BeFalse
    }

    It 'derives usesTelephonyMfa from registered methods' {
        $dba = @($script:Result.users | Where-Object { $_.userPrincipalName -eq 'olddba@contoso.com' })[0]
        $dba.usesTelephonyMfa | Should -BeTrue
        $dba.telephonyMethods | Should -Contain 'mobilePhone'
        $bg = @($script:Result.users | Where-Object { $_.userPrincipalName -eq 'breakglass@contoso.com' })[0]
        $bg.usesTelephonyMfa | Should -BeFalse
    }

    It 'does not expose raw method secrets, only method identifiers' {
        $bg = @($script:Result.users | Where-Object { $_.userPrincipalName -eq 'breakglass@contoso.com' })[0]
        $bg.methodsRegistered | Should -Contain 'fido2SecurityKey'
        $bg.PSObject.Properties.Name | Should -Not -Contain 'phoneNumber'
    }
}

Describe 'Get-CapMethodLabel' {
    It 'returns a friendly label for a known method' {
        Get-CapMethodLabel -Method 'fido2SecurityKey' | Should -Be 'FIDO2 security key'
    }

    It 'returns the raw identifier for an unknown method' {
        Get-CapMethodLabel -Method 'somethingNew' | Should -Be 'somethingNew'
    }
}
