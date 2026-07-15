<#
.SYNOPSIS
    CAPVisualizer authentication-methods audit. Turns the per-user MFA
    registration report (enrichment.mfaCapability) into a tenant rollup, a set of
    gap findings, and a per-user table. Pure, read-only, offline. It uses only the
    aggregate reporting data already collected during enrichment - it never reads
    a user's actual method secrets (phone numbers, security-key names).
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Method identifiers (from the beta userRegistrationDetails report) that are
# considered phishing-resistant per Microsoft / CISA guidance.
$script:CapPhishResistantMethods = @(
    'windowsHelloForBusiness',
    'fido2SecurityKey',
    'passKeyDeviceBound',
    'passKeyDeviceBoundAuthenticator',
    'passKeyDeviceBoundWindowsHello',
    'certificateBasedAuthentication'
)

# Friendly labels for the raw methodsRegistered identifiers.
$script:CapMethodLabels = @{
    'email'                        = 'Email'
    'mobilePhone'                  = 'Phone (SMS/voice)'
    'alternateMobilePhone'         = 'Alternate phone'
    'officePhone'                  = 'Office phone'
    'microsoftAuthenticatorPush'   = 'Microsoft Authenticator (push)'
    'microsoftAuthenticatorPasswordless' = 'Microsoft Authenticator (passwordless)'
    'softwareOneTimePasscode'      = 'Software OTP'
    'hardwareOneTimePasscode'      = 'Hardware OTP'
    'windowsHelloForBusiness'      = 'Windows Hello for Business'
    'fido2SecurityKey'             = 'FIDO2 security key'
    'passKeyDeviceBound'           = 'Passkey (device-bound)'
    'passKeyDeviceBoundAuthenticator' = 'Passkey (Authenticator)'
    'passKeyDeviceBoundWindowsHello'  = 'Passkey (Windows Hello)'
    'certificateBasedAuthentication'  = 'Certificate-based auth'
    'temporaryAccessPass'          = 'Temporary Access Pass'
}

function _AmGet {
    param($Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [System.Collections.IDictionary]) { if ($Obj.Contains($Name)) { return $Obj[$Name] } return $null }
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    $null
}

function _AmArr {
    param($Value)
    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) { return @($Value) }
    if ($Value -is [System.Collections.IEnumerable]) { return @($Value) }
    @($Value)
}

function _AmPct {
    param([int]$Part, [int]$Whole)
    if ($Whole -le 0) { return 0 }
    [math]::Round(($Part / $Whole) * 100, 1)
}

function Get-CapMethodLabel {
    [CmdletBinding()]
    param([string]$Method)
    if ($script:CapMethodLabels.ContainsKey($Method)) { return $script:CapMethodLabels[$Method] }
    return $Method
}

function Invoke-CapAuthMethods {
<#
.SYNOPSIS
    Build the authentication-methods audit from directory enrichment.

.PARAMETER Enrichment
    The enrichment object (see CapEnrich\Get-CapEnrichment). Uses the
    mfaCapability dataset; degrades to { available = $false } when absent.

.OUTPUTS
    [ordered] hashtable: available, collectedUtc, summary, gaps, users.
#>
    [CmdletBinding()]
    param($Enrichment)

    $mfa = _AmArr (_AmGet (_AmGet $Enrichment 'mfaCapability') 'data')
    $available = [bool](_AmGet (_AmGet $Enrichment 'mfaCapability') 'available')

    if (-not $available -or @($mfa).Count -eq 0) {
        return [ordered]@{
            available   = $false
            reason      = 'Per-user authentication-method registration data was not collected (needs AuditLog.Read.All + UserAuthenticationMethod.Read.All or Reports.Read.All).'
            summary     = $null
            gaps        = @()
            users       = @()
        }
    }

    # Normalize per-user rows.
    $users = foreach ($m in $mfa) {
        $methods = @(_AmArr (_AmGet $m 'methodsRegistered'))
        $phishResistant = @($methods | Where-Object { $script:CapPhishResistantMethods -contains $_ })
        $upn  = "$(_AmGet $m 'userPrincipalName')"
        $name = "$(_AmGet $m 'userDisplayName')"
        [ordered]@{
            userId              = "$(_AmGet $m 'userId')"
            displayName         = if ($name) { $name } else { $upn }
            userPrincipalName   = $upn
            userType            = "$(_AmGet $m 'userType')"
            isAdmin             = [bool](_AmGet $m 'isAdmin')
            isMfaCapable        = [bool](_AmGet $m 'isMfaCapable')
            isMfaRegistered     = [bool](_AmGet $m 'isMfaRegistered')
            isPasswordlessCapable = [bool](_AmGet $m 'isPasswordlessCapable')
            isSsprCapable       = [bool](_AmGet $m 'isSsprCapable')
            isSsprRegistered    = [bool](_AmGet $m 'isSsprRegistered')
            isSsprEnabled       = [bool](_AmGet $m 'isSsprEnabled')
            methodsRegistered   = @($methods)
            methodCount         = @($methods).Count
            hasPhishResistant   = @($phishResistant).Count -ge 1
            defaultMfaMethod    = "$(_AmGet $m 'defaultMfaMethod')"
        }
    }
    $users = @($users)

    $total     = @($users).Count
    $admins    = @($users | Where-Object { $_.isAdmin })
    $adminCount = @($admins).Count

    # Method registration breakdown (how many users have each method).
    $breakdown = [ordered]@{}
    foreach ($u in $users) {
        foreach ($mth in $u.methodsRegistered) {
            if ($breakdown.Contains($mth)) { $breakdown[$mth] = $breakdown[$mth] + 1 } else { $breakdown[$mth] = 1 }
        }
    }
    $methodBreakdown = @(
        $breakdown.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
            [ordered]@{ method = $_.Key; label = (Get-CapMethodLabel -Method $_.Key); count = $_.Value }
        }
    )

    $mfaReg   = @($users | Where-Object { $_.isMfaRegistered }).Count
    $mfaCap   = @($users | Where-Object { $_.isMfaCapable }).Count
    $pwless   = @($users | Where-Object { $_.isPasswordlessCapable }).Count
    $phishRes = @($users | Where-Object { $_.hasPhishResistant }).Count
    $ssprReg  = @($users | Where-Object { $_.isSsprRegistered }).Count
    $adminMfaReg   = @($admins | Where-Object { $_.isMfaRegistered }).Count
    $adminPhishRes = @($admins | Where-Object { $_.hasPhishResistant }).Count

    $summary = [ordered]@{
        totalUsers            = $total
        mfaRegistered         = $mfaReg
        mfaRegisteredPct      = _AmPct $mfaReg $total
        mfaCapable            = $mfaCap
        mfaCapablePct         = _AmPct $mfaCap $total
        passwordlessCapable   = $pwless
        passwordlessCapablePct = _AmPct $pwless $total
        phishResistant        = $phishRes
        phishResistantPct     = _AmPct $phishRes $total
        ssprRegistered        = $ssprReg
        ssprRegisteredPct     = _AmPct $ssprReg $total
        admins                = $adminCount
        adminsMfaRegistered   = $adminMfaReg
        adminsPhishResistant  = $adminPhishRes
        methodBreakdown       = $methodBreakdown
    }

    # --- Gap findings (grouped) ---
    $gaps = [System.Collections.Generic.List[object]]::new()
    function _Gap {
        param([string]$Id, [string]$Title, [string]$Severity, [string]$Detail, $Matched)
        $matched = @($Matched)
        if ($matched.Count -eq 0) { return }
        $gaps.Add([ordered]@{
            id       = $Id
            title    = $Title
            severity = $Severity
            detail   = $Detail
            count    = $matched.Count
            users    = @($matched | ForEach-Object { [ordered]@{ id = $_.userId; displayName = $_.displayName; userPrincipalName = $_.userPrincipalName } })
        })
    }

    _Gap -Id 'admin-not-mfa-registered' -Title 'Admin has not registered for MFA' -Severity 'critical' `
        -Detail 'A privileged (admin) account has no registered MFA method, so it can authenticate with a single factor.' `
        -Matched @($admins | Where-Object { -not $_.isMfaRegistered })

    _Gap -Id 'admin-no-phishing-resistant' -Title 'Admin has no phishing-resistant method' -Severity 'high' `
        -Detail 'A privileged (admin) account is registered for MFA but has no phishing-resistant method (FIDO2, Windows Hello, passkey, or certificate).' `
        -Matched @($admins | Where-Object { $_.isMfaRegistered -and -not $_.hasPhishResistant })

    _Gap -Id 'user-mfa-capable-not-registered' -Title 'User is MFA-capable but not registered' -Severity 'medium' `
        -Detail 'The user can register a strong method but has not completed registration, so an MFA policy cannot yet be satisfied.' `
        -Matched @($users | Where-Object { $_.isMfaCapable -and -not $_.isMfaRegistered })

    _Gap -Id 'user-no-mfa-method' -Title 'User has no MFA-capable method' -Severity 'high' `
        -Detail 'The user has no method capable of satisfying multifactor authentication (lockout risk if MFA is enforced, single-factor risk if excluded).' `
        -Matched @($users | Where-Object { -not $_.isMfaCapable })

    _Gap -Id 'user-no-methods' -Title 'User has no registered authentication methods' -Severity 'medium' `
        -Detail 'The user has not registered any authentication method at all.' `
        -Matched @($users | Where-Object { $_.methodCount -eq 0 })

    _Gap -Id 'user-sspr-not-registered' -Title 'User is not registered for self-service password reset' -Severity 'low' `
        -Detail 'The user is capable of SSPR but has not registered, so they cannot self-recover a forgotten password.' `
        -Matched @($users | Where-Object { $_.isSsprCapable -and -not $_.isSsprRegistered })

    return [ordered]@{
        available   = $true
        collectedUtc = "$(_AmGet $Enrichment 'collectedUtc')"
        summary     = $summary
        gaps        = @($gaps)
        users       = @($users)
    }
}

Export-ModuleMember -Function Invoke-CapAuthMethods, Get-CapMethodLabel
