<#
.SYNOPSIS
    CAPVisualizer compliance baseline engine (Phase 7). Evaluates the normalized
    Conditional Access policy set against an independently authored baseline pack
    mapped to public CISA SCuBA (MS.AAD.*) control identifiers, with NIST 800-53
    and MITRE ATT&CK references.

.DESCRIPTION
    The baseline pack (assets/reference/baselines/cisa-scuba-aad.json) supplies
    the control text, criticality, and standards references. Each control names a
    checkId that maps to a predicate implemented here, so the pack can be versioned
    and extended (for controls reusing existing checks) without code changes.

    Authored independently: control identifiers, NIST controls, and MITRE
    technique IDs are public references, not third-party tool code or logic.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Built-in "Phishing-resistant MFA" authentication strength policy id (public,
# stable Microsoft identifier).
$script:CapPhishResistantStrengthId = '00000000-0000-0000-0000-000000000004'

function _CoArr { param($v) if ($null -eq $v) { return @() }; if ($v -is [string]) { return @($v) }; if ($v -is [System.Collections.IEnumerable]) { return @($v | ForEach-Object { $_ }) }; @($v) }

function _CoGet {
    param($Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [System.Collections.IDictionary]) { if ($Obj.Contains($Name)) { return $Obj[$Name] } return $null }
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    $null
}

function Get-CapBaseline {
<#
.SYNOPSIS
    Load the compliance baseline pack. Defaults to the packaged CISA SCuBA AAD
    baseline.
#>
    [CmdletBinding()]
    param([string]$BaselinePath)
    if (-not $BaselinePath) {
        $BaselinePath = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'assets/reference/baselines/cisa-scuba-aad.json'
    }
    if (-not (Test-Path $BaselinePath)) { throw "Baseline pack not found: $BaselinePath" }
    Get-Content -Raw -Path $BaselinePath | ConvertFrom-Json
}

# --- Predicate helpers: each returns @{ pass = [bool]; evidence = [string[]] } --

function _BroadBlock {
    param($Policies, [scriptblock]$ExtraCondition)
    $matches = @($Policies | Where-Object {
        $_.enforced -and $_.grant.block -and
        $_.conditions.users.includeAll -and $_.conditions.applications.includeAll -and
        (& $ExtraCondition $_)
    })
    @{ pass = ($matches.Count -ge 1); evidence = @($matches | ForEach-Object { $_.displayName }) }
}

function _BroadGrant {
    param($Policies, [scriptblock]$ExtraCondition)
    $matches = @($Policies | Where-Object {
        $_.enforced -and
        $_.conditions.users.includeAll -and $_.conditions.applications.includeAll -and
        (& $ExtraCondition $_)
    })
    @{ pass = ($matches.Count -ge 1); evidence = @($matches | ForEach-Object { $_.displayName }) }
}

$script:CapComplianceChecks = @{
    'block-legacy-auth' = {
        param($Policies)
        _BroadBlock $Policies {
            param($p)
            (-not $p.conditions.clientApps.isAll) -and
            (@(_CoArr $p.conditions.clientApps.effective) | Where-Object { @('exchangeActiveSync', 'other') -contains $_ }).Count -ge 1
        }
    }
    'block-high-risk-user' = {
        param($Policies)
        _BroadBlock $Policies { param($p) (@(_CoArr $p.conditions.userRisk) -contains 'high') }
    }
    'block-high-risk-signin' = {
        param($Policies)
        _BroadBlock $Policies { param($p) (@(_CoArr $p.conditions.signInRisk) -contains 'high') }
    }
    'phishing-resistant-mfa-all-users' = {
        param($Policies)
        $matches = @($Policies | Where-Object {
            $_.enforced -and $_.conditions.users.includeAll -and $_.conditions.applications.includeAll -and
            "$($_.grant.authStrengthId)" -eq $script:CapPhishResistantStrengthId
        })
        @{ pass = ($matches.Count -ge 1); evidence = @($matches | ForEach-Object { $_.displayName }) }
    }
    'mfa-all-users' = {
        param($Policies)
        $matches = @($Policies | Where-Object {
            $_.enforced -and $_.grant.requireMfa -and
            $_.conditions.users.includeAll -and $_.conditions.applications.includeAll
        })
        @{ pass = ($matches.Count -ge 1); evidence = @($matches | ForEach-Object { $_.displayName }) }
    }
    'phishing-resistant-mfa-privileged-roles' = {
        param($Policies)
        $matches = @($Policies | Where-Object {
            $_.enforced -and $_.conditions.applications.includeAll -and
            "$($_.grant.authStrengthId)" -eq $script:CapPhishResistantStrengthId -and
            ($_.conditions.users.includeAll -or @($_.conditions.users.includeRoles).Count -ge 1)
        })
        @{ pass = ($matches.Count -ge 1); evidence = @($matches | ForEach-Object { $_.displayName }) }
    }
    'require-managed-device' = {
        param($Policies)
        _BroadGrant $Policies { param($p) ($p.grant.requireCompliant -or $p.grant.requireHybrid) }
    }
}

function Invoke-CapCompliance {
<#
.SYNOPSIS
    Evaluate the normalized policy set against the baseline pack.

.OUTPUTS
    Ordered hashtable: baseline, baselineVersion, controls[] (each with id,
    statement, criticality, result, rationale, evidence, nist[], mitre[]),
    summary{ total, pass, fail, manual, notApplicable, passRate }.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$NormalizedPolicies,
        [string]$BaselinePath
    )

    $pack = Get-CapBaseline -BaselinePath $BaselinePath
    $policies = @($NormalizedPolicies)
    $controls = [System.Collections.Generic.List[object]]::new()

    foreach ($c in @(_CoArr $pack.controls)) {
        $checkId = "$(_CoGet $c 'checkId')"
        $result = 'manual'
        $rationale = ''
        $evidence = @()

        if ($script:CapComplianceChecks.ContainsKey($checkId)) {
            $outcome = & $script:CapComplianceChecks[$checkId] $policies
            if ($outcome.pass) {
                $result = 'pass'; $rationale = "$(_CoGet $c 'rationalePass')"; $evidence = @($outcome.evidence)
            }
            else {
                $result = 'fail'; $rationale = "$(_CoGet $c 'rationaleFail')"
            }
        }
        else {
            $rationale = 'No automated check available - manual review required.'
        }

        $controls.Add([ordered]@{
            id          = "$(_CoGet $c 'id')"
            checkId     = $checkId
            statement   = "$(_CoGet $c 'statement')"
            criticality = "$(_CoGet $c 'criticality')"
            result      = $result
            rationale   = $rationale
            evidence    = @($evidence)
            nist        = @(_CoArr (_CoGet $c 'nist'))
            mitre       = @(_CoArr (_CoGet $c 'mitre'))
        })
    }

    $all = @($controls)
    $pass = @($all | Where-Object { $_.result -eq 'pass' }).Count
    $fail = @($all | Where-Object { $_.result -eq 'fail' }).Count
    $manual = @($all | Where-Object { $_.result -eq 'manual' }).Count
    $na = @($all | Where-Object { $_.result -eq 'not-applicable' }).Count
    $auto = $pass + $fail

    [ordered]@{
        baseline        = "$(_CoGet $pack 'baseline')"
        baselineVersion = "$(_CoGet $pack 'baselineVersion')"
        controls        = $all
        summary         = [ordered]@{
            total         = $all.Count
            pass          = $pass
            fail          = $fail
            manual        = $manual
            notApplicable = $na
            passRate      = if ($auto -gt 0) { [math]::Round(100.0 * $pass / $auto, 1) } else { 0 }
        }
    }
}

Export-ModuleMember -Function Invoke-CapCompliance, Get-CapBaseline
