<#
.SYNOPSIS
    CAPVisualizer assertion / test engine (Phase 8). Evaluates a declarative
    assertion pack against an export and emits machine-readable results (JUnit /
    SARIF / JSON) with a CI-friendly pass/fail summary. Independent DSL - not
    Pester.

.DESCRIPTION
    Assertion types:
      * compliance       - a baseline control must have an expected result.
      * findingThreshold - the finding set must not contain more than N findings
                           at/above a given severity.
      * whatif           - a simulated sign-in for a principal/resource must yield
                           an expected outcome (e.g. mfaRequired / blocked).

    The engine computes any analysis result it needs (compliance, findings,
    what-if) from the normalized policy set + enrichment, so a single export is
    enough to drive a CI gate fully offline.

    Authored independently; no third-party tool code or logic is reused.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:CapSeverityRank = @{ info = 0; low = 1; medium = 2; high = 3; critical = 4 }

function _TeArr { param($v) if ($null -eq $v) { return @() }; if ($v -is [string]) { return @($v) }; if ($v -is [System.Collections.IEnumerable]) { return @($v | ForEach-Object { $_ }) }; @($v) }

function _TeGet {
    param($Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [System.Collections.IDictionary]) { if ($Obj.Contains($Name)) { return $Obj[$Name] } return $null }
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    $null
}

function Get-CapAssertionPack {
<#
.SYNOPSIS
    Load an assertion pack. Defaults to the packaged starter pack.
#>
    [CmdletBinding()]
    param([string]$AssertionPath)
    if (-not $AssertionPath) {
        $AssertionPath = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'assets/reference/assertions/starter-assertions.json'
    }
    if (-not (Test-Path $AssertionPath)) { throw "Assertion pack not found: $AssertionPath" }
    Get-Content -Raw -Path $AssertionPath | ConvertFrom-Json
}

function _TeResult {
    param([string]$Id, [string]$Name, [string]$Type, [string]$Result, [string]$Message)
    [ordered]@{ id = $Id; name = $Name; type = $Type; result = $Result; message = $Message }
}

function Invoke-CapTest {
<#
.SYNOPSIS
    Run an assertion pack against a normalized policy set + enrichment.

.OUTPUTS
    Ordered hashtable: name, assertions[] (id, name, type, result pass|fail|error,
    message), summary{ total, passed, failed, errored }, passed (overall bool).
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$NormalizedPolicies,
        $Enrichment,
        [string]$AssertionPath,
        $ComplianceResult,
        $FindingsResult
    )

    $pack = Get-CapAssertionPack -AssertionPath $AssertionPath
    $policies = @($NormalizedPolicies)

    # Lazily compute the analysis results the assertions reference.
    $needCompliance = @($pack.assertions | Where-Object { "$(_TeGet $_ 'type')" -eq 'compliance' }).Count -gt 0
    $needFindings   = @($pack.assertions | Where-Object { "$(_TeGet $_ 'type')" -eq 'findingThreshold' }).Count -gt 0

    if ($needCompliance -and -not $ComplianceResult) { $ComplianceResult = Invoke-CapCompliance -NormalizedPolicies $policies }
    if ($needFindings -and -not $FindingsResult) { $FindingsResult = Invoke-CapFindings -NormalizedPolicies $policies -Enrichment $Enrichment }

    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($a in @($pack.assertions)) {
        $id = "$(_TeGet $a 'id')"; $name = "$(_TeGet $a 'name')"; $type = "$(_TeGet $a 'type')"
        try {
            switch ($type) {
                'compliance' {
                    $controlId = "$(_TeGet $a 'control')"
                    $expect = "$(_TeGet $a 'expect')"
                    $ctrl = @($ComplianceResult.controls | Where-Object { $_.id -eq $controlId })
                    if (-not $ctrl.Count) {
                        $results.Add((_TeResult $id $name $type 'error' "Control $controlId not found in baseline."))
                    }
                    elseif ($ctrl[0].result -eq $expect) {
                        $results.Add((_TeResult $id $name $type 'pass' "$controlId = $($ctrl[0].result) (expected $expect)."))
                    }
                    else {
                        $results.Add((_TeResult $id $name $type 'fail' "$controlId = $($ctrl[0].result), expected $expect. $($ctrl[0].rationale)"))
                    }
                }
                'findingThreshold' {
                    $sev = "$(_TeGet $a 'disallowSeverity')"
                    $maxCount = [int](_TeGet $a 'maxCount')
                    $rank = $script:CapSeverityRank[$sev]
                    $over = @($FindingsResult.findings | Where-Object { $script:CapSeverityRank[$_.severity] -ge $rank })
                    if ($over.Count -le $maxCount) {
                        $results.Add((_TeResult $id $name $type 'pass' "$($over.Count) finding(s) at/above '$sev' (max $maxCount)."))
                    }
                    else {
                        $titles = @($over | Select-Object -First 5 | ForEach-Object { $_.title }) -join '; '
                        $results.Add((_TeResult $id $name $type 'fail' "$($over.Count) finding(s) at/above '$sev' exceed max ${maxCount}: $titles"))
                    }
                }
                'whatif' {
                    $principalId = "$(_TeGet $a 'principalId')"
                    $resource = "$(_TeGet $a 'resource')"
                    $signals = _TeGet $a 'signals'
                    $expect = _TeGet $a 'expect'
                    $wiArgs = @{ PrincipalId = $principalId; NormalizedPolicies = $policies; Enrichment = $Enrichment }
                    if ($resource) { $wiArgs['Resource'] = $resource }
                    if ($signals) {
                        foreach ($k in @('Platform', 'ClientApp', 'Location', 'SignInRisk', 'UserRisk', 'AuthFlow', 'DeviceState')) {
                            $v = _TeGet $signals $k
                            if ($v) { $wiArgs[$k] = $v }
                        }
                    }
                    $wi = Test-CapWhatIf @wiArgs
                    $fails = [System.Collections.Generic.List[string]]::new()
                    foreach ($k in @('blocked', 'mfaRequired')) {
                        $exp = _TeGet $expect $k
                        if ($null -ne $exp) {
                            $actual = [bool]$wi.outcome.$k
                            if ($actual -ne [bool]$exp) { $fails.Add("$k expected $([bool]$exp) but was $actual") }
                        }
                    }
                    if ($fails.Count -eq 0) {
                        $results.Add((_TeResult $id $name $type 'pass' 'Sign-in outcome matched expectations.'))
                    }
                    else {
                        $results.Add((_TeResult $id $name $type 'fail' ($fails -join '; ')))
                    }
                }
                default {
                    $results.Add((_TeResult $id $name $type 'error' "Unknown assertion type '$type'."))
                }
            }
        }
        catch {
            $results.Add((_TeResult $id $name $type 'error' "Assertion raised an error: $($_.Exception.Message)"))
        }
    }

    $all = @($results)
    $passed = @($all | Where-Object { $_.result -eq 'pass' }).Count
    $failed = @($all | Where-Object { $_.result -eq 'fail' }).Count
    $errored = @($all | Where-Object { $_.result -eq 'error' }).Count

    [ordered]@{
        name       = "$(_TeGet $pack 'name')"
        assertions = $all
        summary    = [ordered]@{ total = $all.Count; passed = $passed; failed = $failed; errored = $errored }
        passed     = ($failed -eq 0 -and $errored -eq 0)
    }
}

function _XmlEscape { param([string]$s) if ($null -eq $s) { return '' }; $s.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;') }

function ConvertTo-CapJUnit {
<#
.SYNOPSIS
    Render a test result as JUnit XML (fail + error => <failure>).
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$TestResult)
    $all = @($TestResult.assertions)
    $failures = @($all | Where-Object { $_.result -ne 'pass' }).Count
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<?xml version="1.0" encoding="UTF-8"?>')
    [void]$sb.AppendLine("<testsuites tests=""$($all.Count)"" failures=""$failures"">")
    [void]$sb.AppendLine("  <testsuite name=""$(_XmlEscape $TestResult.name)"" tests=""$($all.Count)"" failures=""$failures"">")
    foreach ($a in $all) {
        $cn = _XmlEscape $a.type
        $nm = _XmlEscape $a.name
        if ($a.result -eq 'pass') {
            [void]$sb.AppendLine("    <testcase classname=""$cn"" name=""$nm"" />")
        }
        else {
            [void]$sb.AppendLine("    <testcase classname=""$cn"" name=""$nm"">")
            [void]$sb.AppendLine("      <failure message=""$(_XmlEscape $a.message)"">$(_XmlEscape $a.result)</failure>")
            [void]$sb.AppendLine('    </testcase>')
        }
    }
    [void]$sb.AppendLine('  </testsuite>')
    [void]$sb.AppendLine('</testsuites>')
    $sb.ToString()
}

function ConvertTo-CapSarif {
<#
.SYNOPSIS
    Render failing/errored assertions as SARIF 2.1.0 results (level=error).
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$TestResult)
    $rules = @($TestResult.assertions | ForEach-Object { [ordered]@{ id = $_.id; name = $_.name; shortDescription = [ordered]@{ text = $_.name } } })
    $results = @($TestResult.assertions | Where-Object { $_.result -ne 'pass' } | ForEach-Object {
        [ordered]@{
            ruleId  = $_.id
            level   = if ($_.result -eq 'error') { 'error' } else { 'error' }
            message = [ordered]@{ text = $_.message }
        }
    })
    [ordered]@{
        version = '2.1.0'
        '$schema' = 'https://json.schemastore.org/sarif-2.1.0.json'
        runs = @(
            [ordered]@{
                tool = [ordered]@{ driver = [ordered]@{ name = 'CAPVisualizer'; informationUri = 'https://github.com/'; rules = $rules } }
                results = $results
            }
        )
    } | ConvertTo-Json -Depth 12
}

Export-ModuleMember -Function Invoke-CapTest, Get-CapAssertionPack, ConvertTo-CapJUnit, ConvertTo-CapSarif
