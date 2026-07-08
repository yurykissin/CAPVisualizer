#Requires -Version 7.0
<#
.SYNOPSIS
    CI-friendly assertion runner for CAPVisualizer. Evaluates a declarative
    assertion pack against an export, writes machine-readable output (JUnit /
    SARIF / JSON), and exits non-zero when any assertion fails. Read-only.

.PARAMETER FromJson
    Path to a CAPVisualizer export JSON (schema v2.0 with enrichment recommended).

.PARAMETER AssertionPath
    Path to an assertion pack. Defaults to the packaged starter pack.

.PARAMETER JUnitPath / SarifPath / JsonPath
    Optional output file paths for each format.

.PARAMETER Quiet
    Suppress the console summary (still writes files and sets the exit code).

.EXAMPLE
    ./Invoke-CapTest.ps1 -FromJson ./export.json -JUnitPath ./results.xml
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$FromJson,
    [string]$AssertionPath,
    [string]$JUnitPath,
    [string]$SarifPath,
    [string]$JsonPath,
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modules = Join-Path $PSScriptRoot 'modules'
foreach ($m in 'CapCommon', 'CapExport', 'CapNormalize', 'CapScope', 'CapWhatIf', 'CapAudit', 'CapFindings', 'CapCompliance', 'CapTest') {
    Import-Module (Join-Path $modules "$m.psm1") -Force
}

$export = Import-CapExportJson -Path $FromJson
$grouping = Get-CapAppGroupingMap
$normalized = @($export.policies | ForEach-Object { ConvertTo-CapNormalizedPolicy -Policy $_ -AppGroupingMap $grouping })
$enrichment = if ($export.Contains('enrichment')) { $export.enrichment } else { $null }

$testArgs = @{ NormalizedPolicies = $normalized; Enrichment = $enrichment }
if ($AssertionPath) { $testArgs['AssertionPath'] = $AssertionPath }
$result = Invoke-CapTest @testArgs

if ($JUnitPath) { ConvertTo-CapJUnit -TestResult $result | Set-Content -Path $JUnitPath -Encoding utf8 }
if ($SarifPath) { ConvertTo-CapSarif -TestResult $result | Set-Content -Path $SarifPath -Encoding utf8 }
if ($JsonPath)  { $result | ConvertTo-Json -Depth 12 | Set-Content -Path $JsonPath -Encoding utf8 }

if (-not $Quiet) {
    $s = $result.summary
    Write-Host ''
    Write-Host "Assertion pack: $($result.name)"
    foreach ($a in $result.assertions) {
        $mark = switch ($a.result) { 'pass' { '[PASS]' } 'fail' { '[FAIL]' } default { '[ERR ]' } }
        $color = switch ($a.result) { 'pass' { 'Green' } 'fail' { 'Red' } default { 'Yellow' } }
        Write-Host "  $mark $($a.name)" -ForegroundColor $color
        if ($a.result -ne 'pass') { Write-Host "         $($a.message)" }
    }
    Write-Host ''
    Write-Host "Total $($s.total) | Passed $($s.passed) | Failed $($s.failed) | Errored $($s.errored)"
}

if (-not $result.passed) { exit 1 }
exit 0
