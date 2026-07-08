#Requires -Version 7.0
<#
.SYNOPSIS
    Offline gap analysis for CAPVisualizer: permute the relevant sign-in signals
    for a principal + resource and report scenarios that reach the resource with
    no enforced block or MFA. Read-only; no tenant access.

.PARAMETER FromJson
    Path to a CAPVisualizer export JSON (schema v2.0 with enrichment recommended).

.PARAMETER PrincipalId
    Object id of the signing-in principal.

.PARAMETER Resource
    Target application id.

.PARAMETER MaxScenarios
    Cap on evaluated combinations (default 512).

.PARAMETER IncludeByDesign
    Also list gaps considered by-design (trusted-network relaxations).

.PARAMETER Jsonl
    Emit one JSON object per gap scenario (JSONL) instead of the console summary.

.EXAMPLE
    ./Invoke-CapAnalyze.ps1 -FromJson ./samples/sample-export-enriched.json `
        -PrincipalId 77777777-7777-7777-7777-777777777777 `
        -Resource 00000002-0000-0ff1-ce00-000000000000
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$FromJson,
    [Parameter(Mandatory)][string]$PrincipalId,
    [string]$Resource,
    [int]$MaxScenarios = 512,
    [switch]$IncludeByDesign,
    [switch]$Jsonl
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modules = Join-Path $PSScriptRoot 'modules'
Import-Module (Join-Path $modules 'CapCommon.psm1') -Force
Import-Module (Join-Path $modules 'CapExport.psm1') -Force
Import-Module (Join-Path $modules 'CapNormalize.psm1') -Force
Import-Module (Join-Path $modules 'CapScope.psm1') -Force
Import-Module (Join-Path $modules 'CapWhatIf.psm1') -Force
Import-Module (Join-Path $modules 'CapAnalyze.psm1') -Force

$export = Import-CapExportJson -Path $FromJson
$grouping = Get-CapAppGroupingMap
$normalized = @($export.policies | ForEach-Object { ConvertTo-CapNormalizedPolicy -Policy $_ -AppGroupingMap $grouping })
$enrichment = if ($export.Contains('enrichment')) { $export.enrichment } else { $null }

$analyzeArgs = @{ PrincipalId = $PrincipalId; NormalizedPolicies = $normalized; Enrichment = $enrichment; MaxScenarios = $MaxScenarios }
if ($PSBoundParameters.ContainsKey('Resource')) { $analyzeArgs['Resource'] = $Resource }
$result = Invoke-CapAnalyze @analyzeArgs

if ($Jsonl) {
    ConvertTo-CapAnalyzeJsonl -AnalyzeResult $result
    return
}

$s = $result.summary
Write-Host ''
Write-Host "Principal   : $($result.principal.displayName) [$($result.principal.id)]"
Write-Host "Resource    : $($result.resource)"
Write-Host "Dimensions  : $(@($result.dimensions) -join ', ')"
Write-Host "Scenarios   : evaluated $($result.evaluated) of $($result.totalScenarios)"
Write-Host "Gaps        : $($s.gapCount) total, $($s.actionableCount) actionable, $($s.byDesignCount) by-design"
if ($s.gapTypes.Keys.Count) {
    foreach ($k in $s.gapTypes.Keys) { Write-Host "   - $k : $($s.gapTypes[$k])" }
}

$show = if ($IncludeByDesign) { @($result.gaps) } else { @($result.gaps | Where-Object { -not $_.byDesign }) }
Write-Host ''
if (-not $show.Count) { Write-Host 'No actionable gaps found.' -ForegroundColor Green; return }
Write-Host 'Gap scenarios:' -ForegroundColor Yellow
foreach ($g in $show) {
    $sig = ($g.signals.Keys | ForEach-Object { "$_=$($g.signals[$_])" }) -join ', '
    $tag = if ($g.byDesign) { '[by-design] ' } else { '' }
    Write-Host "  $tag$($g.gapType): $sig" -ForegroundColor ($(if ($g.byDesign) { 'DarkGray' } else { 'Red' }))
    Write-Host "      $($g.reason)"
}
