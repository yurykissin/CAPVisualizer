#Requires -Version 7.0
<#
.SYNOPSIS
    Rationalization & consolidation analysis for CAPVisualizer: compares every
    Conditional Access policy against every other to find duplicates, same-effect
    overlaps and safe merge candidates, plus dead weight, best-practice
    completeness gaps and exclusion concentration. Read-only; no tenant access.

.DESCRIPTION
    Unlike Compare-CapSnapshot.ps1 (which diffs the SAME tenant across two points
    in time by policy id), this compares DIFFERENT policies to each other to
    detect redundancy and reduce estate sprawl. Emits JSON + CSVs and a console
    summary with an estimated before -> after policy count.

.PARAMETER FromJson
    Path to a CAPVisualizer export JSON (or a snapshot folder containing
    raw/export.json).

.PARAMETER OutputPath
    Folder for consolidation.json + the CSV breakdowns. Defaults to the snapshot's
    analysis/ folder when a snapshot folder is given, else the input file's folder.

.EXAMPLE
    ./Invoke-CapConsolidate.ps1 -FromJson ./output/20260722-090000
.EXAMPLE
    ./Invoke-CapConsolidate.ps1 -FromJson ./samples/sample-export-enriched.json -OutputPath ./out
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$FromJson,
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modules = Join-Path $PSScriptRoot 'modules'
Import-Module (Join-Path $modules 'CapCommon.psm1')     -Force
Import-Module (Join-Path $modules 'CapExport.psm1')     -Force
Import-Module (Join-Path $modules 'CapNormalize.psm1')  -Force
Import-Module (Join-Path $modules 'CapConsolidate.psm1') -Force

# Resolve the export file (accept a snapshot folder or a direct json path).
$exportFile = $FromJson
if (Test-Path -LiteralPath $FromJson -PathType Container) {
    $candidate = Join-Path $FromJson 'raw/export.json'
    if (-not (Test-Path -LiteralPath $candidate)) { throw "Could not find raw/export.json under '$FromJson'." }
    $exportFile = $candidate
}

$export = Import-CapExportJson -Path $exportFile
$grouping = Get-CapAppGroupingMap
$normalized = @($export.policies | ForEach-Object { ConvertTo-CapNormalizedPolicy -Policy $_ -AppGroupingMap $grouping })

# Optional name resolution for exclusion concentration.
$nameMap = @{}
if ($export.Contains('nameMap') -and $export.nameMap) {
    foreach ($k in $export.nameMap.Keys) { $nameMap["$k"] = "$($export.nameMap[$k])" }
}

$result = Invoke-CapConsolidate -NormalizedPolicies $normalized -NameMap $nameMap

# --- Resolve output folder ---
if (-not $OutputPath) {
    if (Test-Path -LiteralPath $FromJson -PathType Container) { $OutputPath = Join-Path $FromJson 'analysis' }
    else { $OutputPath = Split-Path -Parent $exportFile }
}
if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null }

Save-CapJson -InputObject $result -Path (Join-Path $OutputPath 'consolidation.json')

# --- Flatten to reviewer-friendly CSVs ---
$dupRows = [System.Collections.Generic.List[object]]::new()
foreach ($c in $result.duplicates.exact) {
    foreach ($m in $c.members) { $dupRows.Add([pscustomobject][ordered]@{ Cluster = 'exact-duplicate'; Effect = $c.controlSig; PolicyId = $m.id; PolicyName = $m.displayName; State = $m.state }) }
}
foreach ($c in $result.duplicates.overlap) {
    $kind = if ($c.identical) { 'overlap-identical' } else { 'overlap-review' }
    foreach ($m in $c.members) { $dupRows.Add([pscustomobject][ordered]@{ Cluster = $kind; Effect = $c.controlSig; PolicyId = $m.id; PolicyName = $m.displayName; State = 'enabled' }) }
}
foreach ($c in $result.duplicates.merge) {
    foreach ($m in $c.members) { $dupRows.Add([pscustomobject][ordered]@{ Cluster = 'merge-candidate'; Effect = $c.controlSig; PolicyId = $m.id; PolicyName = $m.displayName; State = 'enabled' }) }
}
if ($dupRows.Count) { $dupRows | Export-Csv -Path (Join-Path $OutputPath 'consolidation-clusters.csv') -NoTypeInformation -Encoding UTF8 }

$deadRows = [System.Collections.Generic.List[object]]::new()
foreach ($d in $result.deadWeight) {
    $deadRows.Add([pscustomobject][ordered]@{ PolicyId = $d.id; PolicyName = $d.displayName; State = $d.state; Reasons = ($d.reasons -join '; ') })
}
if ($deadRows.Count) { $deadRows | Export-Csv -Path (Join-Path $OutputPath 'consolidation-deadweight.csv') -NoTypeInformation -Encoding UTF8 }

# --- Console summary ---
$s = $result.summary
Write-Host ''
Write-Host "Policies             : $($s.total)  (enabled $($s.enforced) / report-only $($s.reportOnly) / disabled $($s.disabled))"
Write-Host "Exact duplicates     : $($s.exactDuplicateClusters) cluster(s)"
Write-Host "Overlap clusters     : $($s.overlapClusters)  (same control+apps; review those differing by conditions)"
Write-Host "Merge candidates     : $($s.mergeCandidateClusters) cluster(s)"
Write-Host "Dead weight          : $($s.deadWeightCount) policy(ies) (disabled / report-only / name-flagged)"
Write-Host "Completeness gaps    : $($s.completenessGaps) baseline control(s) missing"
Write-Host ("Estimated reduction  : {0} -> ~{1} policies (-{2})" -f $s.total, $s.estimatedTarget, $s.estimatedReduction) -ForegroundColor Cyan

$gaps = @($result.completeness | Where-Object { -not $_.present })
if ($gaps.Count) {
    Write-Host ''
    Write-Host 'Missing baseline controls:' -ForegroundColor Yellow
    foreach ($g in $gaps) { Write-Host "  [$($g.severity)] $($g.control)" -ForegroundColor $(if ($g.severity -eq 'high') { 'Red' } else { 'DarkYellow' }) }
}
Write-Host ''
Write-CapLog "Consolidation analysis written to $OutputPath" 'OK'
