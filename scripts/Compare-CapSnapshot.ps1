<#
.SYNOPSIS
    Compare two CAPVisualizer snapshots and emit a delta (JSON + CSV).

.DESCRIPTION
    Read-only. Loads the raw export.json from two snapshot folders and reports
    added / removed / modified Conditional Access policies with field-level
    changes. Useful to see what changed between two periodic runs.

.PARAMETER BaselinePath
    Path to the older snapshot folder (or its raw/export.json).

.PARAMETER CurrentPath
    Path to the newer snapshot folder (or its raw/export.json).

.PARAMETER OutputPath
    Optional folder to write delta.json / delta-modified.csv. Defaults to the
    current snapshot's delta/ subfolder.

.EXAMPLE
    pwsh ./scripts/Compare-CapSnapshot.ps1 -BaselinePath output/20260101-090000 -CurrentPath output/20260201-090000
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$BaselinePath,
    [Parameter(Mandatory)][string]$CurrentPath,
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'modules/CapCommon.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'modules/CapDelta.psm1')  -Force

function Resolve-ExportJson([string]$p) {
    if (Test-Path -LiteralPath $p -PathType Leaf) { return $p }
    $candidate = Join-Path $p 'raw/export.json'
    if (Test-Path -LiteralPath $candidate) { return $candidate }
    throw "Could not find export.json under '$p'."
}

$baseFile = Resolve-ExportJson $BaselinePath
$curFile  = Resolve-ExportJson $CurrentPath

Write-CapLog "Baseline: $baseFile" 'INFO'
Write-CapLog "Current:  $curFile" 'INFO'

$baseline = Get-Content -LiteralPath $baseFile -Raw | ConvertFrom-Json -Depth 30 -AsHashtable
$current  = Get-Content -LiteralPath $curFile  -Raw | ConvertFrom-Json -Depth 30 -AsHashtable

$delta = Compare-CapExport -Baseline $baseline -Current $current

if (-not $OutputPath) {
    $root = if (Test-Path -LiteralPath $CurrentPath -PathType Container) { $CurrentPath } else { Split-Path -Parent (Split-Path -Parent $curFile) }
    $OutputPath = Join-Path $root 'delta'
}
if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null }

Save-CapJson -InputObject $delta -Path (Join-Path $OutputPath 'delta.json')

# Flatten modified changes to CSV.
$rows = foreach ($m in $delta.modified) {
    foreach ($chg in $m.changes) {
        [pscustomobject][ordered]@{
            PolicyId   = $m.id
            PolicyName = $m.displayName
            Field      = $chg.field
            From       = $chg.from
            To         = $chg.to
        }
    }
}
if ($rows) { $rows | Export-Csv -Path (Join-Path $OutputPath 'delta-modified.csv') -NoTypeInformation -Encoding UTF8 }

Write-CapLog ("Delta: {0} added, {1} removed, {2} modified." -f $delta.addedCount, $delta.removedCount, $delta.modifiedCount) 'OK'
Write-CapLog "Delta written to $OutputPath" 'OK'
