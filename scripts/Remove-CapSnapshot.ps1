#Requires -Version 7.0
<#
.SYNOPSIS
    Finds or removes expired CAPVisualizer snapshots.

.DESCRIPTION
    Examines only timestamped snapshot directories (yyyyMMdd-HHmmss) directly
    beneath the resolved output root. The default is a dry run. Pass -Apply to
    remove the listed directories.

    Reparse points and symbolic links are never followed or removed.

.PARAMETER OutputRoot
    Existing CAPVisualizer output directory. Defaults to the repository output
    directory.

.PARAMETER RetainDays
    Keep snapshots whose timestamp is newer than this many days. Default 90.

.PARAMETER Apply
    Remove the eligible snapshot directories. Without this switch, only report
    what would be removed.

.PARAMETER AsOf
    Reference time used to calculate the cutoff. Defaults to the current time.
    Primarily useful for repeatable tests and controlled automation.

.EXAMPLE
    pwsh ./scripts/Remove-CapSnapshot.ps1 -RetainDays 90
    Preview timestamped snapshots older than 90 days.

.EXAMPLE
    pwsh ./scripts/Remove-CapSnapshot.ps1 -OutputRoot /secure/cap-output -RetainDays 180 -Apply
    Remove eligible snapshots from the explicitly selected output root.
#>
[CmdletBinding()]
param(
    [string]$OutputRoot = (Join-Path (Split-Path -Parent $PSScriptRoot) 'output'),
    [ValidateRange(1, 36500)][int]$RetainDays = 90,
    [switch]$Apply,
    [datetime]$AsOf = (Get-Date)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $OutputRoot -PathType Container)) {
    throw "Output root does not exist or is not a directory: $OutputRoot"
}

$root = (Resolve-Path -LiteralPath $OutputRoot).Path
$repositoryRoot = (Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path
$homeRoot = (Resolve-Path -LiteralPath $HOME).Path
$fileSystemRoot = [System.IO.Path]::GetPathRoot($root)
foreach ($broadRoot in @($repositoryRoot, $homeRoot, $fileSystemRoot)) {
    if ([string]::Equals($root, $broadRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to use a broad root as the snapshot output directory: $root"
    }
}

$cutoff = $AsOf.AddDays(-$RetainDays)
$timestampPattern = '^\d{8}-\d{6}$'
$timestampFormat = 'yyyyMMdd-HHmmss'
$culture = [System.Globalization.CultureInfo]::InvariantCulture
$style = [System.Globalization.DateTimeStyles]::AssumeLocal

foreach ($directory in Get-ChildItem -LiteralPath $root -Directory -Force) {
    if ($directory.Name -notmatch $timestampPattern) { continue }

    $snapshotTime = [datetime]::MinValue
    if (-not [datetime]::TryParseExact($directory.Name, $timestampFormat, $culture, $style, [ref]$snapshotTime)) {
        continue
    }
    if ($snapshotTime -ge $cutoff) { continue }

    if (($directory.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Write-Warning "Skipping reparse point: $($directory.FullName)"
        continue
    }

    $resolved = (Resolve-Path -LiteralPath $directory.FullName).Path
    $parent = Split-Path -Parent $resolved
    if (-not [string]::Equals($parent, $root, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove a path outside the output root: $resolved"
    }

    if ($Apply) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
        [pscustomobject]@{ Action = 'Removed'; Snapshot = $directory.Name; Path = $resolved; Timestamp = $snapshotTime }
    }
    else {
        [pscustomobject]@{ Action = 'WouldRemove'; Snapshot = $directory.Name; Path = $resolved; Timestamp = $snapshotTime }
    }
}
