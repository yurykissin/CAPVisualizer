<#
.SYNOPSIS
    Assemble the bundle that is safe to hand to a cloud service or AI assistant,
    and prove it: every artifact is verified against the local name dictionary
    before the folder is declared clean.

.DESCRIPTION
    Copies only the name-free artifacts of a snapshot (raw/export.json and
    analysis/*) into <snapshot>/safe, optionally pseudonymizing tenant-specific
    object ids, then runs the leak test. If any real name, unallowlisted GUID or
    IP-shaped string survives, the bundle is deleted and the command fails: a
    bundle that cannot be proven clean must never be uploaded.

    The dictionary (raw/names.json) is never copied. Keep it: it is what turns
    the AI's report back into real names, via Restore-CapNames.ps1.

.PARAMETER SnapshotPath
    A CAPVisualizer snapshot folder (the timestamped folder under output/).

.PARAMETER Names
    Dictionary path, when it does not sit at <snapshot>/raw/names.json.

.PARAMETER NoPseudonymize
    Keep the real object ids in the bundle. By default every tenant-specific id
    is replaced with a stable alias (OBJ-004, POL-002, TENANT-001) so the
    uploaded artifact carries nothing tenant-correlatable. The alias map is
    written back into the local dictionary, so the result stays reversible.
    Well-known Microsoft app and role ids are always left readable.

.EXAMPLE
    pwsh ./scripts/Export-CapSafeBundle.ps1 -SnapshotPath ./output/20260728-091141

.EXAMPLE
    pwsh ./scripts/Export-CapSafeBundle.ps1 -SnapshotPath ./output/20260728-091141 -NoPseudonymize
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)][string]$SnapshotPath,
    [string]$Names,
    [string]$OutputPath,
    [switch]$NoPseudonymize,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modules = Join-Path $PSScriptRoot 'modules'
Import-Module (Join-Path $modules 'CapCommon.psm1') -Force
Import-Module (Join-Path $modules 'CapNames.psm1') -Force

$snapshot = (Resolve-Path -LiteralPath $SnapshotPath).Path
$exportFile = Join-Path $snapshot 'raw/export.json'
if (-not (Test-Path -LiteralPath $exportFile)) {
    throw "Not a CAPVisualizer snapshot (raw/export.json not found): $snapshot"
}

$dictionary = Import-CapNameDictionary -Path $Names -NearExport $exportFile
if (-not $dictionary) {
    throw "No name dictionary found. Expected $snapshot/raw/names.json, or pass -Names. Without it the bundle cannot be verified."
}

$pseudonymize = -not $NoPseudonymize
if ($pseudonymize) {
    # The run-time dictionary holds names only; the aliases that remove the last
    # tenant-correlatable ids are added now and persisted, so Restore-CapNames
    # can still resolve them after the review comes back.
    $exportDoc = Get-Content -LiteralPath $exportFile -Raw | ConvertFrom-Json -Depth 30 -AsHashtable
    $dictionary = Add-CapIdAliases -Dictionary $dictionary -Source $exportDoc
    $dictPath = if ($Names) { $Names } else { Join-Path $snapshot 'raw/names.json' }
    Save-CapJson -InputObject $dictionary -Path $dictPath
}

$safeDir = if ($OutputPath) { $OutputPath } else { Join-Path $snapshot 'safe' }
if (Test-Path -LiteralPath $safeDir) {
    if (-not $Force) { throw "Safe bundle already exists: $safeDir (use -Force to replace)." }
    Remove-Item -LiteralPath $safeDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $safeDir | Out-Null

# Only these are name-free by construction. report/* and visual/index.html carry
# resolved names on purpose and stay behind.
$sources = @('raw/export.json')
$analysisDir = Join-Path $snapshot 'analysis'
if (Test-Path -LiteralPath $analysisDir) {
    foreach ($f in Get-ChildItem -LiteralPath $analysisDir -File) { $sources += "analysis/$($f.Name)" }
}
$deltaFile = Join-Path $snapshot 'delta/delta.json'
if (Test-Path -LiteralPath $deltaFile) { $sources += 'delta/delta.json' }

$copied = [System.Collections.Generic.List[string]]::new()
foreach ($rel in $sources) {
    $src = Join-Path $snapshot $rel
    if (-not (Test-Path -LiteralPath $src)) { continue }
    $dst = Join-Path $safeDir ($rel -replace '/', [IO.Path]::DirectorySeparatorChar)
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dst) | Out-Null

    if ($pseudonymize -and $src -like '*.json') {
        # A second pass with an alias-bearing dictionary; the file is already
        # name-free, this removes the remaining tenant-correlatable ids.
        $doc = Get-Content -LiteralPath $src -Raw | ConvertFrom-Json -Depth 30 -AsHashtable
        Save-CapJson -InputObject (ConvertTo-CapSafeObject -InputObject $doc -Dictionary $dictionary) -Path $dst
    }
    else {
        Copy-Item -LiteralPath $src -Destination $dst -Force
    }
    $copied.Add($rel)
}

$requirePseudo = $pseudonymize -and [bool](& { $v = $dictionary['pseudonymized']; $v })
$files = @(Get-ChildItem -LiteralPath $safeDir -Recurse -File | ForEach-Object { $_.FullName })
$violations = @(Test-CapNameLeak -Dictionary $dictionary -Path $files -RequirePseudonymized:$requirePseudo)

if ($violations.Count) {
    Remove-Item -LiteralPath $safeDir -Recurse -Force
    Write-CapLog "Leak test FAILED - the bundle was deleted and must not be uploaded." 'ERROR'
    foreach ($v in ($violations | Select-Object -First 20)) {
        Write-CapLog ("  {0}: {1} (in {2})" -f $v.kind, $v.value, (Split-Path -Leaf $v.source)) 'ERROR'
    }
    throw "Safe bundle rejected: $($violations.Count) leak(s) detected."
}

$readme = @"
CAPVisualizer safe bundle
=========================

Snapshot : $(Split-Path -Leaf $snapshot)
Created  : $((Get-Date).ToUniversalTime().ToString('o'))
Mode     : $(if ($requirePseudo) { 'pseudonymized (object ids aliased)' } else { 'names removed (object ids retained)' })

SAFE TO SHARE - the files in this folder. Every display name, UPN, IP range and
device-filter rule has been replaced by a token, and the result was verified
against the local dictionary before this folder was written.

NEVER SHARE - these stay on your machine:
  raw/names.json        the dictionary that maps tokens back to real names
  report/*              resolved CSV and JSON for humans
  visual/index.html     the rendered report, with names
  transcript.txt        the run log

Residual risk: anonymization removes attribution, not exploitability. This
bundle is still a map of where the Conditional Access gaps are. Share it with
the same care you would give the configuration itself.

To turn an AI-generated report back into real names:
  pwsh ./scripts/Restore-CapNames.ps1 -Path <report.md> -Names <snapshot>/raw/names.json
"@
Set-Content -LiteralPath (Join-Path $safeDir 'README.txt') -Value $readme -Encoding utf8

Write-CapLog "Safe bundle verified clean: $safeDir" 'OK'
Write-CapLog ("  {0} file(s); dictionary held back ({1} entries)." -f $copied.Count, $dictionary['count']) 'INFO'
Write-CapLog "  Upload this folder. Keep raw/names.json, report/ and visual/ local." 'INFO'
