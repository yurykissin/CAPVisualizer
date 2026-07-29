<#
.SYNOPSIS
    Put the real names back into a report that was produced from a safe bundle.

.DESCRIPTION
    The AI (or any downstream tool) only ever sees tokens - object ids, or
    aliases when the bundle was pseudonymized. This script maps them back using
    the dictionary written at export time, so the deliverable reads naturally.

    The dictionary is bound to its snapshot. Applying a dictionary from a
    different run would put the wrong real names into a client-facing report, so
    a mismatch is a hard failure, not a warning. Override with -IgnoreSnapshot
    only when you know the two runs describe the same tenant objects.

.PARAMETER Path
    File(s) to re-hydrate: markdown, HTML, JSON, CSV or plain text.

.PARAMETER Names
    Path to raw/names.json.

.PARAMETER InPlace
    Overwrite the input file instead of writing <name>.named.<ext>.

.EXAMPLE
    pwsh ./scripts/Restore-CapNames.ps1 -Path ./ca-review.md -Names ./output/20260728-091141/raw/names.json

.EXAMPLE
    pwsh ./scripts/Restore-CapNames.ps1 -Path ./review/*.html -Names ./output/latest/raw/names.json -InPlace
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)][string[]]$Path,
    [Parameter(Mandatory)][string]$Names,
    [string]$Snapshot,
    [switch]$InPlace,
    [switch]$IgnoreSnapshot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modules = Join-Path $PSScriptRoot 'modules'
Import-Module (Join-Path $modules 'CapCommon.psm1') -Force
Import-Module (Join-Path $modules 'CapNames.psm1') -Force

$dictionary = Import-CapNameDictionary -Path $Names
if (-not $dictionary) { throw "Name dictionary not found: $Names" }

$dictSnapshot = "$($dictionary['snapshot'])"
if ($Snapshot -and -not $IgnoreSnapshot -and $dictSnapshot -and $Snapshot -ne $dictSnapshot) {
    throw "Dictionary belongs to snapshot '$dictSnapshot' but '$Snapshot' was expected. Re-hydrating with the wrong dictionary would put incorrect names into the report. Use -IgnoreSnapshot to override."
}

$targets = @()
foreach ($p in $Path) {
    $resolved = @(Resolve-Path -Path $p -ErrorAction SilentlyContinue)
    if (-not $resolved) { Write-CapLog "No file matched: $p" 'WARN'; continue }
    $targets += @($resolved | ForEach-Object { $_.Path })
}
if (-not $targets) { throw "No input files found." }

$totalUnresolved = [System.Collections.Generic.List[string]]::new()

foreach ($file in $targets) {
    $text = Get-Content -LiteralPath $file -Raw
    $restored = Restore-CapNameText -Text $text -Dictionary $dictionary

    # Anything still alias-shaped was never in the dictionary. Report it rather
    # than shipping a report with a stray USER-004 in it.
    $unresolved = @(Get-CapUnresolvedTokens -Text $restored)
    foreach ($u in $unresolved) { if (-not $totalUnresolved.Contains($u)) { $totalUnresolved.Add($u) } }

    $out = if ($InPlace) { $file } else {
        $dir = Split-Path -Parent $file
        $base = [IO.Path]::GetFileNameWithoutExtension($file)
        $ext = [IO.Path]::GetExtension($file)
        Join-Path $dir "$base.named$ext"
    }
    Set-Content -LiteralPath $out -Value $restored -Encoding utf8

    $changed = if ($restored -ne $text) { 'restored' } else { 'no tokens found' }
    Write-CapLog ("{0} -> {1} ({2})" -f (Split-Path -Leaf $file), (Split-Path -Leaf $out), $changed) 'OK'
}

if ($totalUnresolved.Count) {
    Write-CapLog ("{0} token(s) had no dictionary entry and were left as-is: {1}" -f `
        $totalUnresolved.Count, (($totalUnresolved | Select-Object -First 10) -join ', ')) 'WARN'
}
Write-CapLog "Done. Re-hydrated $($targets.Count) file(s) from $($dictionary['count']) dictionary entries." 'OK'
