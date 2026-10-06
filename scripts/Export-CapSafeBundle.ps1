<#
.SYNOPSIS
    Assemble the bundle that is safe to hand to a cloud service or AI assistant,
    and prove it: every artifact is verified against the local name dictionary
    before the folder is declared clean.

.DESCRIPTION
    Builds the same canonical, allowlisted review JSON used by the report's
    "Export safely" button. Only classified policy analysis is included;
    per-user authentication-method details, assertions, and unknown future
    sections remain local.

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
$originalDictPath = if ($Names) { (Resolve-Path -LiteralPath $Names).Path } else { Join-Path $snapshot 'raw/names.json' }
$dictPath = $originalDictPath
if ($pseudonymize) {
    # The run-time dictionary holds names only; the aliases that remove the last
    # tenant-correlatable ids are added now and persisted, so Restore-CapNames
    # can still resolve them after the review comes back.
    $exportDoc = Get-Content -LiteralPath $exportFile -Raw | ConvertFrom-Json -Depth 30 -AsHashtable
    $beforeAliasCount = if ($dictionary.Contains('idAliases') -and $dictionary['idAliases']) { $dictionary['idAliases'].Count } else { 0 }
    $dictionary = Add-CapIdAliases -Dictionary $dictionary -Source $exportDoc
    $afterAliasCount = if ($dictionary.Contains('idAliases') -and $dictionary['idAliases']) { $dictionary['idAliases'].Count } else { 0 }
    # Never modify the snapshot's original dictionary after its manifest was
    # generated. A legacy snapshot that lacks aliases gets a separate local-only
    # review dictionary for restoring returned reports.
    if ($afterAliasCount -gt $beforeAliasCount) {
        $dictPath = Join-Path $snapshot 'raw/names.review.json'
        Save-CapJson -InputObject $dictionary -Path $dictPath
    }
}

$safeDir = if ($OutputPath) { $OutputPath } else { Join-Path $snapshot 'safe' }
if (Test-Path -LiteralPath $safeDir) {
    if (-not $Force) { throw "Safe bundle already exists: $safeDir (use -Force to replace)." }
    Remove-Item -LiteralPath $safeDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $safeDir | Out-Null

$bundleExport = Get-Content -LiteralPath $exportFile -Raw | ConvertFrom-Json -Depth 30 -AsHashtable
$bundleAnalysis = [ordered]@{}
foreach ($sec in @{ 'audit.json' = 'audit'; 'findings.json' = 'findings'; 'compliance.json' = 'compliance';
                    'authmethods.json' = 'authMethods'; 'consolidation.json' = 'consolidation'; 'tests.json' = 'tests' }.GetEnumerator()) {
    $f = Join-Path $snapshot "analysis/$($sec.Key)"
    if (Test-Path -LiteralPath $f) {
        $bundleAnalysis[$sec.Value] = Get-Content -LiteralPath $f -Raw | ConvertFrom-Json -Depth 30 -AsHashtable
    }
}
$policyOnly = New-CapPolicyOnlyExport -Export $bundleExport -Snapshot (Split-Path -Leaf $snapshot) -Analysis $bundleAnalysis
$reviewBundle = New-CapSafeReviewBundle -SafeExport $policyOnly -Dictionary $dictionary `
    -Snapshot (Split-Path -Leaf $snapshot) -NoPseudonymize:$NoPseudonymize
$bindingToken = Get-CapBindingToken -Dictionary $dictionary
$bundleName = "cap-safe-review-$(Split-Path -Leaf $snapshot).json"
Save-CapJson -InputObject $reviewBundle -Path (Join-Path $safeDir $bundleName)

$requirePseudo = $pseudonymize -and [bool](& { $v = $dictionary['pseudonymized']; $v })
$files = @((Join-Path $safeDir $bundleName))
$violations = @(Test-CapNameLeak -Dictionary $dictionary -Path $files -RequirePseudonymized:$requirePseudo)

if ($violations.Count) {
    Remove-Item -LiteralPath $safeDir -Recurse -Force
    Write-CapLog "Leak test FAILED - the bundle was deleted and must not be uploaded." 'ERROR'
    foreach ($v in ($violations | Select-Object -First 20)) {
        Write-CapLog ("  {0}: {1} (in {2})" -f $v.kind, $v.value, (Split-Path -Leaf $v.source)) 'ERROR'
        if ($v.context) { Write-CapLog ("      matched: {0}" -f $v.context) 'ERROR' }
    }
    throw "Safe bundle rejected: $($violations.Count) leak(s) detected."
}

$readme = @"
CAPVisualizer safe bundle
=========================

Snapshot : $(Split-Path -Leaf $snapshot)
Created  : $((Get-Date).ToUniversalTime().ToString('o'))
Mode     : $(if ($requirePseudo) { 'pseudonymized (object ids aliased)' } else { 'names removed (object ids retained)' })
Binding  : $bindingToken

$bundleName is everything below merged into one file - the same artifact the
report's "Export safely" button produces. Share just that if you prefer.

BINDING - keep this token with the review. Ask the reviewer or model to include
the line "$bindingToken" verbatim in the report it returns. Restore-CapNames.ps1
refuses to re-hydrate a report whose token does not match this bundle's
dictionary, which is what stops one tenant's report being named from another
tenant's dictionary.

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
  pwsh ./scripts/Restore-CapNames.ps1 -Path ./ca-review.md -Names $dictPath
"@
Set-Content -LiteralPath (Join-Path $safeDir 'README.txt') -Value $readme -Encoding utf8

Write-CapLog "Safe bundle verified clean: $safeDir" 'OK'
Write-CapLog ("  Canonical review JSON plus README; dictionary held back ({0} entries)." -f $dictionary['count']) 'INFO'
Write-CapLog "  Upload only the safe folder. Keep the review dictionary, report/ and visual/ local." 'INFO'
