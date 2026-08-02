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

    Binding is automatic. A safe bundle carries a binding token
    (CAPBIND:<snapshot>:<fingerprint>) derived from the dictionary. If a report
    produced from that bundle carries a binding token that does not match this
    dictionary, re-hydration refuses and exits non-zero, naming both sides. A
    report that carries no token (for example one produced before binding
    existed) cannot be checked, so it is restored with a warning rather than
    blocked.

.PARAMETER Path
    File(s) to re-hydrate: markdown, HTML, JSON, CSV or plain text.

.PARAMETER Names
    Path to raw/names.json.

.PARAMETER InPlace
    Overwrite the input file instead of writing <name>.named.<ext>.

.PARAMETER NoRepairTruncated
    Do not attempt to recover abbreviated ids such as "007dce69-...". Off by
    default: an abbreviated id cannot be matched against the dictionary, so
    without recovery it stays a dead reference in the deliverable.

.PARAMETER IgnoreSnapshot
    Restore even when the artifact's binding token does not match the
    dictionary. Off by default. Use only when you have confirmed by hand that
    the two runs describe the same tenant objects.

.PARAMETER AllowUnresolved
    Exit 0 even when ids were left unresolved. Off by default. A partial
    restore that reports success is how a report shipped with 71 dangling
    references.

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
    [switch]$IgnoreSnapshot,
    [switch]$NoRepairTruncated,
    [switch]$AllowUnresolved
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modules = Join-Path $PSScriptRoot 'modules'
Import-Module (Join-Path $modules 'CapCommon.psm1') -Force
Import-Module (Join-Path $modules 'CapNames.psm1') -Force

# A safe bundle and its dictionary are only meaningful as a pair. The binding
# token ties one to the other without leaking anything: it is a fingerprint over
# the snapshot id and the dictionary shape, not over any name. Export stamps the
# same token into the bundle, so a report carrying a different token was produced
# from a different dictionary. Derivation must match Export-CapSafeBundle.ps1.
$script:CapBindingMarker = 'CAPBIND:[^:\s"''<>]+:[0-9a-fA-F]{8}'
function Get-CapBindingToken {
    param($Dictionary)
    if (-not $Dictionary) { return $null }
    $snap = if ($Dictionary.Contains('snapshot')) { "$($Dictionary['snapshot'])" } else { '' }
    if (-not $snap) { return $null }
    $count = if ($Dictionary.Contains('count')) { "$($Dictionary['count'])" } else { '0' }
    $pseudo = if ($Dictionary.Contains('pseudonymized')) { "$([bool]$Dictionary['pseudonymized'])".ToLowerInvariant() } else { 'false' }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$snap|$count|$pseudo"))
    }
    finally { $sha.Dispose() }
    $fp = (-join ($bytes[0..3] | ForEach-Object { $_.ToString('x2') }))
    return "CAPBIND:${snap}:${fp}"
}

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

# Refuse to re-hydrate the shareable bundle itself. That file exists precisely so
# it can leave the building with no names in it; putting the names back turns the
# one artifact designed to be safe to send into the one artifact that must never
# be sent, in a directory the user is likely to share from. Restoring is also a
# blind text substitution, so aimed at JSON it rewrites values inside string
# literals and a name containing a quote breaks the document structure outright.
# Re-hydrate the review written from the bundle, not the bundle.
$refused = @()
foreach ($file in $targets) {
    $ext = [System.IO.Path]::GetExtension($file)
    if ($ext -ne '.json') { continue }
    $head = Get-Content -LiteralPath $file -Raw
    if ($head -match '"kind"\s*:\s*"(policyOnlyExport|safeReviewBundle)"') { $refused += $file }
}
if ($refused.Count -and -not $AllowUnresolved) {
    Write-CapLog ("Refusing to restore the shareable export itself: {0}. That file is name-free by design and re-hydrating it produces a document that looks shareable but is not. Point this at the review or report written from the bundle instead. Use -AllowUnresolved if you genuinely need a local named copy." -f ($refused -join ', ')) 'ERROR'
    exit 1
}
elseif ($refused.Count) {
    Write-CapLog ("Restoring a shareable export in place because -AllowUnresolved was given: {0}. The result contains tenant names and must not be shared." -f ($refused -join ', ')) 'WARN'
}

# Automatic binding check. Scan the inputs for the binding token before writing
# anything, so a wrong-dictionary restore is refused rather than produced. A
# missing token means the artifact predates binding or the token was stripped;
# that cannot be verified, so it is a warning, not a block.
$expectedBinding = Get-CapBindingToken -Dictionary $dictionary
$foundBindings = [System.Collections.Generic.List[string]]::new()
foreach ($file in $targets) {
    $scan = Get-Content -LiteralPath $file -Raw
    foreach ($m in [regex]::Matches($scan, $script:CapBindingMarker)) {
        $tok = $m.Value
        if (-not $foundBindings.Contains($tok)) { $foundBindings.Add($tok) }
    }
}
if ($foundBindings.Count) {
    $mismatched = @($foundBindings | Where-Object { $_ -ne $expectedBinding })
    if ($mismatched.Count -and $IgnoreSnapshot) {
        Write-CapLog ("Binding mismatch overridden with -IgnoreSnapshot. Dictionary is '{0}', artifact carries {1}." -f `
            $expectedBinding, ($mismatched -join ', ')) 'WARN'
    }
    elseif ($mismatched.Count) {
        Write-CapLog ("Binding mismatch: this dictionary is '{0}' but the artifact was produced from {1}. Re-hydrating with the wrong dictionary would put incorrect names into the report. Use -IgnoreSnapshot to override." -f `
            $expectedBinding, ($mismatched -join ', ')) 'ERROR'
        exit 1
    }
    else {
        Write-CapLog ("Binding verified: artifact and dictionary both belong to {0}." -f $expectedBinding) 'OK'
    }
}
else {
    Write-CapLog "No binding token in the input; cannot confirm it was produced from this dictionary (artifact predates binding, or the token was stripped). Restoring anyway - confirm the snapshot yourself." 'WARN'
}

$totalUnresolved = [System.Collections.Generic.List[string]]::new()
$totalUnresolvedIds = [System.Collections.Generic.List[string]]::new()
$totalRepaired = [System.Collections.Generic.List[string]]::new()
$totalAmbiguous = [System.Collections.Generic.List[string]]::new()
$totalTruncated = [System.Collections.Generic.List[string]]::new()

function Add-Unique {
    param($List, $Items)
    foreach ($i in @($Items)) { if ($i -and -not $List.Contains($i)) { $List.Add($i) } }
}

foreach ($file in $targets) {
    $text = Get-Content -LiteralPath $file -Raw

    # Repair before restoring. An abbreviated id cannot match the dictionary, so
    # doing this afterwards would be too late.
    if (-not $NoRepairTruncated) {
        $repair = Resolve-CapTruncatedIds -Text $text -Dictionary $dictionary
        $text = $repair['text']
        Add-Unique $totalRepaired $repair['resolved']
        Add-Unique $totalAmbiguous $repair['ambiguous']
    }

    $restored = Restore-CapNameText -Text $text -Dictionary $dictionary

    # Anything still alias-shaped was never in the dictionary. Report it rather
    # than shipping a report with a stray USER-004 in it.
    Add-Unique $totalUnresolved (Get-CapUnresolvedTokens -Text $restored)

    # Full-length ids that survived restoration, excluding Microsoft public
    # constants. These are the references a reader cannot act on.
    Add-Unique $totalUnresolvedIds (Get-CapUnresolvedIds -Text $restored)

    # Abbreviations that could not be repaired at all.
    Add-Unique $totalTruncated (Get-CapTruncatedIds -Text $restored)

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

# Accounting. Silence here used to mean "looks fine", which it was not.
if ($totalRepaired.Count) {
    Write-CapLog ("Repaired {0} abbreviated id(s) before restoring, for example: {1}" -f `
        $totalRepaired.Count, (($totalRepaired | Select-Object -First 3) -join '; ')) 'INFO'
    Write-CapLog "Abbreviated ids are a defect in the source report, not a feature. Fix the report so ids are written in full." 'WARN'
}
if ($totalAmbiguous.Count) {
    Write-CapLog ("{0} abbreviation(s) matched more than one id and were left alone rather than guessed: {1}" -f `
        $totalAmbiguous.Count, ($totalAmbiguous -join '; ')) 'WARN'
}
if ($totalUnresolved.Count) {
    Write-CapLog ("{0} alias token(s) had no dictionary entry and were left as-is: {1}" -f `
        $totalUnresolved.Count, (($totalUnresolved | Select-Object -First 10) -join ', ')) 'WARN'
}
if ($totalTruncated.Count) {
    Write-CapLog ("{0} abbreviated id(s) remain unrecoverable: {1}" -f `
        $totalTruncated.Count, (($totalTruncated | Select-Object -First 10) -join ', ')) 'WARN'
}
if ($totalUnresolvedIds.Count) {
    Write-CapLog ("{0} id(s) did not resolve to a name and will read as raw guids: {1}" -f `
        $totalUnresolvedIds.Count, (($totalUnresolvedIds | Select-Object -First 10) -join ', ')) 'WARN'
}

$failures = $totalUnresolvedIds.Count + $totalTruncated.Count + $totalUnresolved.Count
Write-CapLog ("Done. Re-hydrated {0} file(s) from {1} dictionary entries. Repaired {2}, unresolved {3}." -f `
    $targets.Count, $dictionary['count'], $totalRepaired.Count, $failures) 'OK'

if ($failures -and -not $AllowUnresolved) {
    Write-CapLog "Exiting non-zero: the deliverable still contains references that cannot be read as names. Use -AllowUnresolved to override." 'ERROR'
    exit 1
}

# Exit explicitly on success too, so a caller always has a code to test rather
# than having to infer success from the absence of one.
exit 0
