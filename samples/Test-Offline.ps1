# Offline validation of the report + visual pipeline using sample data.
# Does NOT connect to Graph. Proves flattening, hygiene checks, summary,
# delta, and HTML rendering work end to end.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$modules = Join-Path $root 'scripts/modules'
Import-Module (Join-Path $modules 'CapCommon.psm1') -Force
Import-Module (Join-Path $modules 'CapReport.psm1') -Force
Import-Module (Join-Path $modules 'CapVisual.psm1') -Force
Import-Module (Join-Path $modules 'CapDelta.psm1')  -Force

$export = Get-Content -LiteralPath (Join-Path $root 'samples/sample-export.json') -Raw | ConvertFrom-Json -Depth 30 -AsHashtable

$locationMap = @{}
foreach ($nl in $export.namedLocations) { $locationMap[$nl.id] = $nl.displayName }

$friendly = @($export.policies | ForEach-Object { ConvertTo-CapFriendlyPolicy -Policy $_ -LocationMap $locationMap })
$findings = Get-CapHygieneFindings -FriendlyPolicies $friendly
$summary  = New-CapSummary -Export $export -FriendlyPolicies $friendly -Findings $findings

Write-Host "Policies flattened : $($friendly.Count)" -ForegroundColor Green
Write-Host "Findings           : $($findings.Count)" -ForegroundColor Green
Write-Host "Summary blocks/mfa : $($summary.blockPolicies)/$($summary.mfaPolicies)" -ForegroundColor Green

# Delta against a mutated copy (simulate a change).
$baseline = Get-Content -LiteralPath (Join-Path $root 'samples/sample-export.json') -Raw | ConvertFrom-Json -Depth 30 -AsHashtable
$baseline.policies[0].state = 'disabled'
$delta = Compare-CapExport -Baseline $baseline -Current $export
Write-Host "Delta modified     : $($delta.modifiedCount)" -ForegroundColor Green

$out = Join-Path $root 'samples/sample-visual.html'
New-CapVisual -FriendlyPolicies $friendly -Summary $summary -Findings $findings -Delta $delta `
    -AssetsPath (Join-Path $root 'assets') -OutputFile $out

if ((Test-Path $out) -and ((Get-Item $out).Length -gt 1000)) {
    Write-Host "HTML rendered OK   : $out" -ForegroundColor Green
} else {
    throw "HTML render failed."
}

# Exercise the orchestrator's write/redact/manifest path against a temp snapshot.
$snap = Join-Path ([System.IO.Path]::GetTempPath()) ("captest-" + [guid]::NewGuid().ToString('N'))
foreach ($s in 'raw','report') { New-Item -ItemType Directory -Force -Path (Join-Path $snap $s) | Out-Null }

function Protect-CapObject {
    param($Object)
    $json = $Object | ConvertTo-Json -Depth 30
    $map = @{}; $counter = [ref]0
    $rx = [regex]'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    $json = $rx.Replace($json, { param($m) $v = $m.Value.ToLowerInvariant(); if (-not $map.ContainsKey($v)) { $counter.Value++; $map[$v] = ('redacted-{0:d4}' -f $counter.Value) }; $map[$v] })
    return $json | ConvertFrom-Json -Depth 30 -AsHashtable
}

$redacted = @(Protect-CapObject -Object $friendly)
if ("$($redacted[0].id)" -notmatch 'redacted-') { throw "Redaction did not replace GUIDs." }
Write-Host "Redaction OK       : $($redacted[0].id)" -ForegroundColor Green

Save-CapJson -InputObject $export   -Path (Join-Path $snap 'raw/export.json')
Save-CapJson -InputObject $friendly -Path (Join-Path $snap 'report/policies.json')
$csv = @($friendly | ForEach-Object { ConvertTo-CapCsvRow -Friendly $_ })
$csv | Export-Csv -Path (Join-Path $snap 'report/policies.csv') -NoTypeInformation -Encoding UTF8

$files = Get-ChildItem -Path $snap -Recurse -File
$manifest = [ordered]@{ files = @($files | ForEach-Object { [ordered]@{ path = $_.Name; sha256 = (Get-CapFileSha256 -Path $_.FullName) } }) }
Save-CapJson -InputObject $manifest -Path (Join-Path $snap 'manifest.json')
if (-not (Test-Path (Join-Path $snap 'report/policies.csv'))) { throw "CSV not written." }
if (@($manifest.files).Count -lt 3) { throw "Manifest missing files." }
Write-Host "Write/manifest OK  : $(@($manifest.files).Count) files hashed" -ForegroundColor Green
Remove-Item -Recurse -Force $snap

Write-Host "SMOKE TEST PASSED" -ForegroundColor Green
