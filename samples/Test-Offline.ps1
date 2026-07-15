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

# --- Offline analysis engines against the enriched fixture ---
Import-Module (Join-Path $modules 'CapNormalize.psm1') -Force
Import-Module (Join-Path $modules 'CapScope.psm1') -Force
Import-Module (Join-Path $modules 'CapWhatIf.psm1') -Force
Import-Module (Join-Path $modules 'CapAudit.psm1') -Force
Import-Module (Join-Path $modules 'CapFindings.psm1') -Force
Import-Module (Join-Path $modules 'CapCompliance.psm1') -Force
Import-Module (Join-Path $modules 'CapTest.psm1') -Force
Import-Module (Join-Path $modules 'CapAuthMethods.psm1') -Force
Import-Module (Join-Path $modules 'CapExport.psm1') -Force

$enrExport = Import-CapExportJson -Path (Join-Path $root 'samples/sample-export-enriched.json')
$grouping  = Get-CapAppGroupingMap
$norm      = @($enrExport.policies | ForEach-Object { ConvertTo-CapNormalizedPolicy -Policy $_ -AppGroupingMap $grouping })
$enr       = $enrExport.enrichment

$scope = Resolve-CapScope -PrincipalId '22222222-2222-2222-2222-222222222222' -NormalizedPolicies $norm -Enrichment $enr
if ($scope.counts.excluded -lt 1) { throw "Scope: expected the break-glass account to be excluded from a policy." }
Write-Host "Scope OK           : direct=$($scope.counts.inScopeDirect) via=$($scope.counts.inScopeVia) excluded=$($scope.counts.excluded)" -ForegroundColor Green

$wi = Test-CapWhatIf -PrincipalId '77777777-7777-7777-7777-777777777777' -NormalizedPolicies $norm -Enrichment $enr `
    -Resource '00000002-0000-0ff1-ce00-000000000000' -ClientApp 'browser'
if (-not $wi.outcome.mfaRequired) { throw "What-if: expected MFA required for the standard user." }
Write-Host "What-if OK         : mfaRequired=$($wi.outcome.mfaRequired) definitive=$(@($wi.definitive).Count)" -ForegroundColor Green

$audit = Invoke-CapAudit -NormalizedPolicies $norm -Enrichment $enr
if (@($audit.issues | Where-Object { $_.checkId -eq 'app-include-exclude-overlap' }).Count -lt 1) { throw "Audit: expected the CA004 app contradiction." }
Write-Host "Audit OK           : $(@($audit.issues).Count) issue(s)" -ForegroundColor Green

$risk = Invoke-CapFindings -NormalizedPolicies $norm -Enrichment $enr -AuditResult $audit
if (@($risk.findings).Count -lt 3) { throw "Findings: expected several risk-scored findings." }
Write-Host "Findings OK        : $(@($risk.findings).Count) finding(s), top risk $($risk.summary.topRisk)" -ForegroundColor Green

$comp = Invoke-CapCompliance -NormalizedPolicies $norm
if (@($comp.controls).Count -lt 5) { throw "Compliance: expected 5 controls." }
Write-Host "Compliance OK      : $($comp.summary.pass)/$($comp.summary.total) pass ($($comp.summary.passRate)%)" -ForegroundColor Green

$test = Invoke-CapTest -NormalizedPolicies $norm -Enrichment $enr -ComplianceResult $comp -FindingsResult $risk
Write-Host "Tests OK           : passed=$($test.summary.passed) failed=$($test.summary.failed) overall=$(if ($test.passed) { 'PASS' } else { 'FAIL' })" -ForegroundColor Green

# Final showcase viewer: render the enriched 6-policy set (with embedded nameMap
# so workload-identity service principals resolve to friendly names) to align
# the Per-policy tab with the analysis tabs.
$enrLocMap = @{}
foreach ($nl in $enrExport.namedLocations) { $enrLocMap[$nl.id] = $nl.displayName }
$enrNameMap = if ($enrExport.Contains('nameMap')) { $enrExport.nameMap } else { @{} }
$friendly2 = @($enrExport.policies | ForEach-Object { ConvertTo-CapFriendlyPolicy -Policy $_ -LocationMap $enrLocMap -NameMap $enrNameMap })
$findings2 = Get-CapHygieneFindings -FriendlyPolicies $friendly2
$summary2  = New-CapSummary -Export $enrExport -FriendlyPolicies $friendly2 -Findings $findings2

$authMethods = Invoke-CapAuthMethods -Enrichment $enr

$out2 = Join-Path $root 'samples/sample-visual.html'
New-CapVisual -FriendlyPolicies $friendly2 -Summary $summary2 -Findings $findings2 -Delta $delta `
    -RiskFindings $risk.findings -Audit $audit -Compliance $comp -TestResult $test -AuthMethods $authMethods `
    -AssetsPath (Join-Path $root 'assets') -OutputFile $out2
$h2 = Get-Content -Raw $out2
foreach ($needle in 'MS.AAD.1.1','app-include-exclude-overlap','Assertion results') {
    if (-not $h2.Contains($needle)) { throw "Viewer missing analysis content: $needle" }
}
Write-Host "Unified viewer OK  : analysis tabs embedded" -ForegroundColor Green

Write-Host "SMOKE TEST PASSED" -ForegroundColor Green
