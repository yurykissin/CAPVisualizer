#Requires -Version 7.0
<#
.SYNOPSIS
    Offline what-if for CAPVisualizer: simulate a sign-in for a principal against
    an exported (enriched) policy set and print the cumulative outcome plus a
    per-policy applicability breakdown. Read-only; no tenant access.

.PARAMETER FromJson
    Path to a CAPVisualizer export JSON (schema v2.0 with enrichment recommended).

.PARAMETER PrincipalId
    Object id of the signing-in principal.

.PARAMETER Resource
    Target application id (e.g. a first-party appId).

.PARAMETER Platform / ClientApp / Location / SignInRisk / UserRisk / AuthFlow /
           DeviceState
    Optional sign-in signals. Any omitted signal that a policy gates on renders
    that policy "signal-dependent" instead of definitive.

.PARAMETER AsJson
    Emit the full result object as JSON instead of the console summary.

.EXAMPLE
    ./Invoke-CapWhatIf.ps1 -FromJson ./samples/sample-export-enriched.json `
        -PrincipalId 77777777-7777-7777-7777-777777777777 `
        -Resource 00000002-0000-0ff1-ce00-000000000000 -ClientApp browser
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$FromJson,
    [Parameter(Mandatory)][string]$PrincipalId,
    [string]$Resource,
    [ValidateSet('windows', 'macOS', 'iOS', 'android', 'linux', 'windowsPhone')][string]$Platform,
    [ValidateSet('browser', 'mobileAppsAndDesktopClients', 'exchangeActiveSync', 'other', 'modern', 'legacy')][string]$ClientApp,
    [string]$Location,
    [ValidateSet('none', 'low', 'medium', 'high')][string]$SignInRisk,
    [ValidateSet('none', 'low', 'medium', 'high')][string]$UserRisk,
    [string]$AuthFlow,
    [ValidateSet('compliant', 'managed', 'unmanaged')][string]$DeviceState,
    [switch]$AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modules = Join-Path $PSScriptRoot 'modules'
Import-Module (Join-Path $modules 'CapCommon.psm1') -Force
Import-Module (Join-Path $modules 'CapExport.psm1') -Force
Import-Module (Join-Path $modules 'CapNormalize.psm1') -Force
Import-Module (Join-Path $modules 'CapScope.psm1') -Force
Import-Module (Join-Path $modules 'CapWhatIf.psm1') -Force

$export = Import-CapExportJson -Path $FromJson
$grouping = Get-CapAppGroupingMap
$normalized = @($export.policies | ForEach-Object { ConvertTo-CapNormalizedPolicy -Policy $_ -AppGroupingMap $grouping })
$enrichment = if ($export.Contains('enrichment')) { $export.enrichment } else { $null }

$whatIfArgs = @{ PrincipalId = $PrincipalId; NormalizedPolicies = $normalized; Enrichment = $enrichment }
foreach ($p in 'Resource', 'Platform', 'ClientApp', 'Location', 'SignInRisk', 'UserRisk', 'AuthFlow', 'DeviceState') {
    if ($PSBoundParameters.ContainsKey($p)) { $whatIfArgs[$p] = $PSBoundParameters[$p] }
}

$result = Test-CapWhatIf @whatIfArgs

if ($AsJson) {
    $result | ConvertTo-Json -Depth 12
    return
}

$o = $result.outcome
Write-Host ''
Write-Host "Principal : $($result.principal.displayName) [$($result.principal.id)]"
if (@($result.principal.warnings).Count) {
    foreach ($w in $result.principal.warnings) { Write-Host "  ! $w" -ForegroundColor Yellow }
}
Write-Host "Outcome   : " -NoNewline
if ($o.blocked) { Write-Host 'BLOCKED' -ForegroundColor Red }
elseif ($o.mfaRequired) { Write-Host 'MFA required' -ForegroundColor Green }
elseif ($o.noDefinitiveEnforcement) { Write-Host 'No definitive enforcement (gap)' -ForegroundColor Yellow }
else { Write-Host 'Access allowed under other controls' }
if (@($o.grantControls).Count) { Write-Host "Controls  : $($o.grantControls -join ', ')" }
if (@($o.reportOnlyApplied).Count) { Write-Host "Report-only (would apply): $($o.reportOnlyApplied -join ', ')" -ForegroundColor DarkYellow }

Write-Host ''
Write-Host "Applied (definitive): $(@($result.definitive).Count)"
foreach ($r in $result.definitive) { Write-Host "  + $($r.policyName)  ($($r.reason))" -ForegroundColor Green }
Write-Host "Could apply (signal-dependent): $(@($result.signalDependent).Count)"
foreach ($r in $result.signalDependent) { Write-Host "  ? $($r.policyName)  -> $($r.reason)" -ForegroundColor Yellow }
Write-Host "Not applied: $(@($result.notApplied).Count)"
