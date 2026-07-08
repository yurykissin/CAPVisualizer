<#
.SYNOPSIS
    Resolve which Conditional Access policies apply to a principal, and why,
    against a CAPVisualizer snapshot or export JSON. READ-ONLY and fully offline.

.DESCRIPTION
    Loads an export (snapshot folder or export.json), normalizes the policies,
    and evaluates per-user scope for the given principal id: InScopeDirect,
    InScopeVia (naming the group/role), Excluded (naming the excluder), or
    NotInScope. Prints a table and optionally writes JSON/CSV.

.PARAMETER FromJson
    Path to a CAPVisualizer snapshot folder, raw/export.json, or export.json.

.PARAMETER PrincipalId
    Object id (GUID) of the user to resolve.

.PARAMETER OutJson
    Optional path to write the full result as JSON.

.PARAMETER OutCsv
    Optional path to write the per-policy results as CSV.

.EXAMPLE
    pwsh ./scripts/Get-CapUserScope.ps1 -FromJson ./output/20260220-090000 -PrincipalId 2222...-2222
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$FromJson,
    [Parameter(Mandatory)][string]$PrincipalId,
    [string]$OutJson,
    [string]$OutCsv
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modules = Join-Path $PSScriptRoot 'modules'
Import-Module (Join-Path $modules 'CapCommon.psm1')    -Force
Import-Module (Join-Path $modules 'CapExport.psm1')    -Force
Import-Module (Join-Path $modules 'CapNormalize.psm1') -Force
Import-Module (Join-Path $modules 'CapScope.psm1')     -Force

$export = Import-CapExportJson -Path $FromJson
$gm = Get-CapAppGroupingMap
$norm = @($export.policies | ForEach-Object { ConvertTo-CapNormalizedPolicy -Policy $_ -AppGroupingMap $gm })
$enrichment = if ($export.Contains('enrichment')) { $export['enrichment'] } else { $null }

$scope = Resolve-CapScope -PrincipalId $PrincipalId -NormalizedPolicies $norm -Enrichment $enrichment

Write-CapLog ("Principal: {0} ({1})" -f $scope.principal.displayName, $scope.principal.id) 'OK'
if (@($scope.principal.warnings).Count) { foreach ($w in $scope.principal.warnings) { Write-CapLog $w 'WARN' } }
Write-CapLog ("InScopeDirect={0} InScopeVia={1} Excluded={2} NotInScope={3}" -f `
    $scope.counts.inScopeDirect, $scope.counts.inScopeVia, $scope.counts.excluded, $scope.counts.notInScope) 'INFO'

$scope.results |
    ForEach-Object { [pscustomobject]@{ Policy = $_.policyName; State = $_.state; Bucket = $_.bucket; Via = $_.via; Reason = $_.reason } } |
    Format-Table -AutoSize | Out-Host

if ($OutJson) { Save-CapJson -InputObject $scope -Path $OutJson; Write-CapLog "Wrote $OutJson" 'OK' }
if ($OutCsv) {
    $scope.results | ForEach-Object { [pscustomobject]$_ } | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
    Write-CapLog "Wrote $OutCsv" 'OK'
}
