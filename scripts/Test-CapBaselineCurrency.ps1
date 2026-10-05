#Requires -Version 7.0
<#
.SYNOPSIS
    Compare the packaged CISA SCuBA control revisions with the current upstream
    Entra ID baseline.

.DESCRIPTION
    Maintenance-only network check. Normal CAPVisualizer tenant runs never call
    this script and remain fully offline after collection.
#>
[CmdletBinding()]
param(
    [string]$BaselinePath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'assets/reference/baselines/cisa-scuba-aad.json'),
    [string]$SourceUri = 'https://raw.githubusercontent.com/cisagov/ScubaGear/main/PowerShell/ScubaGear/baselines/aad.md',
    [string]$SourcePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$pack = Get-Content -LiteralPath $BaselinePath -Raw | ConvertFrom-Json -Depth 30 -AsHashtable
$markdown = if ($SourcePath) {
    Get-Content -LiteralPath $SourcePath -Raw
} else {
    (Invoke-WebRequest -Uri $SourceUri -UseBasicParsing).Content
}

$upstream = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($match in [regex]::Matches($markdown, '(?m)^#### (MS\.AAD\.\d+\.\d+v\d+)\s*$')) {
    [void]$upstream.Add($match.Groups[1].Value)
}
$packaged = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($control in @($pack['controls'])) { [void]$packaged.Add("$($control['sourceControlId'])") }

$missing = @($upstream | Where-Object { -not $packaged.Contains($_) } | Sort-Object)
$stale = @($packaged | Where-Object { -not $upstream.Contains($_) } | Sort-Object)
if ($missing.Count -or $stale.Count) {
    throw "SCuBA baseline drift detected. Missing/current upstream: $($missing -join ', '); stale/local: $($stale -join ', ')"
}

[pscustomobject]@{
    Valid            = $true
    BaselineVersion  = "$($pack['baselineVersion'])"
    SourceCommit     = "$($pack['sourceCommit'])"
    ControlCount     = $packaged.Count
}
