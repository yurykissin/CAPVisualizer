<#
.SYNOPSIS
    CAPVisualizer environment doctor. Verifies PowerShell version, the required
    Microsoft.Graph.Authentication module, and (optionally) Graph reachability.

.DESCRIPTION
    Read-only checks. Makes no changes to your machine or tenant beyond an
    optional interactive sign-in if -TestConnection is supplied.

.EXAMPLE
    pwsh ./scripts/Test-Prerequisites.ps1

.EXAMPLE
    pwsh ./scripts/Test-Prerequisites.ps1 -TestConnection
#>
[CmdletBinding()]
param(
    [switch]$TestConnection,
    [switch]$Install
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ok = $true
function Report($label, $pass, $detail) {
    $mark = if ($pass) { '[PASS]' } else { '[FAIL]' }
    $color = if ($pass) { 'Green' } else { 'Red' }
    Write-Host ("{0} {1,-32} {2}" -f $mark, $label, $detail) -ForegroundColor $color
    if (-not $pass) { $script:ok = $false }
}

Write-Host "CAPVisualizer prerequisite check" -ForegroundColor Cyan
Write-Host "--------------------------------" -ForegroundColor Cyan

# 1. PowerShell 7+
$psVer = $PSVersionTable.PSVersion
Report 'PowerShell 7+' ($psVer.Major -ge 7) "found $psVer"

# 2. Microsoft.Graph.Authentication module
$mod = Get-Module -ListAvailable -Name Microsoft.Graph.Authentication |
    Sort-Object Version -Descending | Select-Object -First 1
if (-not $mod -and $Install) {
    Write-Host "Installing Microsoft.Graph.Authentication for current user..." -ForegroundColor Yellow
    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber
    $mod = Get-Module -ListAvailable -Name Microsoft.Graph.Authentication |
        Sort-Object Version -Descending | Select-Object -First 1
}
Report 'Microsoft.Graph.Authentication' ($null -ne $mod) ($mod ? "v$($mod.Version)" : 'not installed (run with -Install or: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser)')

# 3. TLS / internet path to Graph (DNS only; no auth)
try {
    $null = [System.Net.Dns]::GetHostEntry('graph.microsoft.com')
    Report 'Resolve graph.microsoft.com' $true 'DNS ok'
}
catch {
    Report 'Resolve graph.microsoft.com' $false $_.Exception.Message
}

# 4. Optional live connection test (interactive, read-only)
if ($TestConnection) {
    try {
        Import-Module (Join-Path $PSScriptRoot 'modules/CapCommon.psm1') -Force
        Connect-CapGraph -Scopes 'Policy.Read.All' | Out-Null
        $probe = Invoke-CapGraphGet -Uri 'identity/conditionalAccess/policies?$top=1&$select=id'
        Report 'Graph read (Policy.Read.All)' $true "reachable ($((@($probe)).Count) sample policy)"
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
    catch {
        Report 'Graph read (Policy.Read.All)' $false $_.Exception.Message
    }
}

Write-Host "--------------------------------" -ForegroundColor Cyan
if ($ok) {
    Write-Host "All checks passed." -ForegroundColor Green
    exit 0
}
else {
    Write-Host "One or more checks failed. See messages above." -ForegroundColor Red
    exit 1
}
