<#
.SYNOPSIS
    Helper to schedule periodic CAPVisualizer runs locally.

.DESCRIPTION
    Generates the appropriate scheduler entry for your OS:
      - macOS / Linux: prints a crontab line (and can install it with -Apply).
      - Windows: registers a Scheduled Task via ScheduledTasks module.

    Unattended periodic runs require app-based auth (ClientId +
    CertificateThumbprint). Interactive sign-in cannot run unattended.

.PARAMETER TenantId
    Tenant id/domain for the scheduled unattended run.

.PARAMETER ClientId
    App registration id for the scheduled unattended run.

.PARAMETER CertificateThumbprint
    Certificate thumbprint for app-based auth.

.PARAMETER Time
    Time of day HH:mm for the daily run. Default 03:00.

.PARAMETER Apply
    Actually install the schedule (otherwise just prints what it would do).

.EXAMPLE
    pwsh ./scripts/Register-CapSchedule.ps1 -TenantId contoso.com -ClientId <id> -CertificateThumbprint <thumb> -Time 02:30

.EXAMPLE
    pwsh ./scripts/Register-CapSchedule.ps1 -TenantId contoso.com -ClientId <id> -CertificateThumbprint <thumb> -Apply
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory)][string]$CertificateThumbprint,
    [ValidatePattern('^\d{2}:\d{2}$')][string]$Time = '03:00',
    [switch]$Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$pwsh = (Get-Process -Id $PID).Path
if (-not $pwsh) { $pwsh = 'pwsh' }
$script = Join-Path $PSScriptRoot 'Invoke-CapVisualizer.ps1'
$hh, $mm = $Time.Split(':')

$argLine = "-NoProfile -File `"$script`" -TenantId `"$TenantId`" -ClientId `"$ClientId`" -CertificateThumbprint `"$CertificateThumbprint`" -Delta -NoTranscript"

if ($IsWindows) {
    Write-Host "Windows Scheduled Task 'CAPVisualizer-Daily' at ${Time}:" -ForegroundColor Cyan
    Write-Host "$pwsh $argLine"
    if ($Apply) {
        $action  = New-ScheduledTaskAction -Execute $pwsh -Argument $argLine
        $trigger = New-ScheduledTaskTrigger -Daily -At $Time
        Register-ScheduledTask -TaskName 'CAPVisualizer-Daily' -Action $action -Trigger $trigger -Description 'Daily read-only Conditional Access export' -Force | Out-Null
        Write-Host "Scheduled task registered." -ForegroundColor Green
    }
    else {
        Write-Host "(dry run - re-run with -Apply to register the task)" -ForegroundColor Yellow
    }
}
else {
    $cronLine = "$([int]$mm) $([int]$hh) * * * $pwsh $argLine >> `"$(Join-Path (Split-Path -Parent $PSScriptRoot) 'output/cron.log')`" 2>&1"
    Write-Host "Crontab line (daily at $Time):" -ForegroundColor Cyan
    Write-Host $cronLine
    if ($Apply) {
        $existing = (crontab -l 2>/dev/null) -split "`n" | Where-Object { $_ -and $_ -notmatch 'Invoke-CapVisualizer\.ps1' }
        $new = @($existing + $cronLine | Where-Object { $_ }) -join "`n"
        $new + "`n" | crontab -
        Write-Host "Crontab updated." -ForegroundColor Green
    }
    else {
        Write-Host "(dry run - re-run with -Apply to install, or paste the line into 'crontab -e')" -ForegroundColor Yellow
    }
}
