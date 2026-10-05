#Requires -Version 7.0
<#
.SYNOPSIS
    Run CAPVisualizer from a scheduler with overlap protection and credential
    file permission checks.
#>
[CmdletBinding(DefaultParameterSetName = 'Thumbprint')]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory, ParameterSetName = 'Thumbprint')][string]$CertificateThumbprint,
    [Parameter(Mandatory, ParameterSetName = 'File')][string]$CertificatePath,
    [string]$OutputRoot = (Join-Path (Split-Path -Parent $PSScriptRoot) 'output')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($PSCmdlet.ParameterSetName -eq 'File') {
    $CertificatePath = (Resolve-Path -LiteralPath $CertificatePath -ErrorAction Stop).Path
    if (-not $IsWindows) {
        $mode = [IO.File]::GetUnixFileMode($CertificatePath)
        $unsafe = [IO.UnixFileMode]::GroupRead -bor [IO.UnixFileMode]::GroupWrite -bor
            [IO.UnixFileMode]::GroupExecute -bor [IO.UnixFileMode]::OtherRead -bor
            [IO.UnixFileMode]::OtherWrite -bor [IO.UnixFileMode]::OtherExecute
        if (($mode -band $unsafe) -ne 0) {
            throw "Certificate PFX permissions are too broad ($mode). Restrict it to the scheduler identity, for example: chmod 600 '$CertificatePath'."
        }
    }
}

New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
$lockPath = Join-Path (Resolve-Path -LiteralPath $OutputRoot).Path '.capvisualizer.lock'
$lock = $null
try {
    try {
        $lock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    }
    catch [IO.IOException] {
        throw "Another CAPVisualizer scheduled run already holds the lock: $lockPath"
    }

    $invoke = Join-Path $PSScriptRoot 'Invoke-CapVisualizer.ps1'
    $args = @{
        TenantId    = $TenantId
        ClientId    = $ClientId
        OutputRoot  = $OutputRoot
        Delta       = $true
        NoTranscript= $true
    }
    if ($PSCmdlet.ParameterSetName -eq 'File') { $args['CertificatePath'] = $CertificatePath }
    else { $args['CertificateThumbprint'] = $CertificateThumbprint }
    & $invoke @args
}
finally {
    if ($lock) { $lock.Dispose() }
}
