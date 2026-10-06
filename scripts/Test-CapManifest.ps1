#Requires -Version 7.0
<#
.SYNOPSIS
    Verify a CAPVisualizer snapshot against its integrity manifest.

.DESCRIPTION
    Checks every listed file for presence, size, and SHA-256; reports unexpected
    files; optionally verifies the manifest HMAC and an externally recorded
    SHA-256 of manifest.json. Throws if any check fails.

.PARAMETER SnapshotPath
    Snapshot directory containing manifest.json.

.PARAMETER ManifestKey
    SecureString key used when the snapshot was created with -ManifestKey.

.PARAMETER ExpectedManifestHash
    Optional out-of-band SHA-256 recorded when the snapshot was generated.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)][string]$SnapshotPath,
    [securestring]$ManifestKey,
    [ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedManifestHash
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modules = Join-Path $PSScriptRoot 'modules'
Import-Module (Join-Path $modules 'CapCommon.psm1') -Force

$snapshot = (Resolve-Path -LiteralPath $SnapshotPath).Path
$manifestPath = Join-Path $snapshot 'manifest.json'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw "manifest.json not found in snapshot: $snapshot"
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -Depth 30 -AsHashtable
$issues = [System.Collections.Generic.List[string]]::new()
$expectedPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($entry in @($manifest['files'])) {
    $relative = "$($entry['path'])"
    if (-not $relative -or [IO.Path]::IsPathRooted($relative) -or $relative -match '(^|/)\.\.(/|$)') {
        $issues.Add("Invalid manifest path: $relative")
        continue
    }
    if (-not $expectedPaths.Add($relative)) {
        $issues.Add("Duplicate manifest path: $relative")
        continue
    }
    $fullPath = Join-Path $snapshot ($relative -replace '/', [IO.Path]::DirectorySeparatorChar)
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        $issues.Add("Missing file: $relative")
        continue
    }
    $file = Get-Item -LiteralPath $fullPath
    if ([long]$entry['bytes'] -ne $file.Length) { $issues.Add("Size mismatch: $relative") }
    $actualHash = Get-CapFileSha256 -Path $fullPath
    if ("$($entry['sha256'])" -ne $actualHash) { $issues.Add("SHA-256 mismatch: $relative") }
}

foreach ($file in Get-ChildItem -LiteralPath $snapshot -Recurse -File) {
    $relative = ($file.FullName.Substring($snapshot.Length + 1) -replace '\\', '/')
    if ($relative -in @('manifest.json', 'transcript.txt')) { continue }
    if (-not $expectedPaths.Contains($relative)) { $issues.Add("Unexpected file: $relative") }
}

if ($ExpectedManifestHash) {
    $actualManifestHash = Get-CapFileSha256 -Path $manifestPath
    if ($actualManifestHash -ne $ExpectedManifestHash.ToLowerInvariant()) {
        $issues.Add('Manifest SHA-256 does not match the external anchor.')
    }
}

$integrity = $manifest['integrity']
$recordedHmac = if ($integrity -and $integrity.Contains('hmacSha256')) { "$($integrity['hmacSha256'])" } else { '' }
if ($recordedHmac) {
    if (-not $ManifestKey) {
        $issues.Add('Manifest contains an HMAC but no -ManifestKey was supplied.')
    }
    else {
        $hashList = ((@($manifest['files']) | ForEach-Object { "$($_['path']):$($_['sha256'])" }) -join "`n")
        $plainManifestKey = [System.Net.NetworkCredential]::new('', $ManifestKey).Password
        $hmac = [System.Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($plainManifestKey))
        try {
            $actualHmac = -join ($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($hashList)) | ForEach-Object { $_.ToString('x2') })
        }
        finally {
            $hmac.Dispose()
            $plainManifestKey = $null
        }
        if ($actualHmac -ne $recordedHmac) { $issues.Add('Manifest HMAC verification failed.') }
    }
}
elseif ($ManifestKey) {
    $issues.Add('A -ManifestKey was supplied, but the manifest has no HMAC.')
}

if ($issues.Count) {
    throw "Manifest verification failed with $($issues.Count) issue(s): $($issues -join '; ')"
}

[pscustomobject]@{
    Snapshot           = $snapshot
    FileCount          = $expectedPaths.Count
    ManifestHash       = Get-CapFileSha256 -Path $manifestPath
    HmacVerified       = [bool]$recordedHmac
    ExternalAnchorUsed = [bool]$ExpectedManifestHash
    Valid              = $true
}
