<#
.SYNOPSIS
    CAPVisualizer entry point. Exports all Conditional Access policies from your
    Microsoft Entra tenant and produces JSON + CSV reports and an offline HTML
    visualization. READ-ONLY: makes no changes to the tenant.

.DESCRIPTION
    Runs entirely locally. All Microsoft Graph calls are reads against your own
    tenant. Nothing is uploaded to any third party. Each run writes an immutable,
    timestamped snapshot under output/.

.PARAMETER OutputRoot
    Root folder for snapshots. Default: ./output

.PARAMETER TenantId
    Tenant id/domain (required for app-based auth).

.PARAMETER ClientId
    App registration id (enables app-based / unattended auth).

.PARAMETER CertificateThumbprint
    Certificate thumbprint for app-based auth (preferred over a secret).

.PARAMETER ClientSecret
    Client secret (SecureString) for app-based auth. Certificate is preferred.

.PARAMETER Scopes
    Delegated scopes for interactive sign-in. Default: Policy.Read.All.

.PARAMETER ResolveNames
    Resolve object GUIDs to display names. Requires additional read-only scopes
    (Directory.Read.All). Off by default to keep the permission footprint minimal.

.PARAMETER Redact
    Replace tenant id and object GUIDs with stable pseudonyms so the output can be
    shared externally.

.PARAMETER Delta
    Compare this run against the most recent previous snapshot (or -BaselinePath).

.PARAMETER BaselinePath
    Explicit baseline snapshot folder for the delta comparison.

.PARAMETER NoVisual
    Skip HTML visualization generation.

.PARAMETER NoTranscript
    Do not write a PowerShell transcript into the snapshot folder.

.EXAMPLE
    pwsh ./scripts/Invoke-CapVisualizer.ps1
    Interactive sign-in, export + report + visualization.

.EXAMPLE
    pwsh ./scripts/Invoke-CapVisualizer.ps1 -ResolveNames -Delta
    Resolve names and diff against the previous run.

.EXAMPLE
    pwsh ./scripts/Invoke-CapVisualizer.ps1 -TenantId contoso.com -ClientId <appId> -CertificateThumbprint <thumb> -Delta
    Unattended run using an app registration with certificate auth.
#>
[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param(
    [string]$OutputRoot = (Join-Path (Split-Path -Parent $PSScriptRoot) 'output'),

    [Parameter(ParameterSetName = 'Interactive')]
    [string[]]$Scopes = @('Policy.Read.All'),

    [Parameter(Mandatory, ParameterSetName = 'AppCert')]
    [Parameter(Mandatory, ParameterSetName = 'AppSecret')]
    [string]$TenantId,

    [Parameter(Mandatory, ParameterSetName = 'AppCert')]
    [Parameter(Mandatory, ParameterSetName = 'AppSecret')]
    [string]$ClientId,

    [Parameter(Mandatory, ParameterSetName = 'AppCert')]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory, ParameterSetName = 'AppSecret')]
    [System.Security.SecureString]$ClientSecret,

    [switch]$ResolveNames,
    [switch]$Redact,
    [switch]$Delta,
    [string]$BaselinePath,
    [switch]$NoVisual,
    [switch]$NoTranscript
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modules = Join-Path $PSScriptRoot 'modules'
Import-Module (Join-Path $modules 'CapCommon.psm1') -Force
Import-Module (Join-Path $modules 'CapExport.psm1') -Force
Import-Module (Join-Path $modules 'CapReport.psm1') -Force
Import-Module (Join-Path $modules 'CapVisual.psm1') -Force
Import-Module (Join-Path $modules 'CapDelta.psm1')  -Force

$assetsPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'assets'

# --- Snapshot folder ---
$stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
$snapshot = Join-Path $OutputRoot $stamp
foreach ($sub in 'raw', 'report', 'visual') { New-Item -ItemType Directory -Force -Path (Join-Path $snapshot $sub) | Out-Null }
Write-CapLog "Snapshot: $snapshot" 'INFO'

$transcriptPath = Join-Path $snapshot 'transcript.txt'
if (-not $NoTranscript) { Start-Transcript -Path $transcriptPath -Force | Out-Null }

function Protect-CapObject {
    # Redact: replace tenant id + object GUIDs with stable pseudonyms.
    param($Object)
    $json = $Object | ConvertTo-Json -Depth 30
    $map = @{}
    $counter = [ref]0
    $guidRegex = [regex]'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    $json = $guidRegex.Replace($json, {
        param($m)
        $v = $m.Value.ToLowerInvariant()
        if (-not $map.ContainsKey($v)) { $counter.Value++; $map[$v] = ('redacted-{0:d4}' -f $counter.Value) }
        $map[$v]
    })
    return $json | ConvertFrom-Json -Depth 30 -AsHashtable
}

try {
    # --- Connect ---
    switch ($PSCmdlet.ParameterSetName) {
        'AppCert'   { Connect-CapGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint | Out-Null }
        'AppSecret' { Connect-CapGraph -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret | Out-Null }
        default     { Connect-CapGraph -Scopes $Scopes | Out-Null }
    }

    # --- Export ---
    $export = Get-CapExport

    # --- Name / location maps ---
    $nameMap = @{}
    if ($ResolveNames) {
        Write-CapLog "Resolving object names (requires Directory.Read.All)..." 'INFO'
        $ids = Get-CapReferencedIds -Export $export
        if ($ids.Count) { $nameMap = Get-CapDirectoryNameMap -Ids $ids }
        Write-CapLog "Resolved $($nameMap.Count) of $($ids.Count) object ids." 'OK'
    }
    $locationMap = @{}
    foreach ($nl in $export.namedLocations) { if ($nl.id) { $locationMap[$nl.id] = $nl.displayName } }

    # --- Friendly / report ---
    $friendly = @($export.policies | ForEach-Object { ConvertTo-CapFriendlyPolicy -Policy $_ -NameMap $nameMap -LocationMap $locationMap })
    $findings = Get-CapHygieneFindings -FriendlyPolicies $friendly
    $summary  = New-CapSummary -Export $export -FriendlyPolicies $friendly -Findings $findings

    # --- Redact (optional) ---
    if ($Redact) {
        Write-CapLog "Redacting tenant id and object GUIDs..." 'WARN'
        $export.metadata.tenantId = 'REDACTED'
        $export.metadata.account  = 'REDACTED'
        $summary.tenantId = 'REDACTED'
        $export   = Protect-CapObject -Object $export
        $friendly = @(Protect-CapObject -Object $friendly)
    }

    # --- Write raw + report ---
    Save-CapJson -InputObject $export   -Path (Join-Path $snapshot 'raw/export.json')
    Save-CapJson -InputObject $friendly -Path (Join-Path $snapshot 'report/policies.json')
    Save-CapJson -InputObject $summary  -Path (Join-Path $snapshot 'report/summary.json')
    Save-CapJson -InputObject $findings -Path (Join-Path $snapshot 'report/findings.json')

    $csvRows = @($friendly | ForEach-Object { ConvertTo-CapCsvRow -Friendly $_ })
    if ($csvRows) { $csvRows | Export-Csv -Path (Join-Path $snapshot 'report/policies.csv') -NoTypeInformation -Encoding UTF8 }
    if ($findings) { $findings | ForEach-Object { [pscustomobject]$_ } | Export-Csv -Path (Join-Path $snapshot 'report/findings.csv') -NoTypeInformation -Encoding UTF8 }

    Write-CapLog "Reports written to $snapshot/report" 'OK'

    # --- Delta ---
    $delta = $null
    if ($Delta) {
        $base = $BaselinePath
        if (-not $base) {
            $prev = Get-ChildItem -Path $OutputRoot -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -ne $snapshot -and (Test-Path (Join-Path $_.FullName 'raw/export.json')) } |
                Sort-Object Name -Descending | Select-Object -First 1
            if ($prev) { $base = $prev.FullName }
        }
        if ($base) {
            $baseFile = if (Test-Path -LiteralPath $base -PathType Container) { Join-Path $base 'raw/export.json' } else { $base }
            Write-CapLog "Computing delta against $baseFile" 'INFO'
            $baseline = Get-Content -LiteralPath $baseFile -Raw | ConvertFrom-Json -Depth 30 -AsHashtable
            $delta = Compare-CapExport -Baseline $baseline -Current ($export)
            New-Item -ItemType Directory -Force -Path (Join-Path $snapshot 'delta') | Out-Null
            Save-CapJson -InputObject $delta -Path (Join-Path $snapshot 'delta/delta.json')
            Write-CapLog ("Delta: {0} added, {1} removed, {2} modified." -f $delta.addedCount, $delta.removedCount, $delta.modifiedCount) 'OK'
        }
        else {
            Write-CapLog "No previous snapshot found for delta; skipping." 'WARN'
        }
    }

    # --- Visualization ---
    if (-not $NoVisual) {
        New-CapVisual -FriendlyPolicies $friendly -Summary $summary -Findings $findings -Delta $delta `
            -AssetsPath $assetsPath -OutputFile (Join-Path $snapshot 'visual/index.html')
    }

    # --- Manifest (integrity hashes; no secrets) ---
    $files = Get-ChildItem -Path $snapshot -Recurse -File | Where-Object { $_.Name -ne 'manifest.json' -and $_.Name -ne 'transcript.txt' }
    $manifest = [ordered]@{
        tool         = 'CAPVisualizer'
        snapshot     = $stamp
        generatedUtc = $summary.generatedUtc
        tenantId     = $summary.tenantId
        resolveNames = [bool]$ResolveNames
        redacted     = [bool]$Redact
        files        = @($files | ForEach-Object {
            [ordered]@{ path = ($_.FullName.Substring($snapshot.Length + 1) -replace '\\', '/'); sha256 = (Get-CapFileSha256 -Path $_.FullName); bytes = $_.Length }
        })
    }
    Save-CapJson -InputObject $manifest -Path (Join-Path $snapshot 'manifest.json')

    Write-CapLog "Done. Open: $(Join-Path $snapshot 'visual/index.html')" 'OK'
}
finally {
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
    if (-not $NoTranscript) { try { Stop-Transcript | Out-Null } catch { } }
}
