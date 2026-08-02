<#
.SYNOPSIS
    CAPVisualizer visualization module. Renders a single self-contained,
    offline HTML file (no CDN / no external requests) from the friendly policy
    set, summary, findings, and optional delta.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-CapVisual {
<#
.SYNOPSIS
    Write a self-contained index.html into the given output folder.

.PARAMETER FriendlyPolicies
    Array of friendly policy objects (see CapReport\ConvertTo-CapFriendlyPolicy).

.PARAMETER Summary
    Summary object (see CapReport\New-CapSummary).

.PARAMETER Findings
    Hygiene findings array.

.PARAMETER Delta
    Optional delta object (see CapDelta\Compare-CapExport).

.PARAMETER SafeBundle
    Verified name-free review bundle to embed behind the "Export safely" button.
    Omit it and the button is hidden.

.PARAMETER SnapshotName
    Snapshot stamp, used to name the exported file.

.PARAMETER AssetsPath
    Folder containing template.html, styles.css, app.js.

.PARAMETER OutputFile
    Destination .html path.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$FriendlyPolicies,
        [Parameter(Mandatory)]$Summary,
        [Parameter(Mandatory)]$Findings,
        $Delta,
        $RiskFindings,
        $Audit,
        $Compliance,
        $TestResult,
        $AuthMethods,
        [hashtable]$NameMap = @{},
        $SafeBundle,
        [string]$SnapshotName = '',
        [Parameter(Mandatory)][string]$AssetsPath,
        [Parameter(Mandatory)][string]$OutputFile,
        [string]$Title = 'CAPVisualizer'
    )

    $template = Get-Content -LiteralPath (Join-Path $AssetsPath 'template.html') -Raw
    $styles   = Get-Content -LiteralPath (Join-Path $AssetsPath 'styles.css')    -Raw
    $appJs    = Get-Content -LiteralPath (Join-Path $AssetsPath 'app.js')        -Raw

    $data = [ordered]@{
        policies     = @($FriendlyPolicies)
        summary      = $Summary
        findings     = @($Findings)
        delta        = $Delta
        riskFindings = if ($RiskFindings) { @($RiskFindings) } else { @() }
        audit        = $Audit
        compliance   = $Compliance
        test         = $TestResult
        authMethods  = $AuthMethods
        nameMap      = $NameMap
    }
    # Embed as JSON. Escape </script to keep the inline <script> intact.
    $dataJson = ($data | ConvertTo-Json -Depth 30) -replace '</script', '<\/script'

    # The shareable payload behind "Export safely". It is embedded rather than
    # regenerated in the browser so the file the user shares is byte-for-byte the
    # one PowerShell built. The HTML itself holds real names, so carrying a
    # policies-only copy adds no exposure.
    $safeJson = 'null'
    if ($SafeBundle) {
        $safeJson = ($SafeBundle | ConvertTo-Json -Depth 30) -replace '</script', '<\/script'
    }

    $tenant = if ($Summary.tenantId) { $Summary.tenantId } else { 'unknown' }
    $html = $template.
        Replace('__TITLE__', $Title).
        Replace('__STYLES__', $styles).
        Replace('__APP_JS__', $appJs).
        Replace('__DATA_JSON__', $dataJson).
        Replace('__SAFE_JSON__', $safeJson).
        Replace('__SNAPSHOT__', $SnapshotName).
        Replace('__TENANT__', [string]$tenant).
        Replace('__GENERATED__', [string]$Summary.generatedUtc).
        Replace('__POLICYCOUNT__', [string]$Summary.totalPolicies)

    $OutputFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputFile)
    $dir = Split-Path -Parent $OutputFile
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    [System.IO.File]::WriteAllText($OutputFile, $html, [System.Text.UTF8Encoding]::new($false))
    Write-CapLog "Visualization written: $OutputFile" 'OK'
}

Export-ModuleMember -Function New-CapVisual
