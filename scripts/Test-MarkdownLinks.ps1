#Requires -Version 7.0
<#
.SYNOPSIS
    Check local links in repository Markdown files.
#>
[CmdletBinding()]
param([string]$Root = (Split-Path -Parent $PSScriptRoot))

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$rootPath = (Resolve-Path -LiteralPath $Root).Path
$broken = [System.Collections.Generic.List[string]]::new()
foreach ($file in Get-ChildItem -LiteralPath $rootPath -Recurse -File -Filter '*.md' |
    Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' }) {
    $content = Get-Content -LiteralPath $file.FullName -Raw
    foreach ($match in [regex]::Matches($content, '!?\[[^\]]*\]\((?<target>[^)]+)\)')) {
        $target = $match.Groups['target'].Value.Trim()
        if ($target.StartsWith('<') -and $target.EndsWith('>')) { $target = $target.Substring(1, $target.Length - 2) }
        $target = ($target -split '\s+"', 2)[0]
        if (-not $target -or $target.StartsWith('#') -or $target -match '^(?i:https?|mailto):') { continue }
        $pathPart = [uri]::UnescapeDataString(($target -split '#', 2)[0])
        if (-not $pathPart) { continue }
        $candidate = if ([IO.Path]::IsPathRooted($pathPart)) {
            Join-Path $rootPath $pathPart.TrimStart('/', '\')
        } else {
            Join-Path $file.DirectoryName $pathPart
        }
        if (-not (Test-Path -LiteralPath $candidate)) {
            $relativeFile = [IO.Path]::GetRelativePath($rootPath, $file.FullName)
            $broken.Add("$relativeFile -> $target")
        }
    }
}

if ($broken.Count) {
    throw "Broken Markdown links ($($broken.Count)): $($broken -join '; ')"
}
Write-Host 'Markdown links: OK' -ForegroundColor Green
