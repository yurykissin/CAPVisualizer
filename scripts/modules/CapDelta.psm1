<#
.SYNOPSIS
    CAPVisualizer delta module. Compares two CA exports (current vs baseline)
    and produces a structured change set. Pure comparison; read-only.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function _Flatten {
    param($obj, [string]$prefix = '')
    $out = [ordered]@{}
    if ($null -eq $obj) { $out[$prefix] = $null; return $out }
    if ($obj -is [System.Collections.IDictionary]) {
        foreach ($k in $obj.Keys) {
            $child = _Flatten $obj[$k] ($(if ($prefix) { "$prefix.$k" } else { "$k" }))
            foreach ($ck in $child.Keys) { $out[$ck] = $child[$ck] }
        }
    }
    elseif ($obj -is [System.Collections.IEnumerable] -and $obj -isnot [string]) {
        $arr = @($obj)
        # Represent arrays as a sorted, joined scalar so ordering noise is ignored.
        $out[$prefix] = (($arr | ForEach-Object { "$_" } | Sort-Object) -join '|')
    }
    else { $out[$prefix] = "$obj" }
    return $out
}

function Compare-CapPolicy {
    [CmdletBinding()]
    param($Baseline, $Current)
    $bFlat = _Flatten $Baseline
    $cFlat = _Flatten $Current
    $keys = @($bFlat.Keys) + @($cFlat.Keys) | Sort-Object -Unique
    $changes = [System.Collections.Generic.List[object]]::new()
    foreach ($k in $keys) {
        $bv = if ($bFlat.Contains($k)) { $bFlat[$k] } else { $null }
        $cv = if ($cFlat.Contains($k)) { $cFlat[$k] } else { $null }
        if ("$bv" -ne "$cv") {
            $changes.Add([ordered]@{ field = $k; from = $bv; to = $cv })
        }
    }
    return @($changes)
}

function Compare-CapExport {
<#
.SYNOPSIS
    Compare two export objects (as produced by Get-CapExport) by policy id.

.OUTPUTS
    [ordered] hashtable: baselineUtc, currentUtc, added, removed, modified.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Baseline,
        [Parameter(Mandatory)]$Current
    )
    $bMap = @{}; foreach ($p in $Baseline.policies) { $bMap[$p.id] = $p }
    $cMap = @{}; foreach ($p in $Current.policies)  { $cMap[$p.id] = $p }

    $added = @($cMap.Keys | Where-Object { -not $bMap.ContainsKey($_) } |
        ForEach-Object { [ordered]@{ id = $_; displayName = $cMap[$_].displayName; state = $cMap[$_].state } })
    $removed = @($bMap.Keys | Where-Object { -not $cMap.ContainsKey($_) } |
        ForEach-Object { [ordered]@{ id = $_; displayName = $bMap[$_].displayName; state = $bMap[$_].state } })

    $modified = [System.Collections.Generic.List[object]]::new()
    foreach ($id in $cMap.Keys) {
        if (-not $bMap.ContainsKey($id)) { continue }
        $changes = @(Compare-CapPolicy -Baseline $bMap[$id] -Current $cMap[$id])
        if ($changes.Count -gt 0) {
            $modified.Add([ordered]@{
                id          = $id
                displayName = $cMap[$id].displayName
                stateFrom   = $bMap[$id].state
                stateTo     = $cMap[$id].state
                changeCount = $changes.Count
                changes     = $changes
            })
        }
    }

    return [ordered]@{
        baselineUtc = $Baseline.metadata.generatedUtc
        currentUtc  = $Current.metadata.generatedUtc
        addedCount    = $added.Count
        removedCount  = $removed.Count
        modifiedCount = $modified.Count
        added    = @($added)
        removed  = @($removed)
        modified = @($modified)
    }
}

Export-ModuleMember -Function Compare-CapExport, Compare-CapPolicy
