<#
.SYNOPSIS
    CAPVisualizer gap-permutation engine (Phase 4). Given a principal and a target
    resource, it enumerates combinations of the sign-in signals that the in-scope
    policies actually gate on, runs each combination through the offline what-if
    engine, and reports the scenarios that reach the resource with no enforced
    block or MFA - i.e. coverage gaps / bypass paths.

.DESCRIPTION
    This automates the "what signal combination slips through?" question that is
    otherwise manual. Only signals referenced by at least one in-scope policy are
    permuted, keeping the search bounded. Scenarios that are protected only on
    untrusted networks (and therefore intentionally relaxed on trusted networks)
    are flagged by-design so they don't drown out actionable findings.

    Authored independently against the public Entra CA evaluation model; no
    third-party tool code or logic is reused.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Canonical value domains explored per signal. Two representative values each so
# the cartesian product stays small while still exercising both sides of every
# gate (modern vs legacy client, clean vs risky, trusted vs untrusted, etc.).
$script:CapSignalDomains = [ordered]@{
    ClientApp   = @('browser', 'exchangeActiveSync')
    Platform    = @('windows', 'iOS')
    Location    = @('trusted', 'untrusted')
    SignInRisk  = @('none', 'high')
    UserRisk    = @('none', 'high')
    DeviceState = @('compliant', 'unmanaged')
}

function _AnArr { param($v) if ($null -eq $v) { return @() }; if ($v -is [string]) { return @($v) }; if ($v -is [System.Collections.IEnumerable]) { return @($v | ForEach-Object { $_ }) }; @($v) }

function Get-CapRelevantSignals {
<#
.SYNOPSIS
    Determine which signal dimensions are worth permuting for a principal+resource:
    the union of signals gated by policies that are in scope (not excluded) and
    that could target the resource. ClientApp is always included because legacy
    authentication is a classic bypass axis.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PrincipalId,
        [Parameter(Mandatory)]$NormalizedPolicies,
        $Enrichment,
        [string]$Resource
    )

    $ctx = Resolve-CapPrincipalContext -PrincipalId $PrincipalId -Enrichment $Enrichment
    $signals = [System.Collections.Generic.HashSet[string]]::new()
    [void]$signals.Add('ClientApp')

    foreach ($np in @($NormalizedPolicies)) {
        $scope = Test-CapPolicyScope -NormalizedPolicy $np -Context $ctx
        if ($scope.bucket -eq 'Excluded' -or $scope.bucket -eq 'NotInScope') { continue }

        if ($null -ne $np.conditions.platforms)   { [void]$signals.Add('Platform') }
        if ($null -ne $np.conditions.locations)   { [void]$signals.Add('Location') }
        if (@(_AnArr $np.conditions.signInRisk).Count) { [void]$signals.Add('SignInRisk') }
        if (@(_AnArr $np.conditions.userRisk).Count)   { [void]$signals.Add('UserRisk') }
        if ($null -ne $np.conditions.deviceFilter) { [void]$signals.Add('DeviceState') }
    }
    # Preserve the canonical ordering.
    @($script:CapSignalDomains.Keys | Where-Object { $signals.Contains($_) })
}

function _CapCartesian {
    param([string[]]$Dimensions)
    $combos = @([ordered]@{})
    foreach ($dim in $Dimensions) {
        $values = $script:CapSignalDomains[$dim]
        $next = [System.Collections.Generic.List[object]]::new()
        foreach ($c in $combos) {
            foreach ($v in $values) {
                $copy = [ordered]@{}
                foreach ($k in $c.Keys) { $copy[$k] = $c[$k] }
                $copy[$dim] = $v
                $next.Add($copy)
            }
        }
        $combos = $next.ToArray()
    }
    @($combos)
}

function Invoke-CapAnalyze {
<#
.SYNOPSIS
    Permute the relevant sign-in signals for a principal+resource and report gap
    scenarios (reachable with no enforced block or MFA).

.PARAMETER MaxScenarios
    Safety cap on how many combinations are evaluated (default 512).

.OUTPUTS
    Ordered hashtable: principal, resource, dimensions, totalScenarios, evaluated,
    gaps[], summary. Each gap: signals, outcome, gapType, byDesign, reason.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PrincipalId,
        [Parameter(Mandatory)]$NormalizedPolicies,
        $Enrichment,
        [string]$Resource,
        [int]$MaxScenarios = 512
    )

    $dims = @(Get-CapRelevantSignals -PrincipalId $PrincipalId -NormalizedPolicies $NormalizedPolicies -Enrichment $Enrichment -Resource $Resource)
    $allCombos = @(_CapCartesian -Dimensions $dims)
    $total = $allCombos.Count
    $combos = if ($total -gt $MaxScenarios) { @($allCombos[0..($MaxScenarios - 1)]) } else { $allCombos }

    # First pass: evaluate every scenario, keyed for by-design detection.
    $evaluated = [System.Collections.Generic.List[object]]::new()
    foreach ($c in $combos) {
        $wiArgs = @{ PrincipalId = $PrincipalId; NormalizedPolicies = $NormalizedPolicies; Enrichment = $Enrichment }
        if ($Resource) { $wiArgs['Resource'] = $Resource }
        foreach ($k in $c.Keys) { $wiArgs[$k] = $c[$k] }
        $wi = Test-CapWhatIf @wiArgs
        $protected = [bool]($wi.outcome.blocked -or $wi.outcome.mfaRequired)
        $evaluated.Add([ordered]@{
            signals   = $c
            protected = $protected
            outcome   = $wi.outcome
            reportOnlyApplied = @($wi.outcome.reportOnlyApplied)
        })
    }

    # Index protected scenarios by their non-location signal signature so a gap on
    # a trusted network can be recognised as by-design when its untrusted twin is
    # protected.
    $protectedByKey = @{}
    foreach ($e in $evaluated) {
        if (-not $e.protected) { continue }
        $protectedByKey[(_CapSignalKey $e.signals -Exclude 'Location')] = $true
    }

    $gaps = [System.Collections.Generic.List[object]]::new()
    foreach ($e in $evaluated) {
        if ($e.protected) { continue }
        $sig = $e.signals
        $byDesign = $false
        if ($sig.Contains('Location') -and $sig['Location'] -eq 'trusted') {
            if ($protectedByKey.ContainsKey((_CapSignalKey $sig -Exclude 'Location'))) { $byDesign = $true }
        }

        $gapType = 'no-enforcement'
        if ($sig.Contains('ClientApp') -and @('exchangeActiveSync', 'other') -contains $sig['ClientApp']) {
            $gapType = 'legacy-auth-bypass'
        }
        elseif (@($e.reportOnlyApplied).Count -gt 0) {
            $gapType = 'report-only-only'
        }

        $gaps.Add([ordered]@{
            signals   = $sig
            outcome   = [ordered]@{
                blocked       = $e.outcome.blocked
                mfaRequired   = $e.outcome.mfaRequired
                grantControls = @($e.outcome.grantControls)
            }
            gapType   = $gapType
            byDesign  = $byDesign
            reportOnlyApplied = @($e.reportOnlyApplied)
            reason    = if ($byDesign) { 'Reachable without enforcement on trusted network (protected off trusted network - likely by design)' }
                        elseif ($gapType -eq 'legacy-auth-bypass') { 'Legacy authentication client reaches the resource without an enforced block' }
                        elseif ($gapType -eq 'report-only-only') { 'Only report-only policies would apply - no enforcement' }
                        else { 'Resource reachable with no enforced block or MFA' }
        })
    }

    $actionable = @($gaps | Where-Object { -not $_.byDesign })
    $gapTypeCounts = @{}
    foreach ($g in $actionable) { $gapTypeCounts[$g.gapType] = 1 + ($(if ($gapTypeCounts.ContainsKey($g.gapType)) { $gapTypeCounts[$g.gapType] } else { 0 })) }

    [ordered]@{
        principal      = (Resolve-CapPrincipalContext -PrincipalId $PrincipalId -Enrichment $Enrichment)
        resource       = $Resource
        dimensions     = @($dims)
        totalScenarios = $total
        evaluated      = $combos.Count
        gaps           = @($gaps)
        summary        = [ordered]@{
            gapCount        = @($gaps).Count
            byDesignCount   = @($gaps | Where-Object { $_.byDesign }).Count
            actionableCount = $actionable.Count
            gapTypes        = $gapTypeCounts
        }
    }
}

function _CapSignalKey {
    param([Parameter(Mandatory)]$Signals, [string[]]$Exclude = @())
    $parts = foreach ($k in $Signals.Keys) {
        if ($Exclude -contains $k) { continue }
        "$k=$($Signals[$k])"
    }
    ($parts | Sort-Object) -join '|'
}

function ConvertTo-CapAnalyzeJsonl {
<#
.SYNOPSIS
    Render each gap scenario as one JSON object per line (JSONL) for streaming /
    diffing / ingestion.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$AnalyzeResult)
    foreach ($g in $AnalyzeResult.gaps) {
        [ordered]@{
            principalId = $AnalyzeResult.principal.id
            resource    = $AnalyzeResult.resource
            signals     = $g.signals
            gapType     = $g.gapType
            byDesign    = $g.byDesign
            blocked     = $g.outcome.blocked
            mfaRequired = $g.outcome.mfaRequired
            reason      = $g.reason
        } | ConvertTo-Json -Depth 6 -Compress
    }
}

Export-ModuleMember -Function Invoke-CapAnalyze, Get-CapRelevantSignals, ConvertTo-CapAnalyzeJsonl
