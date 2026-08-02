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
    Tenant id/domain. Required for app-based auth; optional for interactive
    sign-in, where it pins which tenant to authenticate against.

.PARAMETER ClientId
    App registration id (enables app-based / unattended auth).

.PARAMETER CertificateThumbprint
    Certificate thumbprint for app-based auth (preferred over a secret).

.PARAMETER ClientSecret
    Client secret (SecureString) for app-based auth. Certificate is preferred.

.PARAMETER Scopes
    Delegated scopes for interactive sign-in. Default: Policy.Read.All.

.PARAMETER UseDeviceCode
    Interactive sign-in only. Use the device-code flow (prints a copy/paste
    sign-in URL and one-time code in the terminal) instead of the default
    system-browser sign-in. Intended for headless / SSH sessions with no local
    browser. Device-code flow is more phishing-prone, so it is off by default.

.PARAMETER SkipResolveNames
    By default the tool resolves object GUIDs (users, groups, roles, apps) to
    display names, which needs the read-only Directory.Read.All scope in addition
    to Policy.Read.All. Use -SkipResolveNames to keep the minimal
    Policy.Read.All-only footprint (output will then show GUIDs).

.PARAMETER SkipDirectory
    By default the tool also collects read-only directory enrichment (groups,
    role assignments, users, MFA capability) that powers the scope/findings/
    contradiction/compliance analysis. Each dataset degrades gracefully if a
    scope is missing. Use -SkipDirectory to keep a policy-only run.

.PARAMETER FromJson
    Fully-offline render mode. Instead of connecting to Graph, load policies from
    an existing JSON file (a CAPVisualizer export.json, a snapshot folder, a raw
    Graph { value: [...] } response, or a bare array of policy objects) and
    produce the same reports + HTML. No permissions and no network are used.
    Names show as GUIDs unless the JSON embeds a nameMap.

.PARAMETER Redact
    Replace tenant id and object GUIDs with stable pseudonyms so the output can be
    shared externally.

.PARAMETER Delta
    Compare this run against the most recent previous snapshot (or -BaselinePath).

.PARAMETER BaselinePath
    Explicit baseline snapshot folder for the delta comparison.

.PARAMETER NoVisual
    Skip HTML visualization generation.

.PARAMETER NoOpen
    Do not automatically open the generated HTML report in the default browser
    when the run completes. By default the report is opened (except in
    unattended app-only runs).

.PARAMETER NoTranscript
    Do not write a PowerShell transcript into the snapshot folder.

.PARAMETER ManifestKey
    Optional operator-supplied secret. When given, the manifest also carries an
    HMAC-SHA256 over the file hash list, keyed with this value. Unlike the plain
    hashes, an HMAC cannot be recomputed by someone who edits a file without also
    knowing the key, so it turns the manifest from a corruption check into a
    tamper-evidence check for whoever holds the key. The key itself is never
    written to disk.

.EXAMPLE
    pwsh ./scripts/Invoke-CapVisualizer.ps1
    Interactive sign-in; resolves names; export + report + visualization.

.EXAMPLE
    pwsh ./scripts/Invoke-CapVisualizer.ps1 -SkipResolveNames -Delta
    Minimal permissions (GUIDs only) and diff against the previous run.

.EXAMPLE
    pwsh ./scripts/Invoke-CapVisualizer.ps1 -TenantId contoso.com -ClientId <appId> -CertificateThumbprint <thumb> -Delta
    Unattended run using an app registration with certificate auth.
#>
[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param(
    [string]$OutputRoot = (Join-Path (Split-Path -Parent $PSScriptRoot) 'output'),

    [Parameter(ParameterSetName = 'Interactive')]
    [string[]]$Scopes = @('Policy.Read.All'),

    [Parameter(ParameterSetName = 'Interactive')]
    [switch]$UseDeviceCode,

    [Parameter(ParameterSetName = 'Interactive')]
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

    [Parameter(Mandatory, ParameterSetName = 'FromJson')]
    [string]$FromJson,

    [switch]$SkipResolveNames,
    [switch]$SkipDirectory,
    [switch]$SkipAnalysis,
    [string]$AssertionPath,
    [switch]$Redact,
    [switch]$Pseudonymize,
    [switch]$NoNames,
    [string]$Names,
    [switch]$Delta,
    [string]$BaselinePath,
    [switch]$NoVisual,
    [switch]$NoOpen,
    [switch]$NoTranscript,
    [string]$ManifestKey
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Name resolution is ON by default (GUIDs -> display names). It needs the
# read-only Directory.Read.All scope in addition to Policy.Read.All. Use
# -SkipResolveNames to keep the minimal Policy.Read.All-only footprint.
$resolveNames = -not $SkipResolveNames
$includeDirectory = -not $SkipDirectory

$modules = Join-Path $PSScriptRoot 'modules'
Import-Module (Join-Path $modules 'CapCommon.psm1') -Force
Import-Module (Join-Path $modules 'CapNames.psm1') -Force
Import-Module (Join-Path $modules 'CapExport.psm1') -Force
Import-Module (Join-Path $modules 'CapEnrich.psm1') -Force
Import-Module (Join-Path $modules 'CapNormalize.psm1') -Force
Import-Module (Join-Path $modules 'CapScope.psm1') -Force
Import-Module (Join-Path $modules 'CapWhatIf.psm1') -Force
Import-Module (Join-Path $modules 'CapAudit.psm1') -Force
Import-Module (Join-Path $modules 'CapConsolidate.psm1') -Force
Import-Module (Join-Path $modules 'CapFindings.psm1') -Force
Import-Module (Join-Path $modules 'CapCompliance.psm1') -Force
Import-Module (Join-Path $modules 'CapAuthMethods.psm1') -Force
Import-Module (Join-Path $modules 'CapTest.psm1') -Force
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
    $offline = $PSCmdlet.ParameterSetName -eq 'FromJson'
    # Set only in -FromJson mode, where the on-disk export is already masked.
    $preRestoreExport = $null
    $inputDictionary = $null

    if ($offline) {
        # --- Offline render: load from JSON, no Graph connection, no network ---
        if ($resolveNames -and -not $SkipResolveNames.IsPresent) {
            # Cannot resolve live in offline mode; rely only on any embedded nameMap.
            $resolveNames = $false
        }
        Write-CapLog "Offline render mode (-FromJson). No Graph connection will be made." 'INFO'
        $export = Import-CapExportJson -Path $FromJson

        # A name-free export (schema 3.x) carries ids only. Re-hydrate it from the
        # dictionary when one is supplied or sits next to the export; without one
        # the whole run renders ids, which is the intended safe-mode behaviour.
        $inputDictionary = Import-CapNameDictionary -Path $Names -NearExport $FromJson
        if ($inputDictionary) {
            Write-CapLog "Name dictionary found ($($inputDictionary.count) entries); rendering with names." 'OK'
            # Keep the file exactly as it sat on disk. Re-hydration is a blind
            # text substitution, so it rewrites identifier fields as well as
            # labels: a policy whose displayName was masked to its own id comes
            # back with that name in BOTH id and displayName, and the original
            # id is unrecoverable. Building the shareable export from the
            # re-hydrated copy therefore ships real names. The on-disk form is
            # already the masked one, so it is the correct source.
            $preRestoreExport = $export
            $export = ConvertFrom-CapSafeObject -InputObject $export -Dictionary $inputDictionary
            # Blind substitution also rewrote the identifier fields, so every
            # object now reads as its own name where its id used to be. Put the
            # ids back from the on-disk copy, position by position. Without this
            # the dictionary rebuilt below finds no guid to key on, skips the
            # object entirely, and its name becomes unmaskable: it then leaks
            # through the analysis into the shareable export.
            $repaired = Repair-CapRestoredIds -Restored $export -Masked $preRestoreExport
            if ($repaired -gt 0) {
                Write-CapLog "Re-hydration overwrote $repaired identifier(s); restored them from the masked export." 'INFO'
            }
        }
        else {
            Write-CapLog "No name dictionary supplied; the report will show object ids instead of names." 'WARN'
        }
    }
    else {
        # --- Connect ---
        switch ($PSCmdlet.ParameterSetName) {
            'AppCert'   { Connect-CapGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint | Out-Null }
            'AppSecret' { Connect-CapGraph -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret | Out-Null }
            default     {
                $connectScopes = @($Scopes)
                if ($resolveNames -and $connectScopes -notcontains 'Directory.Read.All') { $connectScopes += 'Directory.Read.All' }
                if ($includeDirectory) {
                    foreach ($s in 'Directory.Read.All', 'Group.Read.All', 'User.Read.All', 'RoleManagement.Read.Directory', 'AuditLog.Read.All', 'UserAuthenticationMethod.Read.All') {
                        if ($connectScopes -notcontains $s) { $connectScopes += $s }
                    }
                }
                $connectArgs = @{ Scopes = $connectScopes; UseDeviceCode = $UseDeviceCode }
                if ($TenantId) { $connectArgs['TenantId'] = $TenantId }
                Connect-CapGraph @connectArgs | Out-Null
            }
        }

        # --- Export ---
        $export = Get-CapExport -IncludeDirectory $includeDirectory
    }

    # --- Name / location maps ---
    $locationMap = @{}
    foreach ($nl in $export.namedLocations) { $nlId = if ($nl -is [System.Collections.IDictionary]) { $nl['id'] } else { $nl.id }; $nlName = if ($nl -is [System.Collections.IDictionary]) { $nl['displayName'] } else { $nl.displayName }; if ($nlId) { $locationMap[$nlId] = $nlName } }
    # Named locations are also resolved as generic names (e.g. inside conditions).
    $nameMap = @{}
    foreach ($k in $locationMap.Keys) { $nameMap[$k] = $locationMap[$k] }
    # Authentication context references (id -> displayName).
    foreach ($ac in $export.authenticationContexts) { $acId = if ($ac -is [System.Collections.IDictionary]) { $ac['id'] } else { $ac.id }; $acName = if ($ac -is [System.Collections.IDictionary]) { $ac['displayName'] } else { $ac.displayName }; if ($acId) { $nameMap[$acId] = $acName } }
    # Any name map embedded in an offline JSON export.
    if ($export.Contains('nameMap') -and $export['nameMap']) { foreach ($k in $export['nameMap'].Keys) { $nameMap["$k"] = $export['nameMap'][$k] } }
    # Offline re-render of a masked export: the supplied dictionary is the only
    # place the real names live. Identifiers were put back after re-hydration
    # (see Repair-CapRestoredIds), so the report resolves them the same way a
    # live run does, through the name map, rather than by carrying names in the
    # data itself.
    if ($inputDictionary) {
        foreach ($e in $inputDictionary.entries.GetEnumerator()) {
            $eid = "$($e.Key)"
            $en = "$(if ($e.Value -is [System.Collections.IDictionary]) { $e.Value['name'] } else { $e.Value.name })"
            if ($eid -and $en) { $nameMap[$eid] = $en }
        }
    }
    # Well-known first-party app ids are always safe to resolve (static, offline).
    (Get-CapWellKnownAppMap).GetEnumerator() | ForEach-Object { if (-not $nameMap.ContainsKey($_.Key)) { $nameMap[$_.Key] = $_.Value } }

    # Policy ids -> display names (findings/audit reference policies by id).
    foreach ($pol in $export.policies) {
        $polId = if ($pol -is [System.Collections.IDictionary]) { $pol['id'] } else { $pol.id }
        $polNm = if ($pol -is [System.Collections.IDictionary]) { $pol['displayName'] } else { $pol.displayName }
        if ($polId -and $polNm) { $nameMap["$polId"] = "$polNm" }
    }
    # Directory enrichment display names (users incl. UPN, groups, role templates).
    # These power the analysis-engine tabs (findings/contradictions), whose affected
    # objects are directory ids that are not necessarily referenced by any policy.
    if ($includeDirectory -and $export.Contains('enrichment') -and $export['enrichment']) {
        $enrichmentData = $export['enrichment']
        $encGet = { param($o, $n) if ($null -eq $o) { $null } elseif ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { $o[$n] } else { $null } } else { $p = $o.PSObject.Properties[$n]; if ($p) { $p.Value } else { $null } } }
        foreach ($u in @(& $encGet (& $encGet $enrichmentData 'users') 'data')) {
            $uid = "$(& $encGet $u 'id')"; $udn = "$(& $encGet $u 'displayName')"; $upn = "$(& $encGet $u 'userPrincipalName')"
            if ($uid) { $nameMap[$uid] = if ($udn -and $upn) { "$udn ($upn)" } elseif ($udn) { $udn } else { $upn } }
        }
        foreach ($g in @(& $encGet (& $encGet $enrichmentData 'groups') 'data')) {
            $gid = "$(& $encGet $g 'id')"; $gdn = "$(& $encGet $g 'displayName')"
            if ($gid -and $gdn) { $nameMap[$gid] = $gdn }
        }
        foreach ($ra in @(& $encGet (& $encGet $enrichmentData 'roleAssignments') 'data')) {
            $rtid = "$(& $encGet $ra 'roleTemplateId')"; $rtn = "$(& $encGet $ra 'roleName')"
            if ($rtid -and $rtn -and -not $nameMap.ContainsKey($rtid)) { $nameMap[$rtid] = $rtn }
        }
    }

    if ($resolveNames -and -not $offline) {
        Write-CapLog "Resolving object names (users/groups, roles, apps) via Directory.Read.All..." 'INFO'
        $refs = Get-CapReferences -Export $export
        if (@($refs.UserGroupIds).Count)    { (Get-CapDirectoryNameMap -Ids $refs.UserGroupIds).GetEnumerator()      | ForEach-Object { $nameMap[$_.Key] = $_.Value } }
        if (@($refs.RoleTemplateIds).Count) { (Get-CapRoleTemplateMap).GetEnumerator()                                | ForEach-Object { $nameMap[$_.Key] = $_.Value } }
        if (@($refs.AppIds).Count)          { (Get-CapServicePrincipalMap -AppIds $refs.AppIds).GetEnumerator()       | ForEach-Object { $nameMap[$_.Key] = $_.Value } }
        if (@($refs.ServicePrincipalIds).Count) { (Get-CapDirectoryNameMap -Ids $refs.ServicePrincipalIds).GetEnumerator() | ForEach-Object { $nameMap[$_.Key] = $_.Value } }
        Write-CapLog "Resolved $($nameMap.Count) names (users/groups: $(@($refs.UserGroupIds).Count), roles: $(@($refs.RoleTemplateIds).Count), apps: $(@($refs.AppIds).Count), service principals: $(@($refs.ServicePrincipalIds).Count))." 'OK'
    }

    # --- Friendly / report ---
    $friendly = @($export.policies | ForEach-Object { ConvertTo-CapFriendlyPolicy -Policy $_ -NameMap $nameMap -LocationMap $locationMap })
    $findings = Get-CapHygieneFindings -FriendlyPolicies $friendly
    $summary  = New-CapSummary -Export $export -FriendlyPolicies $friendly -Findings $findings

    # --- Offline analysis engines (normalize -> audit/findings/compliance/test) ---
    $riskFindings = $null; $auditResult = $null; $complianceResult = $null; $testResult = $null; $authMethods = $null; $consolidation = $null
    if (-not $SkipAnalysis) {
        Write-CapLog "Running offline analysis engines (normalize, audit, consolidation, findings, compliance, tests)..." 'INFO'
        $grouping   = Get-CapAppGroupingMap
        $normalized = @($export.policies | ForEach-Object { ConvertTo-CapNormalizedPolicy -Policy $_ -AppGroupingMap $grouping })
        $enrichment = if ($export.Contains('enrichment')) { $export.enrichment } else { $null }

        # Say out loud when the export carries condition data this build does not
        # read. Microsoft adds new shapes for existing conditions, and a tool that
        # reads only the old one reports the condition as absent rather than
        # failing. Absent targeting reads as "this policy does nothing", which is
        # how live policies get recommended for deletion. Every judgement below
        # depends on this being empty.
        $unreadShapes = @(Test-CapShapeCoverage -Policies $export.policies)
        if ($unreadShapes.Count) {
            Write-CapLog ("Unread condition shapes: {0} key(s) are populated in this export but not read by the analysis engines. Targeting and dead-weight judgements for the affected policies may be wrong. Report this." -f $unreadShapes.Count) 'WARN'
            foreach ($u in $unreadShapes) {
                Write-CapLog ("  {0} - {1} policy(ies), e.g. '{2}'" -f $u.path, $u.count, $u.sample) 'WARN'
            }
        }

        $auditResult      = Invoke-CapAudit -NormalizedPolicies $normalized -Enrichment $enrichment
        $riskFindings     = Invoke-CapFindings -NormalizedPolicies $normalized -Enrichment $enrichment -AuditResult $auditResult
        $complianceResult = Invoke-CapCompliance -NormalizedPolicies $normalized
        $authMethods      = Invoke-CapAuthMethods -Enrichment $enrichment
        $consolidation    = Invoke-CapConsolidate -NormalizedPolicies $normalized -NameMap $nameMap -UnreadShapes $unreadShapes
        $testArgs = @{ NormalizedPolicies = $normalized; Enrichment = $enrichment; ComplianceResult = $complianceResult; FindingsResult = $riskFindings }
        if ($AssertionPath) { $testArgs['AssertionPath'] = $AssertionPath }
        $testResult = Invoke-CapTest @testArgs
        Write-CapLog ("Analysis: {0} audit issue(s), {1} finding(s), compliance {2}% pass, tests {3}." -f `
            @($auditResult.issues).Count, @($riskFindings.findings).Count, $complianceResult.summary.passRate, `
            $(if ($testResult.passed) { 'PASS' } else { 'FAIL' })) 'OK'
        Write-CapLog ("Consolidation: {0} -> ~{1} policies (exact dup {2}, overlap {3}, merge {4}, dead weight {5}, gaps {6})." -f `
            $consolidation.summary.total, $consolidation.summary.estimatedTarget, $consolidation.summary.exactDuplicateClusters, `
            $consolidation.summary.overlapClusters, $consolidation.summary.mergeCandidateClusters, `
            $consolidation.summary.deadWeightCount, $consolidation.summary.completenessGaps) 'OK'
    }

    # --- Name separation ---
    # Every tenant-identifying name moves into a local-only dictionary, leaving a
    # name-free raw/export.json and analysis set that can be handed to a cloud
    # service. The in-memory objects stay resolved, so report/ and the HTML keep
    # their names. See docs/SAFEEXPORT.md.
    if ($Redact -and -not $Pseudonymize) {
        Write-CapLog "-Redact is deprecated and one-way; use -Pseudonymize (reversible via the local dictionary)." 'WARN'
        $Pseudonymize = $true
    }

    $dictionary = New-CapNameDictionary -Export $export -NameMap $nameMap -AuthMethods $authMethods `
        -Snapshot $stamp -Pseudonymize:$Pseudonymize
    Write-CapLog ("Name dictionary: {0} entr{1}{2}." -f $dictionary.count, $(if ($dictionary.count -eq 1) { 'y' } else { 'ies' }), `
        $(if ($Pseudonymize) { ", $($dictionary.idAliases.Count) id alias(es)" } else { '' })) 'INFO'

    $safeExport = ConvertTo-CapSafeObject -InputObject $export -Dictionary $dictionary
    $safeExport.metadata.schemaVersion = '3.0'
    # nameMap is superseded by the dictionary; carrying a masked copy is noise.
    if ($safeExport.Contains('nameMap')) { $safeExport.Remove('nameMap') }
    if ($Pseudonymize) {
        $summary.tenantId = $safeExport.metadata.tenantId
    }

    # --- Write raw + report ---
    # raw/export.json is name-free; raw/names.json is the dictionary that turns it
    # back into names. Delete or withhold names.json and the report renders ids.
    Save-CapJson -InputObject $safeExport -Path (Join-Path $snapshot 'raw/export.json')

    # Split the export into its natural parts as well. export.json stays the
    # single source of truth, but 98% of its bytes are directory enrichment
    # (user inventory, MFA posture, group membership) that has nothing to do
    # with Conditional Access. Keeping the CA definitions in their own small
    # file means the thing most often read, diffed or shared does not drag the
    # whole user directory along with it.
    Save-CapJson -InputObject ([ordered]@{
        metadata = $safeExport.metadata
        policies = $safeExport.policies
    }) -Path (Join-Path $snapshot 'raw/policies.json')

    Save-CapJson -InputObject ([ordered]@{
        metadata                = $safeExport.metadata
        namedLocations          = $safeExport.namedLocations
        authenticationStrengths = $safeExport.authenticationStrengths
        authenticationContexts  = $safeExport.authenticationContexts
    }) -Path (Join-Path $snapshot 'raw/references.json')

    if ($safeExport.Contains('enrichment')) {
        Save-CapJson -InputObject ([ordered]@{
            metadata   = $safeExport.metadata
            enrichment = $safeExport.enrichment
        }) -Path (Join-Path $snapshot 'raw/enrichment.json')
    }

    Save-CapJson -InputObject $friendly -Path (Join-Path $snapshot 'report/policies.json')
    Save-CapJson -InputObject $summary  -Path (Join-Path $snapshot 'report/summary.json')
    Save-CapJson -InputObject $findings -Path (Join-Path $snapshot 'report/findings.json')

    $safeAnalysis = [ordered]@{}
    if (-not $SkipAnalysis) {
        New-Item -ItemType Directory -Force -Path (Join-Path $snapshot 'analysis') | Out-Null
        $safeAnalysis['audit'] = ConvertTo-CapSafeObject -InputObject $auditResult -Dictionary $dictionary
        $safeAnalysis['findings'] = ConvertTo-CapSafeObject -InputObject $riskFindings -Dictionary $dictionary
        $safeAnalysis['compliance'] = ConvertTo-CapSafeObject -InputObject $complianceResult -Dictionary $dictionary
        if ($authMethods) { $safeAnalysis['authMethods'] = ConvertTo-CapSafeObject -InputObject $authMethods -Dictionary $dictionary }
        if ($consolidation) { $safeAnalysis['consolidation'] = ConvertTo-CapSafeObject -InputObject $consolidation -Dictionary $dictionary }
        $safeTestResult = ConvertTo-CapSafeObject -InputObject $testResult -Dictionary $dictionary
        $safeAnalysis['tests'] = $safeTestResult

        Save-CapJson -InputObject $safeAnalysis['audit']      -Path (Join-Path $snapshot 'analysis/audit.json')
        Save-CapJson -InputObject $safeAnalysis['findings']   -Path (Join-Path $snapshot 'analysis/findings.json')
        Save-CapJson -InputObject $safeAnalysis['compliance'] -Path (Join-Path $snapshot 'analysis/compliance.json')
        if ($authMethods) { Save-CapJson -InputObject $safeAnalysis['authMethods'] -Path (Join-Path $snapshot 'analysis/authmethods.json') }
        if ($consolidation) { Save-CapJson -InputObject $safeAnalysis['consolidation'] -Path (Join-Path $snapshot 'analysis/consolidation.json') }
        Save-CapJson -InputObject $safeTestResult -Path (Join-Path $snapshot 'analysis/tests.json')
        if ($testResult) {
            ConvertTo-CapJUnit -TestResult $safeTestResult | Set-Content -Path (Join-Path $snapshot 'analysis/tests.junit.xml') -Encoding utf8
            ConvertTo-CapSarif -TestResult $safeTestResult | Set-Content -Path (Join-Path $snapshot 'analysis/tests.sarif.json') -Encoding utf8
        }
    }

    # --- Shareable export (behind "Export safely") ---
    # Built by allowlist from the masked export: policies only, no tenant id, no
    # display names. Because it copies in only known-safe structure rather than
    # subtracting what looks sensitive, there is nothing to verify after the
    # fact and nothing that can withhold the button.
    # In -FromJson mode prefer the file as it sat on disk: it is already masked,
    # whereas the in-memory copy has been re-hydrated for the local report.
    $bundleSource = if ($preRestoreExport) { $preRestoreExport } else { $safeExport }
    # Mask again with the dictionary built by this run, even when the source was
    # already masked on disk. An older snapshot was masked by an older build, so
    # anything this build learned to remove since - a partner tenant id, for one
    # - is still sitting in that file, and re-exporting it would publish it. Name
    # substitution is idempotent, so masking twice costs nothing and closes the
    # gap where a re-render of last month's snapshot is less safe than a fresh run.
    if ($dictionary) { $bundleSource = ConvertTo-CapSafeObject -InputObject $bundleSource -Dictionary $dictionary }
    $safeBundle = New-CapPolicyOnlyExport -Export $bundleSource -Snapshot $stamp -Analysis $safeAnalysis
    $analysisNote = if ($safeBundle.Contains('consolidation') -or $safeBundle.Contains('compliance')) { ', with the deterministic analysis included' } else { '' }
    Write-CapLog "Shareable export ready: $(@($safeBundle.policies).Count) policies, no tenant id or display names$analysisNote (use 'Export safely' in the report)." 'OK'

    # Belt and braces: the allowlist is the control, this only reports. It must
    # never gate the button - that was the previous design's mistake.
    try {
        $residual = @(Test-CapNameLeak -Dictionary $dictionary -InputObject $safeBundle -RequirePseudonymized)
        if ($residual.Count) {
            $detail = ($residual | Select-Object -First 5 | ForEach-Object {
                if ($_.context) { "$($_.kind): $($_.value) [$($_.context)]" } else { "$($_.kind): $($_.value)" }
            }) -join '; '
            Write-CapLog "Shareable export self-check flagged $($residual.Count) item(s) for review: $detail" 'WARN'
        }
    }
    catch {
        Write-CapLog "Shareable export self-check could not run: $($_.Exception.Message)" 'WARN'
    }

    if (-not $NoNames) {
        Save-CapJson -InputObject $dictionary -Path (Join-Path $snapshot 'raw/names.json')
    }

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
            # Both sides must be in the same (name-free) form or every renamed
            # object would surface as a spurious change. A legacy 2.x baseline
            # still carries names, so mask it with its own dictionary first.
            $baseMeta = if ($baseline.Contains('metadata')) { $baseline['metadata'] } else { $null }
            $baseSchema = if ($baseMeta -and $baseMeta.Contains('schemaVersion')) { "$($baseMeta['schemaVersion'])" } else { '1.0' }
            if ($baseSchema -notlike '3.*') {
                $baseDict = New-CapNameDictionary -Export $baseline `
                    -NameMap $(if ($baseline.Contains('nameMap')) { $baseline['nameMap'] } else { @{} }) -Snapshot 'baseline'
                $baseline = ConvertTo-CapSafeObject -InputObject $baseline -Dictionary $baseDict
            }
            $delta = Compare-CapExport -Baseline $baseline -Current ($safeExport)
            New-Item -ItemType Directory -Force -Path (Join-Path $snapshot 'delta') | Out-Null
            Save-CapJson -InputObject $delta -Path (Join-Path $snapshot 'delta/delta.json')
            Write-CapLog ("Delta: {0} added, {1} removed, {2} modified." -f $delta.addedCount, $delta.removedCount, $delta.modifiedCount) 'OK'
        }
        else {
            Write-CapLog "No previous snapshot found for delta; skipping." 'WARN'
        }
    }

    # --- Visualization ---
    # The HTML generator reads both artifacts: the name-free export and, when it
    # exists, the dictionary. With the dictionary it renders real names; without
    # it (-NoNames, or a dictionary the operator withheld) it renders ids.
    if (-not $NoVisual) {
        $visualDelta = $delta
        if ($NoNames) {
            $visFriendly   = @(ConvertTo-CapSafeObject -InputObject $friendly -Dictionary $dictionary)
            $visSummary    = ConvertTo-CapSafeObject -InputObject $summary  -Dictionary $dictionary
            $visFindings   = @(ConvertTo-CapSafeObject -InputObject $findings -Dictionary $dictionary)
            $visRisk       = $(if ($riskFindings) { @(ConvertTo-CapSafeObject -InputObject $riskFindings.findings -Dictionary $dictionary) } else { $null })
            $visAudit      = ConvertTo-CapSafeObject -InputObject $auditResult -Dictionary $dictionary
            $visCompliance = ConvertTo-CapSafeObject -InputObject $complianceResult -Dictionary $dictionary
            $visTests      = ConvertTo-CapSafeObject -InputObject $testResult -Dictionary $dictionary
            $visAuth       = $(if ($authMethods) { ConvertTo-CapSafeObject -InputObject $authMethods -Dictionary $dictionary } else { $null })
            $visNameMap    = @{}
        }
        else {
            $visFriendly   = $friendly
            $visSummary    = $summary
            $visFindings   = $findings
            $visRisk       = $(if ($riskFindings) { $riskFindings.findings } else { $null })
            $visAudit      = $auditResult
            $visCompliance = $complianceResult
            $visTests      = $testResult
            $visAuth       = $authMethods
            $visNameMap    = $nameMap
            if ($delta) { $visualDelta = ConvertFrom-CapSafeObject -InputObject $delta -Dictionary $dictionary }
        }
        New-CapVisual -FriendlyPolicies $visFriendly -Summary $visSummary -Findings $visFindings -Delta $visualDelta `
            -RiskFindings $visRisk `
            -Audit $visAudit -Compliance $visCompliance -TestResult $visTests -AuthMethods $visAuth -NameMap $visNameMap `
            -SafeBundle $safeBundle -SnapshotName $stamp `
            -AssetsPath $assetsPath -OutputFile (Join-Path $snapshot 'visual/index.html')
    }

    # --- Manifest (integrity hashes; no secrets) ---
    # containsNames marks the files that must never leave the machine. Be honest
    # about what the hashes prove: they catch accidental edits and partial copies,
    # but the manifest is generated and verified by the same tool with the same
    # unkeyed hash, so anyone who edits a file can regenerate it. It is not a
    # signature. For tamper-evidence either record the manifest hash printed
    # below out of band, or pass -ManifestKey to add a keyed HMAC.
    $localOnly = @('raw/names.json', 'report/policies.json', 'report/summary.json', 'report/findings.json',
                   'report/policies.csv', 'report/findings.csv')
    $files = Get-ChildItem -Path $snapshot -Recurse -File | Where-Object { $_.Name -ne 'manifest.json' -and $_.Name -ne 'transcript.txt' }
    $fileEntries = @($files | ForEach-Object {
        $rel = ($_.FullName.Substring($snapshot.Length + 1) -replace '\\', '/')
        [ordered]@{
            path          = $rel
            sha256        = (Get-CapFileSha256 -Path $_.FullName)
            bytes         = $_.Length
            containsNames = ($localOnly -contains $rel) -or ($rel -eq 'visual/index.html' -and -not $NoNames)
        }
    })
    $integrity = [ordered]@{
        algorithm = 'SHA-256'
        proves    = 'Detects accidental modification and incomplete copies of the files listed below.'
        does_not_prove = 'Not a signature. This manifest is generated and verified by the same tool with the same unkeyed hash, so anyone who edits a file can regenerate it. It does not prove the absence of deliberate tampering.'
        anchor    = 'To detect later tampering, record the manifest hash printed to the console at generation time and compare it independently, or generate with -ManifestKey to add a keyed HMAC.'
    }
    $manifest = [ordered]@{
        tool          = 'CAPVisualizer'
        snapshot      = $stamp
        generatedUtc  = $summary.generatedUtc
        tenantId      = $summary.tenantId
        resolveNames  = [bool]$resolveNames
        offline       = [bool]$offline
        directory     = [bool]$includeDirectory
        pseudonymized = [bool]$Pseudonymize
        namesSplit    = $true
        dictionary    = $(if ($NoNames) { $null } else { 'raw/names.json' })
        integrity     = $integrity
        files         = $fileEntries
    }
    if ($ManifestKey) {
        # Keyed over the canonical "path:sha256" list, which is exactly what the
        # per-file hashes attest to. Someone without the key cannot forge it.
        $hashList = (($fileEntries | ForEach-Object { "$($_.path):$($_.sha256)" }) -join "`n")
        $hmac = [System.Security.Cryptography.HMACSHA256]::new([System.Text.Encoding]::UTF8.GetBytes($ManifestKey))
        try {
            $mac = (-join ($hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($hashList)) | ForEach-Object { $_.ToString('x2') }))
        }
        finally { $hmac.Dispose() }
        $manifest['integrity']['hmacSha256'] = $mac
        $manifest['integrity']['hmacScope'] = 'newline-joined path:sha256 list, in file order'
    }
    Save-CapJson -InputObject $manifest -Path (Join-Path $snapshot 'manifest.json')

    # Print the manifest's own hash so it can be recorded out of band. This is the
    # external anchor: a value written down elsewhere that a later, tampered
    # manifest cannot match.
    $manifestHash = Get-CapFileSha256 -Path (Join-Path $snapshot 'manifest.json')
    Write-CapLog ("Manifest SHA-256 (record separately to anchor integrity): {0}" -f $manifestHash) 'INFO'

    $visualPath = Join-Path $snapshot 'visual/index.html'
    Write-CapLog "Done. Open: $visualPath" 'OK'

    # Auto-open the report in the default browser (interactive runs only). App-only
    # (unattended) runs and -NoOpen / -NoVisual skip this.
    $unattended = $PSCmdlet.ParameterSetName -in @('AppCert', 'AppSecret')
    if (-not $NoOpen -and -not $NoVisual -and -not $unattended -and (Test-Path $visualPath)) {
        Open-CapBrowser -Url $visualPath
    }
}
finally {
    if ($PSCmdlet.ParameterSetName -ne 'FromJson') { try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { } }
    if (-not $NoTranscript) { try { Stop-Transcript | Out-Null } catch { } }
}
