<#
.SYNOPSIS
    CAPVisualizer name separation. Splits every tenant-identifying name out of an
    export into a local-only dictionary, leaving a name-free artifact that is safe
    to hand to a cloud service, and restores the names afterwards.

.DESCRIPTION
    The export keeps its structure and object ids; only the *names* move out. The
    dictionary (names.json) is written next to the export, never uploaded, and is
    the single source used both when rendering the HTML report and when
    re-hydrating an AI-generated report.

    Two levels are supported:

      names only     - display names, UPNs, IP ranges, device-filter rules and
                       other free text are replaced by the object's own id, or by
                       a synthetic alias when the value has no id. Object GUIDs
                       remain, so the file is pseudonymous, not anonymous.
      pseudonymized  - tenant-specific GUIDs are additionally replaced by stable
                       aliases (USER-001, POL-003, ...) and the tenant id is
                       masked, so nothing tenant-correlatable is left.

    Well-known Microsoft identifiers (first-party application ids, built-in
    directory role template ids and their names) are global constants, not tenant
    data. They are never masked: masking them would destroy review quality for no
    privacy gain.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:CapGuidRegex = [regex]'(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b'

# Names per alternation regex. Sized to stay under the DFA node limit for
# typical display names while keeping the number of scans per string small.
$script:CapRegexChunkSize = 1000

# Minimum length for a name to be substituted inside free text. Short names
# ("IT", "All") appear as substrings of ordinary prose and would corrupt it.
# Exact whole-value matches are substituted regardless of length.
$script:CapMinTextNameLength = 5

# Cache for the well-known identifier set (StrictMode requires initialization).
$script:CapWellKnown = $null

function _NmGet {
    param($Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [System.Collections.IDictionary]) { if ($Obj.Contains($Name)) { return $Obj[$Name] } return $null }
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    $null
}

function _NmKeys {
    param($Obj)
    if ($null -eq $Obj) { return @() }
    if ($Obj -is [System.Collections.IDictionary]) { return @($Obj.Keys) }
    return @($Obj.PSObject.Properties.Name)
}

function _NmArr { param($v) if ($null -eq $v) { return @() }; if ($v -is [string]) { return @($v) }; if ($v -is [System.Collections.IEnumerable]) { return @($v | ForEach-Object { $_ }) }; @($v) }

function Get-CapWellKnownIdSet {
<#
.SYNOPSIS
    Identifiers and names that are Microsoft-global rather than tenant data and
    must survive masking: first-party application ids, built-in directory role
    template ids, and the built-in role display names.

.OUTPUTS
    Hashtable with 'ids' (HashSet[string], lowercase) and 'names'
    (HashSet[string], lowercase).
#>
    [CmdletBinding()]
    param()

    if ($script:CapWellKnown) { return $script:CapWellKnown }

    $ids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $names = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    # Microsoft first-party application ids referenced by Conditional Access.
    foreach ($id in @(
        '00000002-0000-0ff1-ce00-000000000000'   # Office 365 Exchange Online
        '00000003-0000-0ff1-ce00-000000000000'   # Office 365 SharePoint Online
        '00000003-0000-0000-c000-000000000000'   # Microsoft Graph
        '00000002-0000-0000-c000-000000000000'   # Azure Active Directory Graph
        '797f4846-ba00-4fd7-ba43-dac1f8f63013'   # Windows Azure Service Management API
        '00000012-0000-0000-c000-000000000000'   # Microsoft Rights Management
        '0000000a-0000-0000-c000-000000000000'   # Microsoft Intune
        '00000007-0000-0000-c000-000000000000'   # Dynamics CRM Online
        '00000009-0000-0000-c000-000000000000'   # Power BI Service
        'c9a559d2-7aab-4f13-a6ed-e7e9c52aec87'   # Microsoft Forms
        'cf36b471-5b44-428c-9ce7-313bf84528de'   # Microsoft Bing Search
        '89bee1f7-5e6e-4d8a-9f3d-ecd601259da7'   # Office365 Shell WCSS-Client
        '66a88757-258c-4c72-893c-3e8bed4d6899'   # Office 365 Search Service
        'd3590ed6-52b3-4102-aeff-aad2292ab01c'   # Microsoft Office
        '872cd9fa-d31f-45e0-9eab-6e460a02d1f1'   # Visual Studio
        'af124e86-4e96-495a-b70a-90f90ab96707'   # OneDrive SyncEngine
        '9bc3ab49-b65d-410a-85ad-de819febfddc'   # SharePoint Online Web Client Extensibility
        'Office365'                              # Graph "Office 365" app bundle token
        'MicrosoftAdminPortals'
        'All'
        'None'
    )) { [void]$ids.Add($id) }

    # Built-in directory role template ids (and their names) are global constants.
    $refPack = Join-Path $PSScriptRoot '../../assets/reference/privileged-roles.json'
    if (Test-Path -LiteralPath $refPack) {
        try {
            $pack = Get-Content -LiteralPath $refPack -Raw | ConvertFrom-Json -Depth 10 -AsHashtable
            foreach ($bucket in @('highlyPrivilegedRoles', 'additionalSensitiveRoles', 'highlyPrivileged', 'additionalSensitive', 'roles')) {
                foreach ($r in _NmArr (_NmGet $pack $bucket)) {
                    $rid = _NmGet $r 'id'; if (-not $rid) { $rid = _NmGet $r 'roleTemplateId' }
                    $rn = _NmGet $r 'name'; if (-not $rn) { $rn = _NmGet $r 'displayName' }
                    if ($rid) { [void]$ids.Add("$rid") }
                    if ($rn) { [void]$names.Add("$rn") }
                }
            }
        }
        catch { }
    }
    foreach ($n in @(
        'Global Administrator', 'Global Reader', 'Privileged Role Administrator',
        'Privileged Authentication Administrator', 'Security Administrator',
        'Security Reader', 'Conditional Access Administrator', 'User Administrator',
        'Application Administrator', 'Cloud Application Administrator',
        'Exchange Administrator', 'SharePoint Administrator', 'Intune Administrator',
        'Helpdesk Administrator', 'Authentication Administrator', 'Billing Administrator',
        'Hybrid Identity Administrator', 'Directory Synchronization Accounts'
    )) { [void]$names.Add($n) }

    $script:CapWellKnown = @{ ids = $ids; names = $names }
    return $script:CapWellKnown
}

function Test-CapWellKnownId {
<#
.SYNOPSIS
    True when the value is a Microsoft-global identifier that must not be masked.
#>
    [CmdletBinding()]
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }
    return (Get-CapWellKnownIdSet).ids.Contains($Value)
}

# Property names known to carry an identity, a location or a naming
# convention. Used by the structural sweep so unfamiliar payload shapes still
# get their names lifted into the dictionary.
$script:CapNameBearingProps = @(
    'displayName', 'userDisplayName', 'principalDisplayName', 'resourceDisplayName',
    'appDisplayName', 'roleDisplayName', 'groupDisplayName', 'name', 'label',
    'userPrincipalName', 'principalName', 'signInName', 'mail', 'mailNickname',
    'givenName', 'surname', 'onPremisesSamAccountName', 'onPremisesUserPrincipalName',
    'description', 'rule', 'cidrAddress', 'address', 'lowerAddress', 'upperAddress',
    'ipAddress', 'city'
)

$script:CapIdBearingProps = @('id', 'userId', 'principalId', 'objectId', 'appId', 'groupId', 'resourceId')

function _CapIsScalar {
<#
    A leaf value: nothing inside it to walk. Covers every ValueType (numbers,
    bool, datetime, DateTimeOffset, guid, enums, timespan) plus the reference
    scalars a Graph payload can carry. Checking this explicitly matters because
    $x.PSObject.Properties.Count throws on scalars under Set-StrictMode Latest.
#>
    param($Node)
    if ($null -eq $Node) { return $true }
    return ($Node -is [string] -or $Node -is [ValueType] -or $Node -is [uri] -or
        $Node -is [System.Text.RegularExpressions.Regex] -or $Node -is [scriptblock])
}

function _CapSweepNames {
    param($Node, [scriptblock]$Add, [int]$Depth = 0)

    if ($Depth -gt 40 -or $null -eq $Node) { return }

    if (_CapIsScalar $Node) { return }

    if ($Node -is [System.Collections.IDictionary]) {
        $ownId = ''
        foreach ($idProp in $script:CapIdBearingProps) {
            if ($Node.Contains($idProp) -and $Node[$idProp] -is [string] -and $Node[$idProp]) {
                $ownId = "$($Node[$idProp])"
                break
            }
        }
        foreach ($k in @($Node.Keys)) {
            $v = $Node[$k]
            if ($v -is [string] -and $script:CapNameBearingProps -contains $k) {
                $type = switch -Regex ($k) {
                    'PrincipalName$|^mail$|^signInName$' { 'upn'; break }
                    '^description$' { 'description'; break }
                    '^rule$' { 'devicerule'; break }
                    '[Aa]ddress$' { 'iprange'; break }
                    default { 'object' }
                }
                # Only a displayName-style field owns the object's id; other
                # strings get their own alias so tokens stay unambiguous.
                $idForValue = if ($k -match 'displayName$|^name$' ) { $ownId } else { '' }
                & $Add $v $idForValue $type
            }
            else {
                _CapSweepNames -Node $v -Add $Add -Depth ($Depth + 1)
            }
        }
        return
    }

    if ($Node -is [System.Collections.IEnumerable]) {
        foreach ($item in $Node) { _CapSweepNames -Node $item -Add $Add -Depth ($Depth + 1) }
        return
    }

    $props = @($Node.PSObject.Properties)
    if ($props.Count) {
        $bag = [ordered]@{}
        foreach ($p in $props) { $bag[$p.Name] = $p.Value }
        _CapSweepNames -Node $bag -Add $Add -Depth ($Depth + 1)
    }
}

function _CapBuildIdAliases {
    param($Source, $Entries, [string]$TenantId, $Existing)

    $aliases = [ordered]@{}
    $counters = @{}
    if ($Existing) {
        foreach ($k in (_NmKeys $Existing)) {
            $aliases[$k] = "$($Existing[$k])"
            if ("$($Existing[$k])" -match '^([A-Z]+)-(\d+)$') {
                $t = $Matches[1]; $n = [int]$Matches[2]
                if (-not $counters.ContainsKey($t) -or $counters[$t] -lt $n) { $counters[$t] = $n }
            }
        }
    }

    $next = {
        param([string]$Type)
        $key = $Type.ToUpperInvariant()
        if (-not $counters.ContainsKey($key)) { $counters[$key] = 0 }
        $counters[$key]++
        return ('{0}-{1:d3}' -f $key, $counters[$key])
    }

    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($k in $aliases.Keys) { [void]$seen.Add($k) }

    # Structural typing wins over the dictionary entry: an id found in
    # Source.policies is a policy even if it reached the dictionary through the
    # generic nameMap, so the alias reads POL-002 rather than OBJ-017.
    $typeById = @{}
    foreach ($pair in @(@{ k = 'policies'; t = 'pol' }, @{ k = 'namedLocations'; t = 'loc' },
            @{ k = 'authenticationStrengths'; t = 'str' }, @{ k = 'authenticationContexts'; t = 'ctx' })) {
        foreach ($o in _NmArr (_NmGet $Source $pair.k)) {
            $oid = "$(_NmGet $o 'id')"
            if ($oid) { $typeById[$oid] = $pair.t }
        }
    }

    # The tenant id is claimed first so it always gets the TENANT-001 alias,
    # rather than an anonymous OBJ-nnn from the general scan below.
    if ($TenantId -and $seen.Add($TenantId)) {
        $aliases[$TenantId] = & $next 'tenant'
    }

    $json = $Source | ConvertTo-Json -Depth 30
    foreach ($m in $script:CapGuidRegex.Matches($json)) {
        $g = $m.Value
        if (Test-CapWellKnownId -Value $g) { continue }
        if (-not $seen.Add($g)) { continue }
        $type = 'obj'
        if ($typeById.ContainsKey($g)) {
            $type = $typeById[$g]
        }
        elseif ($Entries) {
            $entry = $Entries.Values | Where-Object { $_.id -and $_.id -eq $g } | Select-Object -First 1
            if ($entry) {
                $type = switch ($entry.type) {
                    'policy' { 'pol' }
                    'location' { 'loc' }
                    'authstrength' { 'str' }
                    'authcontext' { 'ctx' }
                    default { 'obj' }
                }
            }
        }
        $aliases[$g] = & $next $type
    }
    return $aliases
}

function Add-CapIdAliases {
<#
.SYNOPSIS
    Populate a dictionary's alias map from a source document, so an already
    written (name-free but id-bearing) artifact can be pseudonymized later.

.DESCRIPTION
    Used when the safe bundle is assembled after the run: the dictionary written
    at export time carries names only, and the aliases that remove the last
    tenant-correlatable identifiers are added here. Existing aliases are kept, so
    calling this repeatedly is stable and re-hydration keeps working.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Dictionary,
        [Parameter(Mandatory)]$Source
    )
    $entries = _NmGet $Dictionary 'entries'
    $tenantId = ''
    $meta = _NmGet $Source 'metadata'
    if ($meta) { $tenantId = "$(_NmGet $meta 'tenantId')" }
    $existing = _NmGet $Dictionary 'idAliases'
    $Dictionary['idAliases'] = _CapBuildIdAliases -Source $Source -Entries $entries -TenantId $tenantId -Existing $existing
    $Dictionary['pseudonymized'] = $true
    return $Dictionary
}

function New-CapNameDictionary {
<#
.SYNOPSIS
    Build the GUID/alias -> name dictionary for an export.

.DESCRIPTION
    Collects every tenant-identifying name reachable from the export: the
    resolved name map, policy display names, named-location names and IP ranges,
    authentication strength and context names, directory enrichment (user and
    group display names, UPNs), authentication-method rows, the operator account
    and the tenant id.

    Each entry maps a token to the real value. The token is the object's own id
    where one exists (so the safe export stays structurally identical), otherwise
    a synthetic alias such as IPRANGE-001.

.PARAMETER Pseudonymize
    Also allocate an alias for every tenant-specific object id, so the safe
    artifact carries no tenant-correlatable GUID. The alias -> id -> name chain is
    recorded, keeping re-hydration possible from either form.

.OUTPUTS
    Hashtable dictionary document.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Export,
        [hashtable]$NameMap,
        $AuthMethods,
        [string]$Snapshot = '',
        [switch]$Pseudonymize
    )

    $wellKnown = Get-CapWellKnownIdSet
    $entries = [ordered]@{}   # token -> entry
    $byName = @{}             # name (lower) -> token
    $counters = @{}

    function _NextAlias {
        param([string]$Type)
        $key = $Type.ToUpperInvariant()
        if (-not $counters.ContainsKey($key)) { $counters[$key] = 0 }
        $counters[$key]++
        return ('{0}-{1:d3}' -f $key, $counters[$key])
    }

    function _Add {
        param([string]$Name, [string]$Id, [string]$Type)
        if ([string]::IsNullOrWhiteSpace($Name)) { return }
        $trimmed = "$Name".Trim()
        if ($trimmed.Length -lt 2) { return }
        if ($wellKnown.names.Contains($trimmed)) { return }
        if ($byName.ContainsKey($trimmed.ToLowerInvariant())) { return }
        # A value that is itself an id needs no dictionary entry.
        if ($trimmed -eq $Id) { return }

        $token = if ($Id -and -not (Test-CapWellKnownId -Value $Id)) { $Id } else { _NextAlias -Type $Type }
        if ($entries.Contains($token)) {
            $existing = $entries[$token]
            if ($existing.name -ne $trimmed) { $token = _NextAlias -Type $Type }
        }
        if (-not $entries.Contains($token)) {
            $entries[$token] = [ordered]@{ token = $token; type = $Type; id = $Id; name = $trimmed }
        }
        $byName[$trimmed.ToLowerInvariant()] = $token
    }

    if ($NameMap) {
        foreach ($id in $NameMap.Keys) { _Add -Name "$($NameMap[$id])" -Id "$id" -Type 'object' }
    }

    $meta = _NmGet $Export 'metadata'
    if ($meta) {
        $account = _NmGet $meta 'account'
        if ($account) { _Add -Name "$account" -Id $null -Type 'account' }
    }

    foreach ($p in _NmArr (_NmGet $Export 'policies')) {
        _Add -Name "$(_NmGet $p 'displayName')" -Id "$(_NmGet $p 'id')" -Type 'policy'
        $desc = _NmGet $p 'description'
        if ($desc) { _Add -Name "$desc" -Id $null -Type 'description' }
        $conds = _NmGet $p 'conditions'
        $devices = _NmGet $conds 'devices'
        $filter = _NmGet $devices 'deviceFilter'
        $rule = _NmGet $filter 'rule'
        if ($rule) { _Add -Name "$rule" -Id $null -Type 'devicerule' }
    }

    foreach ($nl in _NmArr (_NmGet $Export 'namedLocations')) {
        $nlId = "$(_NmGet $nl 'id')"
        _Add -Name "$(_NmGet $nl 'displayName')" -Id $nlId -Type 'location'
        foreach ($r in _NmArr (_NmGet $nl 'ipRanges')) {
            foreach ($key in @('cidrAddress', 'address', 'lowerAddress', 'upperAddress')) {
                $v = _NmGet $r $key
                if ($v) { _Add -Name "$v" -Id $null -Type 'iprange' }
            }
        }
        foreach ($c in _NmArr (_NmGet $nl 'countriesAndRegions')) { _Add -Name "$c" -Id $null -Type 'country' }
    }

    foreach ($a in _NmArr (_NmGet $Export 'authenticationStrengths')) {
        _Add -Name "$(_NmGet $a 'displayName')" -Id "$(_NmGet $a 'id')" -Type 'authstrength'
    }
    foreach ($a in _NmArr (_NmGet $Export 'authenticationContexts')) {
        _Add -Name "$(_NmGet $a 'displayName')" -Id "$(_NmGet $a 'id')" -Type 'authcontext'
    }

    $enrich = _NmGet $Export 'enrichment'
    if ($enrich) {
        foreach ($bucket in @('users', 'groups', 'servicePrincipals', 'roles', 'roleAssignments')) {
            $b = _NmGet $enrich $bucket
            if ($null -eq $b) { continue }
            # Enrichment buckets are wrapped as { available, error, data: [...] }.
            $rows = if ($b -is [System.Collections.IDictionary] -and $b.Contains('data')) { _NmArr $b['data'] } else { _NmArr $b }
            foreach ($o in $rows) {
                $oid = "$(_NmGet $o 'id')"
                if (-not $oid) { $oid = "$(_NmGet $o 'principalId')" }
                _Add -Name "$(_NmGet $o 'displayName')" -Id $oid -Type 'object'
                $upn = _NmGet $o 'userPrincipalName'
                if ($upn) { _Add -Name "$upn" -Id $null -Type 'upn' }
            }
        }
    }

    if ($AuthMethods) {
        $amUsers = _NmGet $AuthMethods 'users'
        if ($amUsers -is [System.Collections.IDictionary] -and $amUsers.Contains('data')) { $amUsers = $amUsers['data'] }
        foreach ($u in _NmArr $amUsers) {
            $uid = "$(_NmGet $u 'id')"
            _Add -Name "$(_NmGet $u 'displayName')" -Id $uid -Type 'object'
            $upn = _NmGet $u 'userPrincipalName'
            if ($upn) { _Add -Name "$upn" -Id $null -Type 'upn' }
        }
    }

    # Structural sweep: the targeted collectors above know the shapes we care
    # about, but Graph adds fields over time and enrichment payloads vary. This
    # walks the whole graph and picks up any property whose name is known to
    # carry an identity, so a new field cannot silently leak.
    _CapSweepNames -Node $Export -Add ${function:_Add}

    $idAliases = [ordered]@{}
    if ($Pseudonymize) {
        $idAliases = _CapBuildIdAliases -Source $Export -Entries $entries -TenantId "$(_NmGet $meta 'tenantId')"
    }

    return [ordered]@{
        tool          = 'CAPVisualizer'
        kind          = 'nameDictionary'
        schemaVersion = '1.0'
        snapshot      = $Snapshot
        generatedUtc  = (Get-Date).ToUniversalTime().ToString('o')
        pseudonymized = [bool]$Pseudonymize
        entries       = $entries
        idAliases     = $idAliases
        count         = $entries.Count
    }
}

function _CapBoundaryOk {
<#
    Boundary rule for a candidate name match. Never match inside a word or an
    address (so "contoso" in "user@contoso.com" is not clipped), but a trailing
    sentence period must not block the match ("... contains Break Glass Admin."
    ends a sentence, it is not a domain). Expressed in code rather than as a
    lookaround because the DFA regex engine below does not support lookarounds.
#>
    param([string]$Text, [int]$Index, [int]$Length)

    if ($Index -gt 0) {
        $prev = $Text[$Index - 1]
        if ([char]::IsLetterOrDigit($prev) -or $prev -eq '_' -or $prev -eq '@' -or $prev -eq '-') { return $false }
        if ($prev -eq '.' -and $Index -gt 1) {
            $prev2 = $Text[$Index - 2]
            if ([char]::IsLetterOrDigit($prev2) -or $prev2 -eq '_') { return $false }
        }
    }
    $end = $Index + $Length
    if ($end -lt $Text.Length) {
        $next = $Text[$end]
        if ([char]::IsLetterOrDigit($next) -or $next -eq '_' -or $next -eq '@' -or $next -eq '-') { return $false }
        if ($next -eq '.' -and ($end + 1) -lt $Text.Length) {
            $next2 = $Text[$end + 1]
            if ([char]::IsLetterOrDigit($next2) -or $next2 -eq '_') { return $false }
        }
    }
    return $true
}

function _CapNameMatchers {
<#
    Build the matcher set once per masking session.

    A real tenant yields tens of thousands of names, so testing every name
    against every string does not scale - that measured ~5 minutes for a single
    findings file. Names are instead compiled into a handful of alternation
    regexes running in DFA mode (RegexOptions.NonBacktracking), where scan cost
    is linear in the length of the text and independent of how many names the
    pattern holds. The same workload then takes well under a second.

    Chunking is required because the DFA has a node-count limit; a chunk that
    still exceeds it is split further, and falls back to the backtracking engine
    only if it cannot be split any smaller.
#>
    param($Dictionary)

    $entries = _NmGet $Dictionary 'entries'
    $byName = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
    $textNames = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($token in $entries.Keys) {
        $e = $entries[$token]
        $name = "$(_NmGet $e 'name')"
        if ([string]::IsNullOrEmpty($name)) { continue }
        if (-not $byName.ContainsKey($name)) { $byName[$name] = "$token" }
        if ($name.Length -ge $script:CapMinTextNameLength -and $seen.Add($name)) {
            [void]$textNames.Add($name)
        }
    }

    # Longest first so a longer name is consumed before a shorter one it
    # contains ("Contoso Admins" before "Contoso"). Note: -Unique would dedupe by
    # the sort key (Length) and drop all but one name per length, so duplicates
    # are filtered above instead.
    $ordered = @($textNames | Sort-Object -Property Length -Descending)

    $regexes = [System.Collections.Generic.List[regex]]::new()
    _CapAddNameRegexes -Names $ordered -Size $script:CapRegexChunkSize -Target $regexes

    $aliases = _NmGet $Dictionary 'idAliases'
    $aliasTable = $null
    if ($aliases) {
        $aliasTable = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($k in (_NmKeys $aliases)) { $aliasTable["$k"] = "$($aliases[$k])" }
        if ($aliasTable.Count -eq 0) { $aliasTable = $null }
    }

    return [pscustomobject]@{
        ByName  = $byName
        Regexes = $regexes
        Aliases = $aliasTable
        Count   = $byName.Count
    }
}

function _CapAddNameRegexes {
    param([string[]]$Names, [int]$Size, $Target)

    if (-not $Names -or $Names.Count -eq 0) { return }
    $dfa = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
        [System.Text.RegularExpressions.RegexOptions]::NonBacktracking

    for ($i = 0; $i -lt $Names.Count; $i += $Size) {
        $slice = $Names[$i..([Math]::Min($i + $Size - 1, $Names.Count - 1))]
        $alt = ($slice | ForEach-Object { [regex]::Escape($_) }) -join '|'
        try {
            $Target.Add([regex]::new($alt, $dfa))
        }
        catch {
            if ($slice.Count -gt 1) {
                # Too many automaton nodes for one chunk - split and retry.
                _CapAddNameRegexes -Names $slice -Size ([Math]::Max(1, [int]($slice.Count / 4))) -Target $Target
            }
            else {
                $Target.Add([regex]::new($alt, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase))
            }
        }
    }
}

function _CapMaskString {
    param([string]$Value, $Matchers, $IdAliases)

    if ([string]::IsNullOrEmpty($Value)) { return $Value }
    $out = $Value

    if ($Matchers.ByName.ContainsKey($out)) {
        # Exact whole-value match still has to go through id aliasing below,
        # otherwise a pseudonymized bundle would keep the raw object id here.
        $out = $Matchers.ByName[$out]
    }
    elseif ($out.Length -ge $script:CapMinTextNameLength) {
        $byName = $Matchers.ByName
        foreach ($rx in $Matchers.Regexes) {
            $matches = $rx.Matches($out)
            if ($matches.Count -eq 0) { continue }
            $sb = [System.Text.StringBuilder]::new()
            $pos = 0
            foreach ($m in $matches) {
                if ($m.Index -lt $pos) { continue }
                if (-not (_CapBoundaryOk -Text $out -Index $m.Index -Length $m.Length)) { continue }
                $token = $byName[$m.Value]
                if (-not $token) { continue }
                [void]$sb.Append($out, $pos, $m.Index - $pos)
                [void]$sb.Append($token)
                $pos = $m.Index + $m.Length
            }
            if ($pos -eq 0) { continue }
            [void]$sb.Append($out, $pos, $out.Length - $pos)
            $out = $sb.ToString()
        }
    }

    $aliases = if ($null -ne $IdAliases) { $IdAliases } else { $Matchers.Aliases }
    if ($aliases -and $aliases.Count) {
        $out = $script:CapGuidRegex.Replace($out, {
                param($match)
                $g = $match.Value
                if ($aliases.ContainsKey($g)) { return $aliases[$g] }
                return $g
            })
    }
    return $out
}

function _CapWalkKey {
    param($Key, [string]$Mode, $Matchers, $IdAliases, $Dictionary)
    if ($Key -isnot [string]) { return $Key }
    if ($Mode -eq 'mask') { return (_CapMaskString -Value $Key -Matchers $Matchers -IdAliases $IdAliases) }
    return (Restore-CapNameText -Text $Key -Dictionary $Dictionary)
}

function _CapWalk {
    param($Node, [ValidateSet('mask', 'restore')][string]$Mode, $Matchers, $IdAliases, $Dictionary, [int]$Depth = 0)

    if ($Depth -gt 40) { return $Node }
    if ($null -eq $Node) { return $null }

    if ($Node -is [string]) {
        if ($Mode -eq 'mask') { return (_CapMaskString -Value $Node -Matchers $Matchers -IdAliases $IdAliases) }
        return (Restore-CapNameText -Text $Node -Dictionary $Dictionary)
    }
    # Any value type (bool, numbers, datetime, DateTimeOffset, guid, enums) and a
    # handful of reference scalars are leaf nodes. A live Graph export carries
    # types the offline sample never does, and walking their properties would
    # both explode the shape and throw under StrictMode.
    if (_CapIsScalar $Node) { return $Node }

    if ($Node -is [System.Collections.IDictionary]) {
        $out = [ordered]@{}
        foreach ($k in @($Node.Keys)) {
            # Keys are transformed too: maps keyed by object id or display name
            # (nameMap being the obvious one) would otherwise leak through.
            $key = _CapWalkKey -Key $k -Mode $Mode -Matchers $Matchers -IdAliases $IdAliases -Dictionary $Dictionary
            if ($out.Contains($key)) { $key = $k }
            $out[$key] = _CapWalk -Node $Node[$k] -Mode $Mode -Matchers $Matchers -IdAliases $IdAliases -Dictionary $Dictionary -Depth ($Depth + 1)
        }
        return $out
    }

    if ($Node -is [System.Collections.IEnumerable]) {
        # Rebuild as an explicit array: a bare pipeline would unwrap a
        # single-element list into an object and an empty one into $null,
        # silently changing the shape of the export.
        $items = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $Node) {
            $items.Add((_CapWalk -Node $item -Mode $Mode -Matchers $Matchers -IdAliases $IdAliases -Dictionary $Dictionary -Depth ($Depth + 1)))
        }
        return , $items.ToArray()
    }

    $props = @($Node.PSObject.Properties)
    if ($props.Count) {
        $out = [ordered]@{}
        foreach ($p in $props) {
            $out[$p.Name] = _CapWalk -Node $p.Value -Mode $Mode -Matchers $Matchers -IdAliases $IdAliases -Dictionary $Dictionary -Depth ($Depth + 1)
        }
        return $out
    }

    return $Node
}

function ConvertTo-CapSafeObject {
<#
.SYNOPSIS
    Return a copy of an object graph with every dictionary name (and, when the
    dictionary is pseudonymized, every tenant-specific GUID) replaced by its
    token. Structural fields and generated prose are handled in one pass.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$InputObject,
        [Parameter(Mandatory)]$Dictionary
    )
    $matchers = _CapNameMatchers -Dictionary $Dictionary
    # The alias lookup lives on the matcher set as a case-insensitive hashtable;
    # passing the raw ordered dictionary down would reintroduce a linear scan.
    return _CapWalk -Node $InputObject -Mode 'mask' -Matchers $matchers -IdAliases $null -Dictionary $Dictionary
}

function ConvertFrom-CapSafeObject {
<#
.SYNOPSIS
    Inverse of ConvertTo-CapSafeObject: replace tokens with real names.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$InputObject,
        [Parameter(Mandatory)]$Dictionary
    )
    return _CapWalk -Node $InputObject -Mode 'restore' -Matchers @() -IdAliases $null -Dictionary $Dictionary
}

function Restore-CapNameText {
<#
.SYNOPSIS
    Replace tokens (aliases or object ids) in a block of text with the real
    names from the dictionary. Works inside markdown tables, HTML attributes and
    fenced code blocks, and tolerates a shortened GUID (first segment).

.PARAMETER Strict
    Treat an unresolved alias-shaped token as an error the caller should report.
#>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)]$Dictionary
    )
    if ([string]::IsNullOrEmpty($Text)) { return $Text }

    $entries = _NmGet $Dictionary 'entries'
    $aliases = _NmGet $Dictionary 'idAliases'

    $out = $Text

    # Alias -> id first, so pseudonymized output resolves through to a name.
    if ($aliases -and $aliases.Count) {
        $reverse = @{}
        foreach ($id in $aliases.Keys) { $reverse[[string]$aliases[$id]] = [string]$id }
        foreach ($alias in ($reverse.Keys | Sort-Object { $_.Length } -Descending)) {
            $out = [regex]::Replace($out, '(?i)(?<![\w-])' + [regex]::Escape($alias) + '(?![\w-])', $reverse[$alias])
        }
    }

    $tokens = @($entries.Keys | Sort-Object { "$_".Length } -Descending)
    foreach ($token in $tokens) {
        $name = "$(_NmGet $entries[$token] 'name')"
        if ([string]::IsNullOrEmpty($name)) { continue }
        $out = [regex]::Replace($out, '(?i)(?<![\w-])' + [regex]::Escape("$token") + '(?![\w-])', { param($m) $name }.GetNewClosure())
    }
    return $out
}

function Get-CapUnresolvedTokens {
<#
.SYNOPSIS
    Alias-shaped tokens (TYPE-001) left in text that the dictionary could not
    resolve - reported rather than silently ignored.
#>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return @() }
    $found = [regex]::Matches($Text, '\b(?:OBJ|POL|LOC|STR|CTX|USER|GROUP|IPRANGE|COUNTRY|ACCOUNT|DESCRIPTION|DEVICERULE|UPN|TENANT)-\d{3}\b')
    return @($found | ForEach-Object { $_.Value } | Sort-Object -Unique)
}

function Test-CapNameLeak {
<#
.SYNOPSIS
    Verify that a supposedly safe artifact contains none of the dictionary's
    real values, and no unallowlisted GUID or IP-shaped string when the bundle is
    pseudonymized. This is the guarantee behind the safe bundle - a run that
    fails here must not be uploaded.

.OUTPUTS
    Array of violation records (empty when clean).
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Dictionary,
        [string[]]$Path,
        $InputObject,
        [switch]$RequirePseudonymized
    )

    $violations = [System.Collections.Generic.List[object]]::new()
    $entries = _NmGet $Dictionary 'entries'
    $wellKnown = Get-CapWellKnownIdSet

    $docs = [System.Collections.Generic.List[object]]::new()
    if ($InputObject) { $docs.Add([pscustomobject]@{ Source = '<object>'; Text = ($InputObject | ConvertTo-Json -Depth 30) }) }
    foreach ($p in @($Path)) {
        if (-not $p) { continue }
        if (-not (Test-Path -LiteralPath $p)) { continue }
        $docs.Add([pscustomobject]@{ Source = $p; Text = (Get-Content -LiteralPath $p -Raw) })
    }

    # One alternation scan per document instead of one IndexOf per name: a real
    # tenant dictionary holds tens of thousands of names and the leak test runs
    # over every file in the bundle.
    $tokenByName = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
    $leakNames = [System.Collections.Generic.List[string]]::new()
    foreach ($token in $entries.Keys) {
        $name = "$(_NmGet $entries[$token] 'name')"
        if ([string]::IsNullOrWhiteSpace($name) -or $name.Length -lt 3) { continue }
        if ($tokenByName.ContainsKey($name)) { continue }
        $tokenByName[$name] = "$token"
        [void]$leakNames.Add($name)
    }
    $leakRegexes = [System.Collections.Generic.List[regex]]::new()
    _CapAddNameRegexes -Names @($leakNames | Sort-Object -Property Length -Descending) `
        -Size $script:CapRegexChunkSize -Target $leakRegexes

    foreach ($doc in $docs) {
        # Deliberately no boundary rule here: a real name appearing anywhere,
        # even inside a larger word, is a leak.
        foreach ($rx in $leakRegexes) {
            foreach ($m in $rx.Matches($doc.Text)) {
                $hit = $m.Value
                $token = $tokenByName[$hit]
                if (-not $token) { continue }
                $violations.Add([ordered]@{ source = $doc.Source; kind = 'name'; value = $hit; token = $token })
            }
        }
        if ($RequirePseudonymized) {
            foreach ($m in $script:CapGuidRegex.Matches($doc.Text)) {
                if (Test-CapWellKnownId -Value $m.Value) { continue }
                $violations.Add([ordered]@{ source = $doc.Source; kind = 'guid'; value = $m.Value; token = $null })
            }
            foreach ($m in [regex]::Matches($doc.Text, '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?\b')) {
                $violations.Add([ordered]@{ source = $doc.Source; kind = 'ip'; value = $m.Value; token = $null })
            }
        }
    }

    return @($violations | Group-Object { "$($_.kind)|$($_.value)" } | ForEach-Object { $_.Group[0] })
}

function Import-CapNameDictionary {
<#
.SYNOPSIS
    Load a dictionary from disk, or find it next to an export (raw/names.json).
#>
    [CmdletBinding()]
    param([string]$Path, [string]$NearExport)

    $candidate = $Path
    if (-not $candidate -and $NearExport) {
        $dir = if (Test-Path -LiteralPath $NearExport -PathType Container) { $NearExport } else { Split-Path -Parent $NearExport }
        foreach ($rel in @('names.json', 'raw/names.json', '../raw/names.json')) {
            $try = Join-Path $dir $rel
            if (Test-Path -LiteralPath $try) { $candidate = $try; break }
        }
    }
    if (-not $candidate -or -not (Test-Path -LiteralPath $candidate)) { return $null }

    $doc = Get-Content -LiteralPath $candidate -Raw | ConvertFrom-Json -Depth 20 -AsHashtable
    if ("$(_NmGet $doc 'kind')" -ne 'nameDictionary') {
        throw "Not a CAPVisualizer name dictionary: $candidate"
    }
    return $doc
}

Export-ModuleMember -Function New-CapNameDictionary, ConvertTo-CapSafeObject, ConvertFrom-CapSafeObject, `
    Restore-CapNameText, Test-CapNameLeak, Import-CapNameDictionary, Get-CapWellKnownIdSet, `
    Test-CapWellKnownId, Get-CapUnresolvedTokens, Add-CapIdAliases
