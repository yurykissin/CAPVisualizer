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

# Dictionary-independent leak detectors. These do not consult names.json, so
# they catch tenant data the masker was never told about - the class of leak the
# dictionary-driven check can never see. Each is precompiled once. None uses a
# lookaround, so none depends on a regex engine that supports one.
#
# Email and UPN. Requires a local part before the @, so a Graph annotation key
# such as "@odata.type" (nothing before the @) is not an email. Annotation keys
# that do carry a local part, such as "termsOfUse@odata.context", are filtered
# by the @odata. check in _CapPatternHits.
$script:CapEmailRegex = [regex]::new(
    '[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}',
    [System.Text.RegularExpressions.RegexOptions]::Compiled)

# IPv6, full 8-group form or a compressed form with a leading group and "::".
# An optional CIDR suffix and zone id are included. Timestamps such as
# "19:13:32" cannot match: they have two colons and no "::", while the full form
# needs seven colons and the compressed form needs the double colon.
$script:CapIpv6Regex = [regex]::new(
    '(?i)(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?)(?:%[0-9a-z]+)?(?:/\d{1,3})?',
    [System.Text.RegularExpressions.RegexOptions]::Compiled)

# Fully qualified domain name. Deliberately narrow to keep false positives down:
#   - the final label (the TLD) must be lower case, which excludes Graph enum
#     and permission shapes whose last segment is capitalised or camel case,
#     for example "Policy.Read.All" and "#microsoft.graph.ipNamedLocation".
#   - at least two dots are required, which excludes single-dot shapes such as
#     "odata.type", "microsoft.graph" and a bare file name like "export.json".
# The archetypes this must catch - "contoso.onmicrosoft.com" and an internal
# host like "CONTOSO-FIN-07.corp.contoso.local" - all have two or more dots and
# a lower case TLD. A bare two-label domain is normally carried inside an email
# or UPN, which the email detector already reports.
$script:CapFqdnRegex = [regex]::new(
    '\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.){2,}[a-z]{2,24}\b',
    [System.Text.RegularExpressions.RegexOptions]::Compiled)

# Microsoft-owned public domains that are not tenant data. Matched on a label
# boundary (equal to, or ending in ".<apex>") so a tenant vanity domain such as
# "contoso.onmicrosoft.com" is NOT swallowed by "microsoft.com": the character
# before "microsoft.com" there is a letter, not a dot. onmicrosoft.com and
# sharepoint.com are intentionally absent - a host under either carries the
# tenant name and must be reported.
$script:CapFqdnAllowApex = @(
    'microsoft.com', 'microsoftonline.com', 'microsoftonline-p.com',
    'windows.net', 'windows.com', 'windowsazure.com', 'azure.com', 'azure.net',
    'office.com', 'office365.com', 'live.com', 'msft.net', 'msftauth.net',
    'msauth.net', 'msidentity.com', 'msn.com', 'bing.com', 'skype.com',
    'azureedge.net', 'trafficmanager.net',
    # Standards bodies whose hosts appear in $schema urls the tool emits itself,
    # for example the SARIF schema in tests.sarif.json. These are published
    # constants in this tool's own output, not tenant data.
    'schemastore.org', 'json-schema.org', 'w3.org', 'oasis-open.org'
)

# A dotted string ending in one of these is a file name, not a host. The FQDN
# pattern otherwise reads "sarif-2.1.0.json" as a domain, because it has two
# dots and a lower case tail. Keeping this narrow, only extensions this tool
# actually emits or consumes, so a real domain cannot be excused by accident.
$script:CapFqdnFileTails = @(
    'json', 'md', 'html', 'htm', 'js', 'css', 'csv', 'xml', 'txt', 'log',
    'ps1', 'psm1', 'psd1', 'py', 'yml', 'yaml', 'zip', 'png', 'svg', 'sarif'
)

# Names per alternation regex. Sized to stay under the DFA node limit for
# typical display names while keeping the number of scans per string small.
$script:CapRegexChunkSize = 1000

# Minimum length for a name to be substituted inside free text. Short names
# ("IT", "All") appear as substrings of ordinary prose and would corrupt it.
# Exact whole-value matches are substituted regardless of length.
$script:CapMinTextNameLength = 5
$script:CapRestoreCacheKey = $null
$script:CapRestoreCacheValue = $null

# Schema vocabulary: values that carry meaning in the data model rather than
# naming a tenant object. A tenant is free to call a group "User", "Block" or
# "Test", and when it does, masking rewrites every structural field holding
# that literal - an exclusion record's "type": "user" became the group's guid
# in a real run, so the safe bundle claimed a type that does not exist.
#
# These words are therefore never substituted. Nothing is lost: knowing a
# tenant has a group called "User" identifies no one, while a corrupted schema
# value silently misinforms every downstream reader. The dictionary entry is
# kept, so restoring an id still yields the real name.
$script:CapReservedVocabulary = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]@(
        # principal and target kinds
        'user', 'users', 'group', 'groups', 'role', 'roles', 'guest', 'guests',
        'app', 'apps', 'application', 'applications', 'device', 'devices',
        'location', 'locations', 'platform', 'platforms', 'principal',
        # selectors and states
        'all', 'none', 'any', 'other', 'unknown', 'enabled', 'disabled',
        'enabledforreportingbutnotenforced', 'report', 'reportonly',
        'included', 'excluded', 'include', 'exclude',
        # controls and outcomes
        'block', 'grant', 'allow', 'deny', 'require', 'session', 'control',
        'controls', 'pass', 'fail', 'manual', 'present', 'absent', 'gap',
        'ok', 'error', 'warn', 'warning', 'skip', 'skipped',
        # severities and scoring
        'critical', 'high', 'medium', 'low', 'info', 'informational', 'none',
        # analysis vocabulary
        'policy', 'policies', 'exact', 'overlap', 'merge', 'duplicate',
        'deadweight', 'summary', 'detail', 'finding', 'findings', 'evidence',
        'compliance', 'consolidation', 'audit', 'baseline', 'control',
        # words the tool itself writes into generated reasons and statements
        'test', 'temp', 'temporary', 'demo', 'poc', 'old', 'new', 'default',
        'retire', 'obsolete', 'deprecated', 'delete', 'remove', 'check',
        # generic structure
        'name', 'type', 'id', 'kind', 'state', 'status', 'value', 'count',
        'true', 'false', 'null', 'yes', 'no'
    ),
    [System.StringComparer]::OrdinalIgnoreCase)

function Test-CapReservedName {
<#
.SYNOPSIS
    True when a display name is a schema vocabulary word that must never be
    substituted, because doing so rewrites structural values rather than
    tenant data.
#>
    [CmdletBinding()]
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $true }
    $trimmed = $Name.Trim()
    if ($script:CapReservedVocabulary.Contains($trimmed)) { return $true }
    # Microsoft's built-in authentication strength names are product vocabulary,
    # not tenant labels. They appear verbatim inside CISA SCuBA control
    # statements, so substituting them rewrites the standard's own text. A
    # tenant may create a custom strength with the same name; the name is still
    # not tenant information, and its id is masked either way.
    foreach ($n in (Get-CapBuiltinAuthStrengthMap).Values) {
        if ([string]::Equals($n, $trimmed, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

# Every alias prefix either minting site can produce. Both _NextAlias (long
# forms, used when a value has no id of its own) and _CapBuildIdAliases (short
# forms, used when pseudonymizing ids) draw from this list, and
# Get-CapUnresolvedTokens builds its detector from it. Keeping one list means a
# new alias type cannot be minted without also being detectable - the previous
# hard-coded detector silently missed OBJECT-, POLICY-, LOCATION-, AUTHSTRENGTH-
# and AUTHCONTEXT-prefixed tokens.
$script:CapAliasTypes = @(
    'OBJ', 'POL', 'LOC', 'STR', 'CTX', 'TENANT',
    'OBJECT', 'POLICY', 'LOCATION', 'AUTHSTRENGTH', 'AUTHCONTEXT',
    'USER', 'GROUP', 'IPRANGE', 'COUNTRY', 'ACCOUNT', 'DESCRIPTION',
    'DEVICERULE', 'UPN', 'APPRULE', 'EXTTENANT'
)

# Longest-first so an alternation cannot stop at a prefix of a longer type, and
# \d{3,} because aliases are minted with {0:d3} - a *minimum* width. Past 999
# objects of a class the token grows to four digits, which a \d{3} detector
# misses entirely. Enterprise tenants pass 999 users routinely.
$script:CapAliasTokenRegex = [regex](
    '\b(?:' + (($script:CapAliasTypes | Sort-Object -Property Length -Descending) -join '|') + ')-\d{3,}\b'
)

# Compiled matcher sets, keyed by dictionary instance. A weak table so a
# dictionary that goes out of scope takes its regexes with it rather than
# pinning tens of megabytes of automaton for the life of the session.
$script:CapMatcherCache = [System.Runtime.CompilerServices.ConditionalWeakTable[object, object]]::new()

# Cache for the well-known identifier set (StrictMode requires initialization).
$script:CapWellKnown = $null
$script:CapFirstPartyApps = $null
$script:CapBuiltinRoles = $null
$script:CapBuiltinAuthStrengths = $null

function _CapLoadFirstPartyApps {
<#
    Loads assets/reference/microsoft-first-party-apps.json once. Returns a
    hashtable with 'map' (id -> name, ordered) and 'tokens' (string[]). A
    missing or unreadable pack degrades to empty rather than throwing: the
    tool must still run, it just loses the friendly app names.
#>
    if ($script:CapFirstPartyApps) { return $script:CapFirstPartyApps }

    $map = [ordered]@{}
    $tokens = @()
    $pack = Join-Path $PSScriptRoot '../../assets/reference/microsoft-first-party-apps.json'
    if (Test-Path -LiteralPath $pack) {
        try {
            $data = Get-Content -LiteralPath $pack -Raw | ConvertFrom-Json -Depth 10 -AsHashtable
            foreach ($a in _NmArr (_NmGet $data 'apps')) {
                $aid = "$(_NmGet $a 'id')"
                $an = "$(_NmGet $a 'name')"
                if ($aid -and $an -and -not $map.Contains($aid)) { $map[$aid] = $an }
            }
            $tokens = @(_NmArr (_NmGet $data 'tokens') | ForEach-Object { "$_" } | Where-Object { $_ })
        }
        catch { }
    }

    $script:CapFirstPartyApps = @{ map = $map; tokens = $tokens }
    return $script:CapFirstPartyApps
}

function Get-CapFirstPartyAppMap {
<#
.SYNOPSIS
    Microsoft first-party application ids mapped to their published names.

.DESCRIPTION
    These are global Microsoft constants, identical in every tenant. They are
    not tenant data, so they are never masked as a name and they are seeded
    into every name dictionary. Without the seed a review that cites, say, the
    Device Registration Service id has no dictionary entry to restore from and
    the finished report reads as a bare guid.

.OUTPUTS
    OrderedDictionary of id -> display name.
#>
    [CmdletBinding()]
    param()
    return (_CapLoadFirstPartyApps).map
}

function Get-CapFirstPartyAppTokens {
<#
.SYNOPSIS
    Non-guid application selectors that Graph uses in place of an app id, such
    as All, None and Office365. Global constants, never masked.
#>
    [CmdletBinding()]
    param()
    return (_CapLoadFirstPartyApps).tokens
}

function _CapLoadBuiltinRoles {
<#
    Loads the built-in directory role template ids from the reference packs
    once. Returns an ordered id -> name map. Role template ids are Microsoft
    global constants: identical in every tenant, published, and not tenant
    data. Like the first-party app ids they must be seeded into every
    dictionary, otherwise a review that cites a role restores as a bare guid.
    A missing or unreadable pack degrades to empty rather than throwing.
#>
    if ($script:CapBuiltinRoles) { return $script:CapBuiltinRoles }

    $map = [ordered]@{}
    foreach ($packName in @('builtin-role-templates.json', 'privileged-roles.json')) {
        $path = Join-Path $PSScriptRoot "../../assets/reference/$packName"
        if (-not (Test-Path -LiteralPath $path)) { continue }
        try {
            $pack = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -Depth 10 -AsHashtable
            foreach ($bucket in @('roles', 'highlyPrivilegedRoles', 'additionalSensitiveRoles', 'highlyPrivileged', 'additionalSensitive')) {
                foreach ($r in _NmArr (_NmGet $pack $bucket)) {
                    $rid = _NmGet $r 'id'; if (-not $rid) { $rid = _NmGet $r 'roleTemplateId' }
                    $rn = _NmGet $r 'name'; if (-not $rn) { $rn = _NmGet $r 'displayName' }
                    if ($rid -and $rn -and -not $map.Contains("$rid")) { $map["$rid"] = "$rn" }
                }
            }
        }
        catch { }
    }

    $script:CapBuiltinRoles = $map
    return $script:CapBuiltinRoles
}

function Get-CapBuiltinRoleMap {
<#
.SYNOPSIS
    Built-in directory role template ids mapped to their published names.

.DESCRIPTION
    Global Microsoft constants, identical in every tenant, so they are never
    masked as tenant data and are seeded into every name dictionary. Without
    the seed a review that cites, say, the Global Administrator role template
    id has no dictionary entry to restore from and the finished report reads
    as a bare guid.

.OUTPUTS
    OrderedDictionary of role template id -> display name.
#>
    [CmdletBinding()]
    param()
    return (_CapLoadBuiltinRoles)
}

function Get-CapBuiltinAuthStrengthMap {
<#
.SYNOPSIS
    Microsoft's three built-in authentication strength ids mapped to their
    published names.

.DESCRIPTION
    Global constants, identical in every tenant. Their names also appear
    verbatim inside CISA SCuBA control statements, so masking them rewrites the
    standard's own text. A tenant-created custom strength has a tenant-specific
    id and is masked normally.

.OUTPUTS
    OrderedDictionary of id -> display name.
#>
    [CmdletBinding()]
    param()
    if ($script:CapBuiltinAuthStrengths) { return $script:CapBuiltinAuthStrengths }

    $map = [ordered]@{}
    $path = Join-Path $PSScriptRoot '../../assets/reference/builtin-auth-strengths.json'
    if (Test-Path -LiteralPath $path) {
        try {
            $pack = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -Depth 10 -AsHashtable
            foreach ($s in _NmArr (_NmGet $pack 'strengths')) {
                $sid = "$(_NmGet $s 'id')"; $sn = "$(_NmGet $s 'name')"
                if ($sid -and $sn -and -not $map.Contains($sid)) { $map[$sid] = $sn }
            }
        }
        catch { }
    }

    $script:CapBuiltinAuthStrengths = $map
    return $script:CapBuiltinAuthStrengths
}

function Get-CapGlobalConstantEntry {
<#
.SYNOPSIS
    Dictionary entries for values that are Microsoft-global rather than tenant
    data, keyed by their own identifier.

.DESCRIPTION
    Seeded into every name dictionary so that restoring a review always
    resolves them, in any tenant, including tenants that never referenced the
    app. The safe export still carries only the id: the name lives in the local
    dictionary, never in the uploaded file.

.OUTPUTS
    OrderedDictionary of id -> entry.
#>
    [CmdletBinding()]
    param()

    $entries = [ordered]@{}
    foreach ($app in (Get-CapFirstPartyAppMap).GetEnumerator()) {
        $entries[$app.Key] = [ordered]@{
            token  = $app.Key
            type   = 'msapp'
            id     = $app.Key
            name   = $app.Value
            global = $true
        }
    }
    foreach ($role in (Get-CapBuiltinRoleMap).GetEnumerator()) {
        if ($entries.Contains($role.Key)) { continue }
        $entries[$role.Key] = [ordered]@{
            token  = $role.Key
            type   = 'msrole'
            id     = $role.Key
            name   = $role.Value
            global = $true
        }
    }
    foreach ($s in (Get-CapBuiltinAuthStrengthMap).GetEnumerator()) {
        if ($entries.Contains($s.Key)) { continue }
        $entries[$s.Key] = [ordered]@{
            token  = $s.Key
            type   = 'msauthstrength'
            id     = $s.Key
            name   = $s.Value
            global = $true
        }
    }
    return $entries
}

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
    # Held in an asset pack rather than in code because the same list is needed
    # by the name dictionary, which seeds these ids so a review can always be
    # read back as names (see Get-CapGlobalConstantEntry).
    foreach ($app in (Get-CapFirstPartyAppMap).GetEnumerator()) { [void]$ids.Add($app.Key) }
    foreach ($t in (Get-CapFirstPartyAppTokens)) { [void]$ids.Add($t) }

    # Built-in directory role template ids (and their names) are global
    # constants. Held in asset packs rather than in code because the same list
    # is needed by the name dictionary, which seeds these ids so a review can
    # always be read back as names (see Get-CapGlobalConstantEntry).
    foreach ($role in (Get-CapBuiltinRoleMap).GetEnumerator()) {
        [void]$ids.Add($role.Key)
        [void]$names.Add($role.Value)
    }

    # Microsoft's three built-in authentication strengths, same reasoning.
    foreach ($s in (Get-CapBuiltinAuthStrengthMap).GetEnumerator()) {
        [void]$ids.Add($s.Key)
        [void]$names.Add($s.Value)
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

# Property names that are definitely identity-, location- or naming-bearing.
# The structural sweep no longer gates on this list (see _CapSweepNames): it is
# kept only to classify a lifted value into the right alias type. A property
# that is not listed here still gets examined, it just falls through to the
# generic 'object' type.
$script:CapNameBearingProps = @(
    'displayName', 'userDisplayName', 'principalDisplayName', 'resourceDisplayName',
    'appDisplayName', 'roleDisplayName', 'groupDisplayName', 'name', 'label',
    'userPrincipalName', 'principalName', 'signInName', 'mail', 'mailNickname',
    'givenName', 'surname', 'onPremisesSamAccountName', 'onPremisesUserPrincipalName',
    'description', 'rule', 'cidrAddress', 'address', 'lowerAddress', 'upperAddress',
    'ipAddress', 'city'
)

$script:CapIdBearingProps = @('id', 'userId', 'principalId', 'objectId', 'appId', 'groupId', 'resourceId')

# The structural sweep is deny-by-default: it examines every string property and
# lifts its value into the dictionary unless the property is on this skip list,
# so a Graph field this tool has never seen defaults to being masked rather than
# leaked. The old design was the opposite - a fixed allowlist of name-bearing
# properties - which meant any new or forgotten Graph field passed through
# unexamined and the failure got worse as the schema grew.
#
# The skip list is the small, deliberate set of properties known to carry
# structure, enums, ids, dates or tool metadata rather than tenant identity.
# Skipping them avoids masking values that must survive for the export to stay
# reviewable ('enabled', 'block', 'OR', 'All'). Ids and dates are additionally
# caught by the value-shape guards below, so an unknown id- or date-valued field
# is safe even if it is not named here. Enum-valued fields have no reliable value
# shape, which is why they must be named explicitly.
$script:CapSweepSkipProps = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]@(
        # Object ids and reference-id collections (values are guids or the
        # well-known tokens All/None/Office365, which must not be aliased).
        'id', 'userId', 'principalId', 'objectId', 'appId', 'groupId', 'resourceId',
        'tenantId', 'templateId', 'policyId', 'profileId', 'roleTemplateId',
        'includeUsers', 'excludeUsers', 'includeGroups', 'excludeGroups',
        'includeRoles', 'excludeRoles', 'includeApplications', 'excludeApplications',
        'includeLocations', 'excludeLocations', 'includeDevices', 'excludeDevices',
        'includeServicePrincipals', 'excludeServicePrincipals',
        'includeAgentIdServicePrincipals', 'excludeAgentIdServicePrincipals',
        'includeDeviceStates', 'excludeDeviceStates',
        'members', 'memberIds', 'ownerIds', 'termsOfUse',
        # Tool and export metadata, not tenant data.
        'schemaVersion', 'tool', 'kind', 'snapshot', 'generatedUtc', 'policyApi',
        'source', 'authType',
        # Timestamps.
        'createdDateTime', 'modifiedDateTime', 'deletedDateTime', 'lastUpdatedDateTime',
        # Structural discriminators and enum-valued fields.
        'state', 'mode', 'operator', 'type', 'policyType', 'membershipKind',
        'userType', 'assignmentType', 'authenticationType', 'frequencyInterval',
        'cloudAppSecurityType', 'partialEnablementStrategy',
        'builtInControls', 'clientAppTypes', 'includePlatforms', 'excludePlatforms',
        'transferMethods', 'guestOrExternalUserTypes', 'includeUserActions',
        'includeAuthenticationContextClassReferences', 'allowedCombinations',
        'appliesToCombinations', 'combinationConfigurations', 'agentIdRiskLevels',
        'insiderRiskLevels', 'signInRiskLevels', 'userRiskLevels',
        'servicePrincipalRiskLevels', 'requirementsSatisfied', 'methodsRegistered',
        'systemPreferredAuthenticationMethods', 'defaultMfaMethod',
        'includeTrafficProfiles'
    ), [System.StringComparer]::OrdinalIgnoreCase)

# Value shapes that must never be lifted as a name regardless of the property
# they sit under: object ids (must survive when not pseudonymizing), timestamps
# and absolute references. These protect an unknown id- or date-valued Graph
# field that the skip list above does not name.
$script:CapSweepDateRegex = [regex]'^(?:\d{4}-\d{2}-\d{2}[T ]|\d{1,2}/\d{1,2}/\d{4})'
$script:CapSweepRefRegex = [regex]'(?i)^(?:https?://|urn:|#microsoft\.)'

function _CapSweepMaskable {
<#
    True when a swept string value is worth lifting into the dictionary. Filters
    out ids, dates and absolute references so the deny-by-default sweep does not
    corrupt structure. Whitespace, length and well-known names are handled later
    by _Add.
#>
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $t = $Value.Trim()
    if ($t.Length -lt 2) { return $false }
    if ($t -eq 'true' -or $t -eq 'false') { return $false }
    if ($script:CapGuidRegex.IsMatch($t)) { return $false }
    if ($script:CapSweepDateRegex.IsMatch($t)) { return $false }
    if ($script:CapSweepRefRegex.IsMatch($t)) { return $false }
    # Pure numbers, versions and percentages carry no identity.
    if ($t -match '^[\d.,%:+-]+$') { return $false }
    return $true
}

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
            # Deny-by-default: examine every string value unless its property is
            # a known-safe structural field, an @odata annotation, or the value
            # shape is an id, date or reference. Anything else is treated as a
            # candidate name so a new Graph field cannot slip through unmasked.
            $examine = $v -is [string] -and
                -not $script:CapSweepSkipProps.Contains("$k") -and
                "$k".IndexOf('@odata', [System.StringComparison]::OrdinalIgnoreCase) -lt 0 -and
                (_CapSweepMaskable $v)
            if ($examine) {
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
            elseif ($v -isnot [string]) {
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

    # Microsoft-global constants are seeded first and keyed by their own id, so
    # a review that cites one always restores to a name even in a tenant that
    # never referenced it. Seeding before the collectors also stops _Add from
    # minting an alias token for them, which would have made them unrestorable.
    $globals = Get-CapGlobalConstantEntry
    foreach ($g in $globals.GetEnumerator()) {
        $entries[$g.Key] = $g.Value
        $byName["$($g.Value.name)".ToLowerInvariant()] = $g.Key
    }

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
        # Already seeded as a Microsoft-global constant, keyed by its own id.
        # Returning here keeps the seeded entry rather than shadowing it with an
        # alias token that no restore could resolve.
        if ($Id -and $globals.Contains($Id)) { return }
        if ($wellKnown.names.Contains($trimmed)) { return }
        # A value that is itself an id needs no dictionary entry.
        if ($trimmed -eq $Id) { return }
        # A name that is a bare guid is an identifier, not a name. Registering one
        # against an object that has its own id means the token minted for it is
        # that object's id, so masking rewrites the guid in the name into a
        # different object's id wherever it appears, including where it is
        # genuinely an id. On a real snapshot this rewrote one policy id into
        # another policy's id: the duplicate cluster then listed the same policy
        # twice and the real one disappeared. Nothing is lost by skipping it,
        # since a guid carries no tenant identity to protect.
        #
        # Guid-valued entries with no id of their own are still allowed. They
        # mint a synthetic alias (EXTTENANT-001 and the like), which cannot
        # collide with an object id, and they are how a partner tenant id is
        # removed from the shareable export.
        if ($Id -and $script:CapGuidRegex.IsMatch($trimmed) -and
            $script:CapGuidRegex.Match($trimmed).Value.Length -eq $trimmed.Length) { return }

        $nameKey = $trimmed.ToLowerInvariant()
        if ($byName.ContainsKey($nameKey)) {
            # Two distinct objects share this display name. Masking is name
            # driven and cannot tell them apart from text alone, so the first
            # token stays authoritative there. Restoration is id driven and can:
            # record this id so a review that cites it still reads as a name
            # instead of failing as an unresolved guid. $byName is deliberately
            # left alone so the masking side keeps its existing behaviour.
            if ($Id -and -not $entries.Contains($Id)) {
                $entries[$Id] = [ordered]@{
                    token       = $Id
                    type        = $Type
                    id          = $Id
                    name        = $trimmed
                    duplicateOf = $byName[$nameKey]
                }
            }
            return
        }

        $token = if ($Id -and -not (Test-CapWellKnownId -Value $Id)) { $Id } else { _NextAlias -Type $Type }
        if ($entries.Contains($token)) {
            $existing = $entries[$token]
            if ($existing.name -ne $trimmed) { $token = _NextAlias -Type $Type }
        }
        if (-not $entries.Contains($token)) {
            $entries[$token] = [ordered]@{ token = $token; type = $Type; id = $Id; name = $trimmed }
        }
        $byName[$nameKey] = $token
    }

    # Sorted because $NameMap is an unordered hashtable. Without this, which of
    # two objects sharing a display name becomes the masking token is arbitrary
    # and can differ between runs on identical input.
    if ($NameMap) {
        foreach ($id in @($NameMap.Keys | Sort-Object)) { _Add -Name "$($NameMap[$id])" -Id "$id" -Type 'object' }
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
        $appFilter = _NmGet (_NmGet $conds 'applications') 'applicationFilter'
        $appRule = _NmGet $appFilter 'rule'
        if ($appRule) { _Add -Name "$appRule" -Id $null -Type 'apprule' }
        # Partner tenant ids named by a guest/external-user selector. Unlike a
        # policy id, which means nothing outside the tenant that issued it, this
        # is a global identifier for a named third-party organisation: it says
        # who the customer's managed provider or federation partner is. It is
        # registered here so it is substituted like any other tenant object on
        # the way out, and restored locally on the way back.
        $usersCond = _NmGet $conds 'users'
        foreach ($side in @('includeGuestsOrExternalUsers', 'excludeGuestsOrExternalUsers')) {
            $ext = _NmGet (_NmGet $usersCond $side) 'externalTenants'
            if ($null -eq $ext) { continue }
            $members = _NmGet $ext 'members'
            if ($null -eq $members) { continue }
            # PowerShell unrolls a one-element array to a scalar on the way out,
            # and one named partner is the common case.
            foreach ($t in @($members)) {
                if ($t) { _Add -Name "$t" -Id $null -Type 'exttenant' }
            }
        }
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

    The result is cached against the dictionary instance. A single run masks
    seven or more objects with the same dictionary - audit, findings, compliance,
    auth methods, consolidation, tests and the bundle itself - and compiling
    those regexes costs several seconds each time on a real tenant, which is
    where the masking phase was spending most of its time. The cache is keyed by
    object identity, so a different dictionary never picks up another's matchers.
#>
    param($Dictionary)

    # A dictionary can grow after matchers were built for it (aliases are added
    # late in a run), so identity alone is not enough to reuse a cached set. The
    # stamp below rebuilds whenever the dictionary has changed size, which is the
    # only way it changes. Serving stale matchers would silently under-mask.
    $cacheStamp = $null
    if ($null -ne $Dictionary) {
        $entryCount = 0
        $e0 = _NmGet $Dictionary 'entries'
        if ($null -ne $e0) { $entryCount = @(_NmKeys $e0).Count }
        # Every field the matcher set is derived from has to be in the stamp.
        # Pseudonymization adds idAliases to an existing dictionary part way
        # through a run, and reading the wrong key here means the cache never
        # invalidates and masking silently stops aliasing ids. Getting this
        # wrong under-masks, so it is spelled out rather than inferred.
        $aliasCount = 0
        $a0 = _NmGet $Dictionary 'idAliases'
        if ($null -ne $a0) { $aliasCount = @(_NmKeys $a0).Count }
        $pseudo = "$(_NmGet $Dictionary 'pseudonymized')"
        $cacheStamp = "$entryCount/$aliasCount/$pseudo"

        $slot = $null
        if ($script:CapMatcherCache.TryGetValue($Dictionary, [ref]$slot) -and $null -ne $slot -and $slot.Stamp -eq $cacheStamp) {
            return $slot.Matchers
        }
    }

    $entries = _NmGet $Dictionary 'entries'
    $byName = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
    $textNames = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($token in $entries.Keys) {
        $e = $entries[$token]
        $name = "$(_NmGet $e 'name')"
        if ([string]::IsNullOrEmpty($name)) { continue }
        # Microsoft-global constants are seeded into every dictionary so an id
        # can be read back as a name. They are not tenant data, so substituting
        # them would rewrite Microsoft's own vocabulary - a SCuBA statement
        # reading "the Global Administrator role" would become a guid.
        if (_NmGet $e 'global') { continue }
        # Schema vocabulary is never substituted: rewriting it corrupts the
        # data model and protects nothing.
        if (Test-CapReservedName -Name $name) { continue }
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

    $result = [pscustomobject]@{
        ByName  = $byName
        Regexes = $regexes
        Aliases = $aliasTable
        Count   = $byName.Count
        # Memo for _CapMaskString. Ordinal, not ignore-case: two values differing
        # only in case are different strings and must be masked separately, or a
        # cache hit would silently change the casing of the output.
        Memo    = [System.Collections.Hashtable]::new([System.StringComparer]::Ordinal)
    }
    if ($null -ne $Dictionary) {
        $script:CapMatcherCache.AddOrUpdate($Dictionary, [pscustomobject]@{ Stamp = $cacheStamp; Matchers = $result })
    }
    return $result
}

function Clear-CapMatcherCache {
<#
.SYNOPSIS
    Drop the compiled matcher cache. Call after mutating a dictionary in place.
#>
    [CmdletBinding()]
    param()
    $script:CapMatcherCache = [System.Runtime.CompilerServices.ConditionalWeakTable[object, object]]::new()
}

function _CapMatchContext {
<#
    A short window around a match, so a rejected bundle says *why*. Without it a
    violation reads "name: Bill" and the operator cannot tell a genuine leak from
    an object named "Bill" colliding with "Billing Administrator".
#>
    param([string]$Text, [int]$Index, [int]$Length, [int]$Pad = 40)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $start = [Math]::Max(0, $Index - $Pad)
    $end = [Math]::Min($Text.Length, $Index + $Length + $Pad)
    $snippet = $Text.Substring($start, $end - $start) -replace '\s+', ' '
    if ($start -gt 0) { $snippet = '...' + $snippet }
    if ($end -lt $Text.Length) { $snippet = $snippet + '...' }
    return $snippet.Trim()
}

function _CapAddNameRegexes {
    param([string[]]$Names, [int]$Size, $Target, [switch]$Delimited)

    if (-not $Names -or $Names.Count -eq 0) { return }
    # Lookarounds are unsupported in NonBacktracking mode, so the delimited set
    # (short names only, a small slice of the dictionary) uses the backtracking
    # engine. The bulk set keeps the DFA.
    $opts = if ($Delimited) {
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    }
    else {
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
        [System.Text.RegularExpressions.RegexOptions]::NonBacktracking
    }

    for ($i = 0; $i -lt $Names.Count; $i += $Size) {
        $slice = $Names[$i..([Math]::Min($i + $Size - 1, $Names.Count - 1))]
        $alt = ($slice | ForEach-Object { [regex]::Escape($_) }) -join '|'
        if ($Delimited) { $alt = '(?<![\w.:-])(?:' + $alt + ')(?![\w.:-])' }
        try {
            $Target.Add([regex]::new($alt, $opts))
        }
        catch {
            if ($slice.Count -gt 1) {
                # Too many automaton nodes for one chunk - split and retry.
                _CapAddNameRegexes -Names $slice -Size ([Math]::Max(1, [int]($slice.Count / 4))) -Target $Target -Delimited:$Delimited
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

    # An export repeats the same strings constantly: enum values, odata type
    # urls, timestamps, and the same object id in policy after policy. Masking
    # runs every chunked regex over every one of them, so on a large tenant the
    # cost is dominated by re-deriving answers already derived. The mapping is a
    # pure function of the value, so memoize it. The cache is per matcher set,
    # so a different dictionary cannot pick up another one's answers.
    $memo = $Matchers.Memo
    if ($memo -and $memo.ContainsKey($Value)) { return $memo[$Value] }

    $out = _CapMaskStringUncached -Value $Value -Matchers $Matchers -IdAliases $IdAliases
    if ($memo) { $memo[$Value] = $out }
    return $out
}

function _CapIsBareGuid {
<#
.SYNOPSIS
    True when the whole value is a single guid and nothing else.

.DESCRIPTION
    Object ids make up most of the distinct strings in an export, and scanning
    every chunked name regex across each one is where the masking phase spends
    its time. No name can survive that scan anyway: a guid is hex and dashes, so
    any interior hit is bounded by word characters or a dash and is rejected by
    the boundary rule before it can be substituted.

    Skipping only the free-text scan, not the function, matters. The exact
    whole-value lookup above still runs, which is how a deliberately registered
    guid-valued entry such as a partner tenant id is still replaced, and the id
    aliasing below still runs, which is how pseudonymization still applies.
#>
    param([string]$Value)
    if ($Value.Length -ne 36) { return $false }
    $m = $script:CapGuidRegex.Match($Value)
    return ($m.Success -and $m.Index -eq 0 -and $m.Length -eq $Value.Length)
}

function _CapMaskStringUncached {
    param([string]$Value, $Matchers, $IdAliases)

    if ([string]::IsNullOrEmpty($Value)) { return $Value }
    $out = $Value

    if ($Matchers.ByName.ContainsKey($out)) {
        # Exact whole-value match still has to go through id aliasing below,
        # otherwise a pseudonymized bundle would keep the raw object id here.
        $out = $Matchers.ByName[$out]
    }
    elseif ($out.Length -ge $script:CapMinTextNameLength -and -not (_CapIsBareGuid $out)) {
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
    if ($Mode -eq 'mask') {
        $memo = $Matchers.Memo
        if ($memo -and $memo.ContainsKey($Key)) { return $memo[$Key] }
        return (_CapMaskString -Value $Key -Matchers $Matchers -IdAliases $IdAliases)
    }
    return (Restore-CapNameText -Text $Key -Dictionary $Dictionary)
}

function _CapWalk {
    param($Node, [ValidateSet('mask', 'restore')][string]$Mode, $Matchers, $IdAliases, $Dictionary, [int]$Depth = 0)

    if ($Depth -gt 40) { return $Node }
    if ($null -eq $Node) { return $null }

    if ($Node -is [string]) {
        if ($Mode -eq 'mask') {
            # Memo lookup inlined. A large export walks several hundred thousand
            # strings, so at this depth the PowerShell call itself is a
            # measurable share of the phase.
            $memo = $Matchers.Memo
            if ($memo -and $memo.ContainsKey($Node)) { return $memo[$Node] }
            return (_CapMaskString -Value $Node -Matchers $Matchers -IdAliases $IdAliases)
        }
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

function Repair-CapRestoredIds {
<#
.SYNOPSIS
    Put identifier values back after a re-hydration overwrote them.

.DESCRIPTION
    ConvertFrom-CapSafeObject is a blind text substitution: it replaces every
    occurrence of a token, and it cannot tell a label apart from an identifier.
    When an object's displayName was masked to that object's own id, restoring
    writes the name into BOTH displayName and id, and the id is gone.

    That is not a cosmetic problem. New-CapNameDictionary keys on the id, so an
    object whose id is no longer a guid is skipped, its name never enters the
    new dictionary, and every later masking pass leaves that name in place. It
    then travels through the analysis into a file meant to be shareable.

    This walks the restored graph alongside the masked one it came from and
    copies identifier values back wherever the masked side still holds a guid
    and the restored side no longer does. Structure is identical between the
    two because one was produced from the other, so a positional walk is safe.
    Returns the number of values repaired.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Restored,
        [Parameter(Mandatory)]$Masked
    )

    $idKeys = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@('id', 'templateId', 'roleTemplateId', 'objectId', 'appId', 'servicePrincipalId', 'groupId', 'userId'),
        [System.StringComparer]::OrdinalIgnoreCase)
    # Condition collections hold bare ids with no key of their own to recognise
    # them by. They are normally arrays, and the array rule below covers those,
    # but PowerShell unrolls a one-item array on serialisation, so a policy that
    # excludes exactly one account stores a bare string. That single case is how
    # a break-glass account name survived into an analysis meant to be
    # shareable, so scalars in these keys are repaired too.
    $refKeys = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@(
            'includeUsers', 'excludeUsers', 'includeGroups', 'excludeGroups',
            'includeRoles', 'excludeRoles', 'includeGuestsOrExternalUsers', 'excludeGuestsOrExternalUsers',
            'includeApplications', 'excludeApplications', 'includeServicePrincipals', 'excludeServicePrincipals',
            'includeLocations', 'excludeLocations', 'includeDevices', 'excludeDevices',
            'includeAuthenticationContextClassReferences', 'memberIds', 'members',
            'includePlatforms', 'excludePlatforms', 'policies', 'affectedObjects'),
        [System.StringComparer]::OrdinalIgnoreCase)
    $guidShape = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    $aliasShape = '^[A-Za-z][A-Za-z0-9]*-\d+$'
    $count = 0

    # An identifier value on the masked side is a guid or a minted alias. If the
    # restored side no longer looks like one, substitution turned it into a name.
    function _IsId([string]$v) { return ($v -match $guidShape -or $v -match $aliasShape) }

    function _RepairNode($r, $m) {
        if ($null -eq $r -or $null -eq $m) { return }

        if ($r -is [System.Collections.IDictionary] -and $m -is [System.Collections.IDictionary]) {
            foreach ($key in @($r.Keys)) {
                if (-not $m.Contains($key)) { continue }
                $rv = $r[$key]
                $mv = $m[$key]
                if ($idKeys.Contains([string]$key) -and $mv -is [string] -and $mv -match $guidShape) {
                    if (-not ($rv -is [string]) -or $rv -notmatch $guidShape) {
                        $r[$key] = $mv
                        $script:_CapRepairCount++
                    }
                }
                elseif ($refKeys.Contains([string]$key) -and $mv -is [string] -and (_IsId $mv)) {
                    if (-not ($rv -is [string]) -or -not (_IsId $rv)) {
                        $r[$key] = $mv
                        $script:_CapRepairCount++
                    }
                }
                else {
                    _RepairNode $rv $mv
                }
            }
            return
        }

        if ($r -is [System.Collections.IEnumerable] -and $r -isnot [string] -and
            $m -is [System.Collections.IEnumerable] -and $m -isnot [string]) {
            $ra = @($r); $ma = @($m)
            if ($ra.Count -ne $ma.Count) { return }
            # Reference collections such as excludeRoles or includeApplications
            # are bare id strings with no key to recognise them by. Restoring
            # rewrites them to names, and any signature derived from them then
            # carries those names too, which is how a duplicate-cluster appSig
            # ended up naming two applications.
            $writable = $r -as [System.Collections.IList]
            for ($i = 0; $i -lt $ra.Count; $i++) {
                if ($null -ne $writable -and $ma[$i] -is [string] -and (_IsId $ma[$i]) -and
                    (-not ($ra[$i] -is [string]) -or -not (_IsId $ra[$i]))) {
                    $writable[$i] = $ma[$i]
                    $script:_CapRepairCount++
                    continue
                }
                _RepairNode $ra[$i] $ma[$i]
            }
        }
    }

    $script:_CapRepairCount = 0
    _RepairNode $Restored $Masked
    $count = $script:_CapRepairCount
    return $count
}

function _CapRestoreMatchers {
<#
.SYNOPSIS
    Build (and memoize) a single-scan matcher set for the restore direction.

    The naive form - loop every dictionary token and run a regex replace over
    the text - costs one full pass per token. On a real tenant that is ~29k
    passes per string, and ConvertFrom-CapSafeObject calls this once per string
    and once per key in the graph, so an enterprise export never finishes. The
    mask direction already avoids this via _CapNameMatchers; this is the same
    treatment for restore.

    Dictionary tokens are object ids (GUIDs) or minted aliases (TYPE-001), so
    one alternation over those two shapes finds every candidate in a single
    pass and the substitution becomes a hashtable lookup. Cost is O(text)
    instead of O(text x dictionary).
#>
    param($Dictionary)

    if ([object]::ReferenceEquals($script:CapRestoreCacheKey, $Dictionary)) {
        return $script:CapRestoreCacheValue
    }

    $entries = _NmGet $Dictionary 'entries'
    $aliases = _NmGet $Dictionary 'idAliases'

    $lookup = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
    $literals = [System.Collections.Generic.List[string]]::new()

    $guidShape  = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    $aliasShape = '^[A-Za-z][A-Za-z0-9]*-\d+$'

    # Resolve names first so an alias can be mapped straight through to its
    # name in one hop. The previous implementation did alias -> id, then a
    # second pass id -> name; collapsing that here keeps the same end result.
    $nameOf = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
    if ($entries) {
        foreach ($token in $entries.Keys) {
            $name = "$(_NmGet $entries[$token] 'name')"
            if ([string]::IsNullOrEmpty($name)) { continue }
            $nameOf[[string]$token] = $name
        }
    }

    foreach ($token in $nameOf.Keys) {
        $lookup[$token] = $nameOf[$token]
        if ($token -notmatch $guidShape -and $token -notmatch $aliasShape) { $literals.Add([string]$token) }
    }

    if ($aliases -and $aliases.Count) {
        foreach ($id in $aliases.Keys) {
            $alias = [string]$aliases[$id]
            if ([string]::IsNullOrEmpty($alias)) { continue }
            # An alias resolves to the name when the dictionary knows the id,
            # and otherwise falls back to the id itself - matching the old
            # two-pass behaviour where an unresolved id simply survived.
            $target = $nameOf[[string]$id]
            if ([string]::IsNullOrEmpty($target)) { $target = [string]$id }
            $lookup[$alias] = $target
            if ($alias -notmatch $aliasShape) { $literals.Add($alias) }
        }
    }

    $alternatives = [System.Collections.Generic.List[string]]::new()
    $alternatives.Add('[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
    $alternatives.Add('[A-Za-z][A-Za-z0-9]*-\d+')
    # Longest first so a literal can never be shadowed by a shorter prefix.
    foreach ($lit in ($literals | Sort-Object -Unique { $_.Length } -Descending)) {
        $alternatives.Add([regex]::Escape($lit))
    }

    $pattern = '(?<![\w-])(?:' + ($alternatives -join '|') + ')(?![\w-])'
    $matchers = [pscustomobject]@{
        Lookup = $lookup
        Regex  = [regex]::new($pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }

    $script:CapRestoreCacheKey = $Dictionary
    $script:CapRestoreCacheValue = $matchers
    return $matchers
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

    $m = _CapRestoreMatchers -Dictionary $Dictionary
    if (-not $m.Lookup.Count) { return $Text }

    return $m.Regex.Replace($Text, {
        param($match)
        $hit = $m.Lookup[$match.Value]
        if ($null -ne $hit) { return [string]$hit }
        return $match.Value
    }.GetNewClosure())
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
    $found = $script:CapAliasTokenRegex.Matches($Text)
    return @($found | ForEach-Object { $_.Value } | Sort-Object -Unique)
}

function Resolve-CapTruncatedIds {
<#
.SYNOPSIS
    Recover ids that were written in an abbreviated form, such as
    "007dce69-..." instead of the full 36 characters.

.DESCRIPTION
    A safety net, not a licence to abbreviate. Restoration works by matching the
    complete id against the dictionary, so an abbreviated id is a permanently
    dead reference: the reader is told to act on an object they cannot identify.
    A delivered report once carried 71 of them.

    Recovery is only safe because prefixes are effectively unique. On a real
    tenant dictionary there were 10,405 distinct 8-character prefixes across
    10,407 ids, a single collision. Where a prefix does match more than one
    entry this refuses to choose, because guessing would put the wrong object
    into a report, which is worse than leaving the reference broken.

    Only prefixes of at least -MinPrefix hex characters are considered. Shorter
    ones carry real collision risk.

.OUTPUTS
    Hashtable with 'text' (the repaired text), 'resolved' (list of
    abbreviation -> full id) and 'ambiguous' (list of abbreviations that matched
    more than one id).
#>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)]$Dictionary,
        [int]$MinPrefix = 8
    )

    $result = @{ text = $Text; resolved = @(); ambiguous = @() }
    if ([string]::IsNullOrEmpty($Text)) { return $result }

    $entries = $Dictionary['entries']
    if (-not $entries) { return $result }

    # Every full id the dictionary knows about, indexed by its own prefixes.
    $ids = [System.Collections.Generic.List[string]]::new()
    foreach ($key in $entries.Keys) {
        $token = "$($entries[$key]['token'])"
        if ($token -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
            $ids.Add($token)
        }
    }
    if (-not $ids.Count) { return $result }

    $rx = [regex]'(?<![0-9a-fA-F])(?<prefix>[0-9a-fA-F]{4,}(?:-[0-9a-fA-F]{1,12})*)-?\s*(?:\.{2,}|\u2026)'
    $resolved  = [System.Collections.Generic.List[string]]::new()
    $ambiguous = [System.Collections.Generic.List[string]]::new()
    $seen      = @{}

    $out = $rx.Replace($Text, {
        param($m)
        $prefix = $m.Groups['prefix'].Value
        $bare = $prefix -replace '-', ''
        if ($bare.Length -lt $MinPrefix) { return $m.Value }

        $matches = @($ids | Where-Object { $_.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase) })
        if ($matches.Count -eq 1) {
            if (-not $seen.ContainsKey($m.Value)) {
                $seen[$m.Value] = $true
                $resolved.Add("$($m.Value) -> $($matches[0])")
            }
            return $matches[0]
        }
        if ($matches.Count -gt 1 -and -not $seen.ContainsKey($m.Value)) {
            $seen[$m.Value] = $true
            $ambiguous.Add("$($m.Value) matched $($matches.Count) ids")
        }
        return $m.Value
    })

    $result['text']      = $out
    $result['resolved']  = @($resolved)
    $result['ambiguous'] = @($ambiguous)
    return $result
}

function Get-CapUnresolvedIds {
<#
.SYNOPSIS
    Full-length ids left in text after restoration, excluding Microsoft public
    constants which never appear in a tenant dictionary.

.DESCRIPTION
    This is the accounting that was missing. Restoration used to resolve what it
    could and report success, so a report with dozens of dangling references
    looked like a clean run.
#>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrEmpty($Text)) { return @() }
    $wellKnown = Get-CapWellKnownIdSet
    $rx = [regex]'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($m in $rx.Matches($Text)) {
        $v = $m.Value
        if ($wellKnown['ids'].Contains($v)) { continue }
        # Built-in authentication strengths are Microsoft constants too.
        if ($v -match '^0{8}-0{4}-0{4}-0{4}-0{11}[0-9]$') { continue }
        if (-not $out.Contains($v)) { $out.Add($v) }
    }
    return @($out)
}

function Get-CapTruncatedIds {
<#
.SYNOPSIS
    Abbreviated id references still present in text. Any hit is a dead
    reference that no dictionary can resolve.
#>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return @() }
    $rx = [regex]'(?<![0-9a-fA-F])[0-9a-fA-F]{4,}(?:-[0-9a-fA-F]{1,12})*-?\s*(?:\.{2,}|\u2026)'
    return @($rx.Matches($Text) | ForEach-Object { $_.Value.Trim() } | Sort-Object -Unique)
}

function Get-CapAliasTypes {
<#
.SYNOPSIS
    The alias prefixes either minting site can produce. Exposed so callers and
    tests assert against the real list rather than a copy that can drift.
#>
    [CmdletBinding()]
    param()
    return @($script:CapAliasTypes)
}

function _CapIsAllowedFqdn {
<#
    True when an FQDN-shaped match is a Microsoft-owned public domain rather than
    tenant data. Matched on a label boundary so a tenant vanity domain is not
    mistaken for a Microsoft one.
#>
    param([string]$Fqdn)
    $lower = $Fqdn.ToLowerInvariant()
    foreach ($apex in $script:CapFqdnAllowApex) {
        if ($lower -eq $apex -or $lower.EndsWith('.' + $apex, [System.StringComparison]::Ordinal)) { return $true }
    }
    $tail = $lower.Substring($lower.LastIndexOf('.') + 1)
    if ($script:CapFqdnFileTails -contains $tail) { return $true }
    return $false
}

function _CapPatternHits {
<#
.SYNOPSIS
    Dictionary-independent leak detectors for a single document: email and UPN
    shapes, IPv6 addresses and tenant FQDNs. Returns violation records with a
    kind that is distinct from the dictionary 'name' kind.
#>
    param([string]$Text, [string]$Source)

    $hits = [System.Collections.Generic.List[object]]::new()
    if ([string]::IsNullOrEmpty($Text)) { return $hits }

    foreach ($m in $script:CapEmailRegex.Matches($Text)) {
        # Graph OData annotation keys carry a local part, so the regex alone
        # cannot separate them from real addresses: "combinationConfigurations
        # @odata.context" reads as an email. The @odata. vocabulary is fixed
        # Graph protocol, never tenant data, so a match there is noise. A false
        # positive in a safety gate is not harmless, it teaches people to
        # ignore the gate.
        if ($m.Value -match '@odata\.') { continue }
        $hits.Add([ordered]@{
            source  = $Source
            kind    = 'email'
            value   = $m.Value
            token   = $null
            context = _CapMatchContext -Text $Text -Index $m.Index -Length $m.Length
        })
    }
    foreach ($m in $script:CapIpv6Regex.Matches($Text)) {
        $hits.Add([ordered]@{
            source  = $Source
            kind    = 'ipv6'
            value   = $m.Value
            token   = $null
            context = _CapMatchContext -Text $Text -Index $m.Index -Length $m.Length
        })
    }
    foreach ($m in $script:CapFqdnRegex.Matches($Text)) {
        # A domain sitting directly after "@" is the host part of an email or
        # UPN, already reported above, or the tail of an "@odata.*" annotation
        # key. Either way it is not a standalone FQDN leak.
        if ($m.Index -gt 0 -and $Text[$m.Index - 1] -eq '@') { continue }
        if (_CapIsAllowedFqdn $m.Value) { continue }
        $hits.Add([ordered]@{
            source  = $Source
            kind    = 'fqdn'
            value   = $m.Value
            token   = $null
            context = _CapMatchContext -Text $Text -Index $m.Index -Length $m.Length
        })
    }
    return $hits
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
    #
    # Names are split by length, mirroring exactly what the masker guarantees:
    #
    #   >= CapMinTextNameLength : substituted anywhere in free text, so the test
    #                             matches anywhere too, including inside a word.
    #   <  CapMinTextNameLength : substituted only as a whole value, because
    #                             masking "IT" or "All" inside prose would
    #                             corrupt it. The test is delimiter-anchored to
    #                             match, otherwise a tenant that happens to name
    #                             an object "User", "Bill" or "box" collides with
    #                             Microsoft's own constants ("User.Read.All",
    #                             "Billing Administrator", "MailboxSettings...",
    #                             "urn:user:registerdevice") and every bundle is
    #                             rejected on false positives. Word characters,
    #                             dots and colons all count as "part of a larger
    #                             identifier" so structured constants are skipped
    #                             while a standalone value stays detectable.
    $tokenByName = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
    $leakNames = [System.Collections.Generic.List[string]]::new()
    $shortNames = [System.Collections.Generic.List[string]]::new()
    foreach ($token in $entries.Keys) {
        $name = "$(_NmGet $entries[$token] 'name')"
        if ([string]::IsNullOrWhiteSpace($name) -or $name.Length -lt 3) { continue }
        # Mirrors the masker: Microsoft-global constants and schema vocabulary
        # are deliberately not substituted, so finding them is not a leak.
        if (_NmGet $entries[$token] 'global') { continue }
        if (Test-CapReservedName -Name $name) { continue }
        if ($tokenByName.ContainsKey($name)) { continue }
        $tokenByName[$name] = "$token"
        if ($name.Length -lt $script:CapMinTextNameLength) { [void]$shortNames.Add($name) }
        else { [void]$leakNames.Add($name) }
    }
    $leakRegexes = [System.Collections.Generic.List[regex]]::new()
    _CapAddNameRegexes -Names @($leakNames | Sort-Object -Property Length -Descending) `
        -Size $script:CapRegexChunkSize -Target $leakRegexes
    $shortRegexes = [System.Collections.Generic.List[regex]]::new()
    _CapAddNameRegexes -Names @($shortNames | Sort-Object -Property Length -Descending) `
        -Size $script:CapRegexChunkSize -Target $shortRegexes -Delimited

    foreach ($doc in $docs) {
        foreach ($set in @($leakRegexes, $shortRegexes)) {
            foreach ($rx in $set) {
                foreach ($m in $rx.Matches($doc.Text)) {
                    $hit = $m.Value
                    $token = $tokenByName[$hit]
                    if (-not $token) { continue }
                    $violations.Add([ordered]@{
                        source  = $doc.Source
                        kind    = 'name'
                        value   = $hit
                        token   = $token
                        context = _CapMatchContext -Text $doc.Text -Index $m.Index -Length $m.Length
                    })
                }
            }
        }
        # Dictionary-independent detectors run on every document regardless of
        # the pseudonymization flag: an email, an IPv6 address or a tenant FQDN
        # is a leak whether or not ids were aliased. Reported under their own
        # kinds so a caller can tell "you failed to mask a name you knew about"
        # (kind 'name') from "this looks like tenant data and the dictionary
        # never knew about it" (kind 'email', 'ipv6', 'fqdn').
        foreach ($hit in (_CapPatternHits -Text $doc.Text -Source $doc.Source)) {
            $violations.Add($hit)
        }
        if ($RequirePseudonymized) {
            foreach ($m in $script:CapGuidRegex.Matches($doc.Text)) {
                if (Test-CapWellKnownId -Value $m.Value) { continue }
                $violations.Add([ordered]@{
                    source  = $doc.Source
                    kind    = 'guid'
                    value   = $m.Value
                    token   = $null
                    context = _CapMatchContext -Text $doc.Text -Index $m.Index -Length $m.Length
                })
            }
            foreach ($m in [regex]::Matches($doc.Text, '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?\b')) {
                $violations.Add([ordered]@{
                    source  = $doc.Source
                    kind    = 'ip'
                    value   = $m.Value
                    token   = $null
                    context = _CapMatchContext -Text $doc.Text -Index $m.Index -Length $m.Length
                })
            }
        }
    }

    return @($violations | Group-Object { "$($_.kind)|$($_.value)" } | ForEach-Object { $_.Group[0] })
}

function _CapKeyDropped {
    param([string]$Name, [string[]]$Keys, [string[]]$Suffixes)

    foreach ($k in @($Keys)) { if ($Name -eq $k) { return $true } }
    foreach ($sfx in @($Suffixes)) {
        if ($sfx -and $Name.EndsWith($sfx, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function _CapStripKeys {
<#
.SYNOPSIS
    Recursively drop keys from an object graph, case-insensitively. Keys match
    either exactly (-Keys) or by suffix (-KeySuffixes), the latter for OData
    annotations such as "authenticationStrength@odata.context" whose prefix
    varies with the property they annotate.
#>
    param($Node, [string[]]$Keys, [string[]]$KeySuffixes = @(), [int]$Depth = 0)

    if ($Depth -gt 40 -or $null -eq $Node) { return $Node }
    if ($Node -is [string] -or (_CapIsScalar $Node)) { return $Node }

    if ($Node -is [System.Collections.IDictionary]) {
        $out = [ordered]@{}
        foreach ($k in @($Node.Keys)) {
            if (_CapKeyDropped -Name "$k" -Keys $Keys -Suffixes $KeySuffixes) { continue }
            $out[$k] = _CapStripKeys -Node $Node[$k] -Keys $Keys -KeySuffixes $KeySuffixes -Depth ($Depth + 1)
        }
        return $out
    }

    if ($Node -is [System.Collections.IEnumerable]) {
        $items = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $Node) { $items.Add((_CapStripKeys -Node $item -Keys $Keys -KeySuffixes $KeySuffixes -Depth ($Depth + 1))) }
        return , $items.ToArray()
    }

    $props = @($Node.PSObject.Properties)
    if ($props.Count) {
        $out = [ordered]@{}
        foreach ($p in $props) {
            if (_CapKeyDropped -Name $p.Name -Keys $Keys -Suffixes $KeySuffixes) { continue }
            $out[$p.Name] = _CapStripKeys -Node $p.Value -Keys $Keys -KeySuffixes $KeySuffixes -Depth ($Depth + 1)
        }
        return $out
    }
    return $Node
}

function _CapArrayValuedKeys {
<#
.SYNOPSIS
    Graph properties that are collections in the Conditional Access schema, even
    when they happen to hold a single item.
#>
    return @(
        # conditions.users
        'includeUsers', 'excludeUsers', 'includeGroups', 'excludeGroups',
        'includeRoles', 'excludeRoles',
        'includeAgentIdServicePrincipals', 'excludeAgentIdServicePrincipals',
        # conditions.applications
        'includeApplications', 'excludeApplications', 'includeUserActions',
        'includeAuthenticationContextClassReferences',
        # conditions
        'clientAppTypes', 'signInRiskLevels', 'userRiskLevels',
        'servicePrincipalRiskLevels', 'insiderRiskLevels',
        'includePlatforms', 'excludePlatforms',
        'includeLocations', 'excludeLocations',
        'includeDevices', 'excludeDevices',
        'transferMethods',
        # grantControls
        'builtInControls', 'customAuthenticationFactors', 'termsOfUse',
        # authentication strengths
        'allowedCombinations', 'combinationConfigurations',
        # analysis output. The same one-item unrolling applies: a policy with a
        # single dead-weight reason serialized "reasons": "report-only", which a
        # consumer iterates character by character.
        'reasons', 'policies', 'members', 'evidence', 'nist', 'mitre',
        'references', 'affectedObjects', 'excludedFromPolicies', 'issues',
        'controls', 'deadWeight', 'completeness', 'exclusionConcentration', 'unreadShapes',
        'findings', 'aggregated', 'exact', 'overlap', 'merge', 'aggregatedOnly'
    )
}

function _CapRestoreArrays {
<#
.SYNOPSIS
    Put collection-valued Graph properties back into array shape.

.DESCRIPTION
    PowerShell unrolls a one-item array, so a rebuilt object graph serializes
    "allowedCombinations": ["fido2"] as "allowedCombinations": "fido2". A
    consumer that iterates the property then walks the string character by
    character, which is how a delivered review came to describe a FIDO2-only
    strength as "fragmented single characters". Thirteen properties were
    affected, including excludeGroups and excludeUsers, so the damage was not
    cosmetic: it changed how the scope of a policy reads.
#>
    param($Node, [int]$Depth = 0)

    if ($Depth -gt 40 -or $null -eq $Node) { return $Node }
    if ($Node -is [string] -or (_CapIsScalar $Node)) { return $Node }

    $arrayKeys = _CapArrayValuedKeys

    if ($Node -is [System.Collections.IDictionary]) {
        $out = [ordered]@{}
        foreach ($k in @($Node.Keys)) {
            $value = _CapRestoreArrays -Node $Node[$k] -Depth ($Depth + 1)
            if ($null -ne $value -and $arrayKeys -contains "$k" -and -not ($value -is [System.Collections.IList])) {
                $value = [object[]]@($value)
            }
            $out[$k] = $value
        }
        return $out
    }

    if ($Node -is [System.Collections.IEnumerable]) {
        $items = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $Node) { $items.Add((_CapRestoreArrays -Node $item -Depth ($Depth + 1))) }
        return , $items.ToArray()
    }

    $props = @($Node.PSObject.Properties)
    if ($props.Count) {
        $out = [ordered]@{}
        foreach ($p in $props) {
            $value = _CapRestoreArrays -Node $p.Value -Depth ($Depth + 1)
            if ($null -ne $value -and $arrayKeys -contains $p.Name -and -not ($value -is [System.Collections.IList])) {
                $value = [object[]]@($value)
            }
            $out[$p.Name] = $value
        }
        return $out
    }
    return $Node
}

$script:CapAnalysisExposure = $null

function _CapLoadAnalysisExposure {
<#
    Loads assets/reference/analysis-exposure.json once. A missing or unreadable
    pack degrades to $null, and every caller treats $null as "export no
    analysis at all". Failing closed matters here: the alternative is a pack
    read error quietly turning an allowlist into a pass-through.
#>
    if ($script:CapAnalysisExposure) { return $script:CapAnalysisExposure }

    $pack = Join-Path $PSScriptRoot '../../assets/reference/analysis-exposure.json'
    if (-not (Test-Path -LiteralPath $pack)) { return $null }
    try {
        $script:CapAnalysisExposure = Get-Content -LiteralPath $pack -Raw | ConvertFrom-Json -Depth 12 -AsHashtable
    }
    catch { return $null }
    return $script:CapAnalysisExposure
}

function Get-CapAnalysisExposure {
<#
.SYNOPSIS
    The classification that decides what analysis output may leave the tenant
    and whether it leaves in full or as a count.
#>
    [CmdletBinding()]
    param()
    return (_CapLoadAnalysisExposure)
}

function _CapPickFields {
<#
    Copy only the named fields from a record. Absent fields stay absent rather
    than being emitted as null, so a consumer can tell "not collected" from
    "collected and empty".
#>
    param($Record, [string[]]$Fields)

    if ($null -eq $Record) { return $null }
    $out = [ordered]@{}
    foreach ($f in @($Fields)) {
        $v = _NmGet $Record $f
        if ($null -ne $v) { $out[$f] = $v }
    }
    return $out
}

function New-CapExportableAnalysis {
<#
.SYNOPSIS
    Rebuild the analysis output as a shareable section, field by field, under
    the classification in assets/reference/analysis-exposure.json.

.DESCRIPTION
    The deterministic engine already decides what is true: which policies
    duplicate each other, which are dead weight, which baseline controls are
    missing, which principals concentrate exclusions, and how the estate scores
    against CISA SCuBA with evidence and framework mappings. Dropping all of it
    from the shareable export forced the reviewer to re-derive it from the raw
    policy list, which is slower, non-reproducible, and in a measured run
    produced numbers that contradicted the engine.

    Nothing is copied wholesale. Each record is rebuilt from an explicit field
    list, so a field added upstream is absent until someone classifies it.

    Person-scoped findings are reduced to a count. One tenant produced 2,646
    records naming which individuals cannot perform MFA; that is a ranked target
    list, and a plan does not need it. The count does the same work.

.PARAMETER Analysis
    Ordered map of section name -> already-masked analysis object, exactly as
    written to analysis/*.json.

.OUTPUTS
    Ordered dictionary of section name -> rebuilt section, plus an 'exposure'
    section recording what was aggregated. Empty when the classification pack
    is unavailable.
#>
    [CmdletBinding()]
    param($Analysis)

    $out = [ordered]@{}
    if (-not $Analysis) { return $out }

    $pack = _CapLoadAnalysisExposure
    if (-not $pack) { return $out }

    $sections = _NmGet $pack 'sections'
    $checks = _NmGet $pack 'findingChecks'
    $defaultExposure = "$(_NmGet $pack 'defaultFindingExposure')"
    if (-not $defaultExposure) { $defaultExposure = 'aggregate' }

    $aggregatedNote = [System.Collections.Generic.List[object]]::new()

    foreach ($name in @('consolidation', 'compliance', 'audit', 'findings')) {
        $src = _NmGet $Analysis $name
        if ($null -eq $src) { continue }
        $spec = _NmGet $sections $name
        if ($null -eq $spec) { continue }

        $section = [ordered]@{}

        foreach ($scalar in @(_NmArr (_NmGet $spec '$scalars'))) {
            $v = _NmGet $src "$scalar"
            if ($null -ne $v) { $section["$scalar"] = $v }
        }

        $summaryFields = @(_NmArr (_NmGet $spec 'summary'))
        if ($summaryFields.Count) {
            $summary = _CapPickFields -Record (_NmGet $src 'summary') -Fields $summaryFields
            if ($summary -and $summary.Count) { $section['summary'] = $summary }
        }

        switch ($name) {
            'consolidation' {
                $memberFields = @(_NmArr (_NmGet $spec 'duplicates.members'))
                $dups = [ordered]@{}
                foreach ($kind in @('exact', 'overlap', 'merge')) {
                    $clusterFields = @(_NmArr (_NmGet $spec "duplicates.$kind"))
                    if (-not $clusterFields.Count) { continue }
                    $clusters = [System.Collections.Generic.List[object]]::new()
                    foreach ($c in _NmArr (_NmGet (_NmGet $src 'duplicates') $kind)) {
                        $rebuilt = _CapPickFields -Record $c -Fields $clusterFields
                        if ($rebuilt.Contains('members')) {
                            $rebuilt['members'] = @(_NmArr $rebuilt['members'] | ForEach-Object { _CapPickFields -Record $_ -Fields $memberFields })
                        }
                        $clusters.Add($rebuilt)
                    }
                    $dups[$kind] = @($clusters)
                }
                if ($dups.Count) { $section['duplicates'] = $dups }

                foreach ($listName in @('deadWeight', 'completeness', 'exclusionConcentration', 'unreadShapes')) {
                    $fields = @(_NmArr (_NmGet $spec $listName))
                    if (-not $fields.Count) { continue }
                    $section[$listName] = @(_NmArr (_NmGet $src $listName) | ForEach-Object { _CapPickFields -Record $_ -Fields $fields })
                }
            }
            'compliance' {
                $fields = @(_NmArr (_NmGet $spec 'controls'))
                if ($fields.Count) {
                    $section['controls'] = @(_NmArr (_NmGet $src 'controls') | ForEach-Object { _CapPickFields -Record $_ -Fields $fields })
                }
            }
            'audit' {
                foreach ($listName in @('issues', 'exemptionExposure')) {
                    $fields = @(_NmArr (_NmGet $spec $listName))
                    if (-not $fields.Count) { continue }
                    $section[$listName] = @(_NmArr (_NmGet $src $listName) | ForEach-Object { _CapPickFields -Record $_ -Fields $fields })
                }
            }
            'findings' {
                $fullFields = @(_NmArr (_NmGet $spec 'findings'))
                $aggFields = @(_NmArr (_NmGet $spec 'aggregated'))
                $kept = [System.Collections.Generic.List[object]]::new()
                $buckets = [ordered]@{}

                foreach ($f in _NmArr (_NmGet $src 'findings')) {
                    $checkId = "$(_NmGet $f 'checkId')"
                    $exposure = "$(_NmGet $checks $checkId)"
                    if (-not $exposure) { $exposure = $defaultExposure }

                    if ($exposure -eq 'full') {
                        $kept.Add((_CapPickFields -Record $f -Fields $fullFields))
                        continue
                    }
                    if (-not $buckets.Contains($checkId)) {
                        $b = _CapPickFields -Record $f -Fields $aggFields
                        $b['count'] = 0
                        $buckets[$checkId] = $b
                    }
                    $buckets[$checkId]['count'] = [int]$buckets[$checkId]['count'] + 1
                }

                $section['findings'] = @($kept)
                $section['aggregated'] = @($buckets.Values)
                foreach ($b in $buckets.Values) {
                    $aggregatedNote.Add([ordered]@{ checkId = "$($b['checkId'])"; count = [int]$b['count'] })
                }
            }
        }

        if ($section.Count) { $out[$name] = _CapRestoreArrays -Node $section }
    }

    if ($out.Count) {
        $out['analysisExposure'] = [ordered]@{
            classification = 'assets/reference/analysis-exposure.json'
            rebuilt        = $true
            note           = 'Every record here was rebuilt field by field from an allowlist, not copied. A field that is absent was never classified for export.'
            aggregatedOnly = @($aggregatedNote)
            aggregatedWhy  = 'These checks are about individual people rather than policies. Per-record detail would name which accounts are weakest, which is a target list and is not needed to plan remediation. The count is the plannable fact.'
        }
        $out['analysisExposure'] = _CapRestoreArrays -Node $out['analysisExposure']
    }
    return $out
}

function New-CapPolicyOnlyExport {
<#
.SYNOPSIS
    Build the shareable export: Conditional Access policies only, no tenant id,
    no display names.

.DESCRIPTION
    This is an allowlist, not a scrub. Rather than collecting everything and
    subtracting what looks sensitive, it starts from an empty document and
    copies in only the policy structure. Anything not named here - enrichment
    (user inventory, MFA posture, group membership), the operator account, the
    Graph scopes, the tenant id - is absent because it was never copied, not
    because a pattern matched it.

    That ordering matters. A denylist is only ever as good as the list of things
    someone remembered to remove, which is why the previous design needed a leak
    test to police its own output. Here there is nothing to police: display
    names are dropped wherever they appear, and every remaining value is a GUID,
    an enum, a boolean, a number or a timestamp.

    Policy ids are kept. They are internal references that mean nothing outside
    the tenant that issued them, and without them the policy set cannot be
    discussed or cross-referenced at all.

.PARAMETER Export
    The export to build from. Pass the already-masked export so this acts as a
    second, independent reduction rather than the only one.

.PARAMETER Analysis
    Optional map of already-masked analysis sections. Included through the
    classification in assets/reference/analysis-exposure.json, so the reviewer
    receives what the deterministic engine already established instead of
    re-deriving it. Omit it and the export is policy structure only, exactly as
    before.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Export,
        [string]$Snapshot = '',
        $Analysis
    )

    $policies = _NmGet $Export 'policies'
    if ($null -eq $policies) { $policies = @() }

    # displayName is dropped rather than aliased. The policy id already
    # identifies the policy, and a name is the one field in a CA policy that
    # reliably carries org identity ("CONTOSO - Block Legacy Auth").
    # @odata.context values are Graph metadata urls that echo the policy id back;
    # they carry no review value and are dropped. @odata.type is kept - it is how
    # a reviewer tells an ipNamedLocation from a countryNamedLocation.
    $odata = @('@odata.context')
    $clean = _CapRestoreArrays -Node (_CapStripKeys -Node $policies -Keys @('displayName') -KeySuffixes $odata)

    # Policies reference authentication strengths by id, so without their
    # definitions a reviewer cannot tell whether a policy demands
    # phishing-resistant MFA or accepts SMS - the single most important question
    # about a grant control. allowedCombinations is Microsoft's own method
    # vocabulary (fido2, sms, ...), so it conveys strength without conveying
    # tenant identity.
    $strengths = _CapRestoreArrays -Node (_CapStripKeys -Node (_NmGet $Export 'authenticationStrengths') -Keys @('displayName', 'description') -KeySuffixes $odata)
    $contexts  = _CapRestoreArrays -Node (_CapStripKeys -Node (_NmGet $Export 'authenticationContexts')  -Keys @('displayName', 'description') -KeySuffixes $odata)

    # Named locations are withheld entirely - not the name, not the ip ranges,
    # not the size, not isTrusted. Two reasons.
    #
    # Leak surface: ip ranges are the tenant's real public address space, and
    # every summarised substitute (a range count, a cidr prefix, a private-range
    # flag) is one more field to reason about in a document whose whole strength
    # is that it starts empty.
    #
    # Inference: those summaries would be judged without being verifiable. A /24
    # reads as overly broad until you know it is a datacentre egress block that
    # has to be that size, and a reviewer cannot know that from here.
    #
    # Nothing is lost that matters. The policy carries the location id, and the
    # findings that matter are referential: a location excluded from a policy
    # that enforces mfa or compliance, the same location treated differently by
    # two policies, a location referenced only by report-only policies. Those
    # need the id and nothing else. The reviewer cites the id, hands the check
    # back, and Restore-CapNames.ps1 turns it into a name locally.

    $meta = _NmGet $Export 'metadata'
    $exportable = New-CapExportableAnalysis -Analysis $Analysis
    $hasAnalysis = [bool]($exportable -and $exportable.Count)

    $contains = 'Conditional Access policy definitions, plus the authentication strengths and authentication contexts they reference (structure only).'
    if ($hasAnalysis) {
        $contains += ' Also the deterministic analysis of those policies: duplicate and merge clusters, dead weight, baseline completeness, exclusion concentration, CISA SCuBA control results with evidence, and policy-scoped findings.'
    }

    $guidance = [System.Collections.Generic.List[string]]::new()
    $guidance.Add('Named location definitions are withheld by design. Absence is not evidence that a location is safe or unsafe.')
    $guidance.Add('Where a policy references a location id, report the reference and mark it "requires local verification". Do not infer the size, trust or contents of a location, and do not score it.')
    $guidance.Add('Referential checks are in scope and need only ids: a location excluded from a policy that enforces MFA, an authentication strength or device compliance; the same location included by one policy and excluded by another; a location referenced only by report-only policies; includeLocations "All" combined with exclusions; a location excluded by many policies, which makes it a de facto global bypass.')
    $guidance.Add('Cite every policy, location, group, role and application by its full id verbatim, exactly as it appears in this file. Never abbreviate an id, never invent a name, and never refer to an object only by position ("the first policy"). The requester restores real names locally by matching those ids, so an abbreviated or paraphrased id is unrecoverable.')
    if ($hasAnalysis) {
        $guidance.Add('The analysis sections are the authority on what is true. They were produced by deterministic checks over the full export, including data withheld from this file, so they can see things this file cannot. Do not recompute duplicate clusters, dead weight, completeness or control results, and do not restate them with different numbers.')
        $guidance.Add('Quote the analysis figures as given in any summary, score or headline. If you believe a result is wrong or too lenient, say so in a section of its own, show the analysis value beside yours, and give the reason. Silently substituting your own number is the one thing that makes this file worse than no analysis at all.')
        $guidance.Add('Your task is the plan: what to do with each policy, which duplicate survives and what the merged policy looks like, whether an exclusion is a justified break-glass or accumulated drift, what the missing policies should look like, and the order to apply changes in without locking anyone out.')
        $guidance.Add('findings.aggregated carries a count and no ids, on purpose. Those checks are about individual people, and per-person detail is a target list that adds nothing to a plan. Treat the count as the fact and plan a programme, not a list.')
    }

    $doc = [ordered]@{
        capExport = [ordered]@{
            tool          = 'CAPVisualizer'
            kind          = 'policyOnlyExport'
            # 1.3 adds the analysis sections. Without them the file is exactly
            # the 1.2 shape, so it keeps the 1.2 version and older consumers
            # carry on working unchanged.
            schemaVersion = $(if ($hasAnalysis) { '1.3' } else { '1.2' })
            snapshot      = $Snapshot
            generatedUtc  = if ($meta) { "$(_NmGet $meta 'generatedUtc')" } else { '' }
            policyCount   = @($clean).Count
            contains      = $contains
            excludes      = 'Tenant id, operator account, display names, descriptions, named-location definitions, and directory enrichment (users, groups, role assignments, MFA capability).'
            notAssessable = @('namedLocations')
            reviewerGuidance = @($guidance)
        }
        policies                = @($clean)
        authenticationStrengths = @($strengths)
        authenticationContexts  = @($contexts)
    }
    foreach ($k in (_NmKeys $exportable)) { $doc[$k] = $exportable[$k] }
    return $doc
}

function New-CapSafeReviewBundle {
<#
.SYNOPSIS
    Merge the name-free export and analysis into a single review document, alias
    every remaining tenant-specific id, and verify it. This is the one file a
    user hands to a reviewer or a model.

.DESCRIPTION
    Shaped so a consumer needs no unpacking: the export's own top-level keys
    (metadata, policies, namedLocations, ...) sit alongside findings, audit,
    compliance, tests and consolidation. Verification is not optional - a
    document that fails the leak test throws rather than being returned, so a
    caller cannot accidentally surface an unsafe payload.

.PARAMETER Analysis
    Ordered map of section name -> already-masked analysis object. Passed
    through the same exposure classification as the shareable export, so a
    person-scoped check leaves as a count rather than one record per person.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$SafeExport,
        [Parameter(Mandatory)]$Dictionary,
        $Analysis,
        [string]$Snapshot = ''
    )

    # Aliases are added to the shared dictionary so Restore-CapNames can resolve
    # whatever the reviewer quotes back, and persisted by the caller.
    $null = Add-CapIdAliases -Dictionary $Dictionary -Source $SafeExport

    $doc = [ordered]@{}
    foreach ($k in (_NmKeys $SafeExport)) { $doc[$k] = $SafeExport[$k] }
    if ($Analysis) {
        # Sections the classification covers are rebuilt from an allowlist;
        # anything it does not cover (authMethods, tests) passes through as
        # before. One tenant produced 2,646 findings naming which individuals
        # cannot perform MFA, and that list was previously shipped in full.
        $classified = New-CapExportableAnalysis -Analysis $Analysis
        foreach ($k in (_NmKeys $Analysis)) {
            if ($classified -and $classified.Contains($k)) { continue }
            $v = $Analysis[$k]
            if ($null -ne $v) { $doc[$k] = $v }
        }
        foreach ($k in (_NmKeys $classified)) { $doc[$k] = $classified[$k] }
    }
    $doc['safeBundle'] = [ordered]@{
        tool          = 'CAPVisualizer'
        kind          = 'safeReviewBundle'
        schemaVersion = '1.0'
        snapshot      = $Snapshot
        pseudonymized = $true
        notice        = 'Name-free. Objects are identified by stable tokens; the token -> name dictionary was deliberately withheld. Reduces attribution, not exploitability - still treat as security-relevant.'
    }

    $safe = ConvertTo-CapSafeObject -InputObject $doc -Dictionary $Dictionary
    $violations = @(Test-CapNameLeak -Dictionary $Dictionary -InputObject $safe -RequirePseudonymized)
    if ($violations.Count) {
        $detail = ($violations | Select-Object -First 5 | ForEach-Object {
            if ($_.context) { "$($_.kind): $($_.value) [$($_.context)]" } else { "$($_.kind): $($_.value)" }
        }) -join '; '
        throw "Safe review bundle rejected: $($violations.Count) leak(s) detected ($detail)."
    }
    return $safe
}

function Import-CapNameDictionary {
<#
.SYNOPSIS
    Load a dictionary from disk, or find it next to an export (raw/names.json).

.DESCRIPTION
    Microsoft-global constants are merged in on load, so a dictionary written
    before those constants were seeded still resolves them. Tenant entries
    always win: the merge only fills ids the dictionary does not already carry.
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

    $entries = _NmGet $doc 'entries'
    if ($entries -is [System.Collections.IDictionary]) {
        $merged = 0
        $flagged = 0
        foreach ($g in (Get-CapGlobalConstantEntry).GetEnumerator()) {
            if (-not $entries.Contains($g.Key)) { $entries[$g.Key] = $g.Value; $merged++; continue }
            # The id is already present because a collector picked the object up
            # from the directory. It is still a Microsoft constant, so flag it:
            # without the flag the masker rewrites Microsoft's own vocabulary
            # (a SCuBA statement naming the Guest User role) and the leak test
            # then reports that vocabulary as tenant data. The existing name is
            # left alone; only the classification is added.
            $existing = $entries[$g.Key]
            if ($existing -is [System.Collections.IDictionary] -and -not (_NmGet $existing 'global')) {
                $existing['global'] = $true
                $flagged++
            }
        }
        # 'count' stays as written. It feeds the snapshot binding fingerprint,
        # and these constants are identical in every tenant so they identify
        # nothing. Bumping it would invalidate every previously stamped bundle.
        $doc['globalsMerged'] = $merged
        $doc['globalsFlagged'] = $flagged
    }
    return $doc
}

Export-ModuleMember -Function New-CapNameDictionary, ConvertTo-CapSafeObject, ConvertFrom-CapSafeObject, `
    Restore-CapNameText, Test-CapNameLeak, Import-CapNameDictionary, Get-CapWellKnownIdSet, `
    Repair-CapRestoredIds, `
    Resolve-CapTruncatedIds, Get-CapUnresolvedIds, Get-CapTruncatedIds, `
    Test-CapWellKnownId, Get-CapUnresolvedTokens, Clear-CapMatcherCache, Add-CapIdAliases, New-CapSafeReviewBundle, New-CapPolicyOnlyExport, `
    Get-CapFirstPartyAppMap, Get-CapFirstPartyAppTokens, Get-CapGlobalConstantEntry, `
    Get-CapBuiltinRoleMap, Get-CapBuiltinAuthStrengthMap, Test-CapReservedName, `
    Get-CapAnalysisExposure, New-CapExportableAnalysis, `
    Get-CapAliasTypes
