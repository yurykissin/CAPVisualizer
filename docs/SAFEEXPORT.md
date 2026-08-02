# Safe export - sharing a report with an AI or a third party

A Conditional Access export is one of the most sensitive artifacts a tenant can
produce. It names your admins, your break-glass accounts, your office IP ranges
and your device naming conventions - and it shows exactly where your coverage
gaps are. That makes "just upload it to a model" a bad default.

CAPVisualizer solves this by **separating names from structure**. Every run
writes two files instead of one:

| File | Contains | Safe to share? |
| --- | --- | --- |
| `raw/export.json` | Policy structure, object ids **and the tenant id**. No names. | **No.** Name-free, but still tenant-attributable |
| `raw/names.json` | The token -> name dictionary. | **Never** |

> [!IMPORTANT]
> `raw/export.json` is **not** the artifact you share. It has no display names,
> but it keeps every object GUID and the tenant id in the clear, and the tenant
> id maps directly to your organization. The artifact you share is the **safe
> bundle**: the "Export safely" button, or `Export-CapSafeBundle.ps1`. Only
> those alias the tenant id and object ids and are leak-tested before they are
> written.

The structure is what a reviewer actually needs. The names are what you cannot
afford to hand over. Splitting them costs you nothing locally, because the
**HTML generator reads both files at build time**:

- Dictionary present -> the report shows real names, exactly as before.
- Dictionary absent -> the report shows ids, and still renders.

There is no runtime file picker and no second HTML file. One report, one build.

## The workflow - from the report (recommended)

Open `visual/index.html` and click **Export safely** in the header. It explains
what is removed and what is kept, then saves a single JSON file wherever you
choose.

That file is an **allowlist**, not a scrub. It starts as an empty document and
copies in only what a Conditional Access review needs. Anything not named below
is absent because it was never copied, not because a pattern matched it, which
is why the button is always available and is not gated on a leak test.

**What it carries**

- Policy structure: id, state, conditions, targeting, grant and session
  controls. Every id is a GUID.
- Authentication strengths and authentication contexts, structure only. A policy
  gated on a custom strength is unreviewable without its definition - there is
  no way to tell phishing-resistant from SMS - so `allowedCombinations` travels.
  It is Microsoft's own method vocabulary (`fido2`, `sms`), so it conveys
  strength without conveying identity.

**What it does not carry**

- The tenant id, the operator account, and every `displayName` and
  `description`.
- Directory enrichment: user inventory, group membership, role assignments, MFA
  posture. That is 98% of a real export by volume and none of it is a policy.
- Graph `@odata.context` metadata urls.
- **Named location definitions, entirely.** Not the name, not the IP ranges, and
  deliberately not a summary either - no range count, no CIDR prefix, no
  `isTrusted` flag.

That last one is a design decision worth stating plainly. Every summarised
substitute is one more field to reason about in a document whose whole strength
is that it starts empty, and each invites a judgement the reviewer cannot check:
a `/24` reads as overly broad until you know it is a datacentre egress block
that has to be that size.

Nothing useful is lost. The policy still carries the **location id**, and the
findings that matter are referential rather than descriptive:

- a location excluded from a policy that enforces MFA, an authentication
  strength or device compliance - a hole in the control;
- the same location included by one policy and excluded by another;
- a location referenced only by report-only policies, so the intent was never
  enforced;
- `includeLocations: All` plus exclusions, the "trust the office" pattern;
- one location excluded by many policies, which makes it a de facto global
  bypass.

Each of those needs the id and nothing else. So the export ships
`capExport.notAssessable` and `capExport.reviewerGuidance`, which tell the
reviewer to report such references as "requires local verification" and never to
score them. Declaring the gap matters: without it, a policy carrying a location
exclusion looks *tidier* than one without, because there is nothing left to
criticise.

The same guidance requires every object to be cited by its **full id, verbatim**.
That is what makes the round trip work - you run `Restore-CapNames.ps1` over the
returned report and the ids become real names on your machine.

`Restore-CapNames.ps1` now polices that round trip rather than assuming it. It
recovers an abbreviated id where the prefix matches exactly one dictionary
entry, refuses to guess where a prefix matches more than one, prints an
accounting of how many ids resolved and which did not, and **exits non-zero when
any reference is left unreadable**. A partial restore can no longer look like a
clean run. Use `-AllowUnresolved` only when you have decided the leftovers are
acceptable.

### Collections stay collections

PowerShell unrolls a one-item array, so a rebuilt object graph would serialize
`"allowedCombinations": ["fido2"]` as the bare string `"fido2"`. Anything
iterating that property then walks the string one character at a time, and a
FIDO2-only phishing-resistant strength reads as a list of single letters. The
same fault hit `excludeGroups`, `builtInControls`, `clientAppTypes` and ten
other properties, so it changed how the scope of a policy reads, not just how it
looks. The export now restores array shape for every collection-valued Graph
property before writing.

Nothing is masked in the browser. The payload is built by PowerShell during the
run and embedded verbatim, so what the button hands you is what the run
produced. It is built from the export as collected, before any dictionary
re-hydration, so re-rendering a snapshot with `-FromJson` cannot leak names back
into it.

Embedding it adds no exposure: the HTML already contains the *real* names, which
is exactly why it must stay local while the exported file may travel.

On a real tenant the file is roughly 175 KB, down from an 11.5 MB export.

## The workflow - from the command line

Use this when you want the artifacts as separate files, or you are scripting.

```powershell
# 1. Normal run. Writes the name-free export and the local dictionary.
./scripts/Invoke-CapVisualizer.ps1

# 2. Assemble the bundle you are allowed to upload.
./scripts/Export-CapSafeBundle.ps1 -SnapshotPath ./output/<snapshot>

# 3. Hand ONLY <snapshot>/safe/ to the model or the third party.

# 4. Map the model's output back to real names, locally.
./scripts/Restore-CapNames.ps1 -Path ./ai-report.md `
    -Names ./output/<snapshot>/raw/names.json -InPlace
```

`Export-CapSafeBundle.ps1` **fails closed**: after assembling the bundle it
scans every file for every value in the dictionary, plus unallowlisted GUIDs and
IP-shaped strings. If anything is found, the bundle is deleted and the run
throws. A bundle that exists has been verified clean.

The folder also contains `cap-safe-review-<snapshot>.json` - the same single
file the **Export safely** button produces, so either route gives a reviewer an
interchangeable artifact.

## What gets masked

- Display names of policies, users, groups, roles, applications and service
  principals, and every user principal name.
- The tenant id and the **operator account** that ran the export.
- Named-location names, **IP ranges/CIDR blocks** and countries.
- **Device-filter rules**, which routinely embed naming conventions such as
  `device.displayName -startsWith "CONTOSO-"`.
- Policy descriptions, authentication strength and authentication context labels.
- **Application filter rules**, for the same reason as device-filter rules.
- **Partner tenant ids** named by a guest or external-user selector. Unlike a
  policy id, which means nothing outside the tenant that issued it, this is a
  global identifier for a named third-party organisation: it says who the
  customer's managed provider or federation partner is. It leaves as
  `EXTTENANT-001` and is restored locally like any other token.
- Generated finding and audit prose, which interpolates names into sentences.

Masking is applied three ways: a targeted pass over known fields, a structural
sweep over any property whose name is known to carry an identity (so a new Graph
field cannot silently leak), and a text pass over generated prose. The leak test
backs all three.

## What is deliberately *not* masked

Microsoft **first-party application ids** and **built-in directory role
template ids** are global constants, identical in every tenant. Masking
`62e90394-69f5-4237-9190-012177145e10` would only make the review worse, so
well-known identifiers are allowlisted and stay readable.

A display name that is itself a bare GUID is also left alone. It is an
identifier rather than a name, and registering it would make masking rewrite
that GUID wherever it appears, including where it is genuinely an object id. On
a real snapshot that rewrote one policy id into another policy's id, so the
duplicate cluster listed one policy twice and the other disappeared.

## Restore will not re-hydrate the shareable export itself

`Restore-CapNames.ps1` refuses to run against the safe bundle and exits
non-zero. That file exists precisely so it can leave the building with no names
in it; putting the names back turns the one artifact designed to be safe to send
into the one artifact that must never be sent, sitting in the directory people
share from. Point it at the review or report written *from* the bundle. Use
`-AllowUnresolved` if you genuinely need a local named copy.

## Pseudonymization

By default the token *is* the object's own GUID: names are removed, ids are left
alone. That is the smallest possible change and keeps the export structurally
identical.

The safe bundle goes one step further and **pseudonymizes by default**: every
tenant-specific GUID becomes a stable alias (`OBJ-004`, `POL-002`,
`TENANT-001`). The `alias -> GUID -> name` chain is recorded in the same local
dictionary, so re-hydration still works from either form.

Why bother, if GUIDs are not credentials? Because they are stable and
tenant-unique, so they support **correlation**. The same GUID appearing in a
support ticket, an earlier AI session or a leaked document joins those datasets
together. The tenant id is worse: it maps directly to your organization and is
publicly discoverable from any of your domains. A GUIDs-only file is
*pseudonymous*, not anonymous. Aliasing closes that gap.

`-Redact` is deprecated. It only pseudonymized GUIDs - names survived it
entirely - and it threw away its own map, so results could never be mapped back.
It now warns and behaves as `-Pseudonymize`.

## Re-hydration and the stale-dictionary trap

The dictionary written at export time is the same one used after the model
returns its report. `Restore-CapNames.ps1` handles `.md`, `.html`, `.json` and
`.csv`, matches inside markdown tables, HTML attributes and fenced code blocks,
and reports any alias-shaped token it could not resolve rather than leaving it
silently unmapped.

It also enforces **snapshot binding**: the dictionary records the snapshot it
belongs to, and re-hydration **refuses to run** against output from a different
snapshot. Applying a stale dictionary would quietly put the wrong real names
into a client-facing report - the worst failure mode this design has. Override
with `-IgnoreSnapshot` only when you know exactly why.

## Honest residual risk

**Anonymization reduces attribution, not exploitability.**

Even a perfectly anonymized export is still a map of where your gaps are: which
apps are unprotected, which accounts are excluded, which controls are report-only.
Nothing in this pipeline changes that, and no masking scheme can. The safe
bundle is *safe to share*, not *harmless* - it is still security-relevant
material, and it should go only to parties and services you would trust with a
gap analysis.

Manage that risk by choosing **where the file goes**, not by assuming the
masking made it inert:

- Prefer a model or service with a no-training, no-retention commitment.
- Do not paste the bundle into a public chat or a general-purpose assistant.
- Keep `names.json`, `report/*` and `visual/index.html` on the machine that
  produced them. They contain names by design, and `manifest.json` marks each
  file with `containsNames` so you can tell at a glance.

## Related switches

| Switch | Effect |
| --- | --- |
| `-Pseudonymize` | Alias tenant-specific GUIDs and the tenant id. Default inside the safe bundle. |
| `-NoNames` | Skip the dictionary entirely - the local report renders with ids too. |
| `-Names <path>` | Point an offline `-FromJson` render at a dictionary elsewhere on disk. |
| `-Redact` | Deprecated alias for `-Pseudonymize`. |
