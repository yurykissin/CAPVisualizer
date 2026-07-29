# Safe export - sharing a report with an AI or a third party

A Conditional Access export is one of the most sensitive artifacts a tenant can
produce. It names your admins, your break-glass accounts, your office IP ranges
and your device naming conventions - and it shows exactly where your coverage
gaps are. That makes "just upload it to a model" a bad default.

CAPVisualizer solves this by **separating names from structure**. Every run
writes two files instead of one:

| File | Contains | Leaves the machine? |
| --- | --- | --- |
| `raw/export.json` | Policy structure and object ids. **No names.** | Yes - this is the shareable artifact |
| `raw/names.json` | The token -> name dictionary. | **Never** |

The structure is what a reviewer actually needs. The names are what you cannot
afford to hand over. Splitting them costs you nothing locally, because the
**HTML generator reads both files at build time**:

- Dictionary present -> the report shows real names, exactly as before.
- Dictionary absent -> the report shows ids, and still renders.

There is no runtime file picker and no second HTML file. One report, one build.

## The workflow

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

## What gets masked

- Display names of policies, users, groups, roles, applications and service
  principals, and every user principal name.
- The tenant id and the **operator account** that ran the export.
- Named-location names, **IP ranges/CIDR blocks** and countries.
- **Device-filter rules**, which routinely embed naming conventions such as
  `device.displayName -startsWith "CONTOSO-"`.
- Policy descriptions, authentication strength and authentication context labels.
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
