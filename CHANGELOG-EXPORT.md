# Changelog — Collector (Entra → JSON export)

This changelog covers the **data-collection component**: the code that connects to
Microsoft Graph and produces the offline `export.json` snapshot
(`raw/export.json` under each output folder).

> **Golden rule — when does a change land here?**
> A change belongs in *this* file if it alters **what is collected from Entra or the
> shape of the exported JSON** (new fields, new object types, new enrichment,
> changed Graph queries or permissions). **Any entry here means downstream consumers
> should take a fresh export** — re-rendering an old JSON with `-FromJson` will not
> surface the new data.
>
> Purely analytical or presentational changes (new findings, report layout, viewer
> tabs) do **not** go here — see [`CHANGELOG-REPORT.md`](./CHANGELOG-REPORT.md). Those
> can be re-run offline against an existing export of a compatible schema version.

## Export schema version

The contract is stamped in every snapshot at `metadata.schemaVersion`
(`scripts/modules/CapExport.psm1`). Bump it whenever the JSON shape changes in a way
that consumers must be aware of. **Current: `3.0`.**

## Component scope (files owned by the collector)

- `scripts/modules/CapCommon.psm1` — Graph auth, `directoryObjects/getByIds` name
  resolution, `Save-CapJson`.
- `scripts/modules/CapExport.psm1` — policy/named-location/auth-strength/auth-context
  export, reference collection, `schemaVersion`, offline `Import-CapExportJson`.
- `scripts/modules/CapEnrich.psm1` — Graph enrichment (users incl. `accountEnabled`
  and sign-in activity, groups, group owners, role assignments, MFA capability).
- `scripts/Test-Prerequisites.ps1` — required Graph scopes / connectivity checks.
- `scripts/Register-CapSchedule.ps1` — scheduled export runs.
- The **live-collection path** of `scripts/Invoke-CapVisualizer.ps1` (everything up to
  writing `raw/export.json`; the offline `-FromJson` path is report-side).

---

## [Unreleased]

### Changed — **breaking, schemaVersion 3.0**
- **Names are no longer written into `raw/export.json`.** Every run now writes two
  files: a name-free `raw/export.json` (structure + object ids) and a local-only
  `raw/names.json` token → name dictionary. The embedded `nameMap` is gone and
  `metadata.schemaVersion` is now `3.0`. This lets the export structure be reviewed
  by a cloud model without handing over tenant identities. Legacy 2.x exports are
  auto-split on import, so `-FromJson` keeps working against old snapshots.
- **`-Redact` is deprecated.** It only pseudonymized GUIDs — names, UPNs, IP ranges
  and device-filter rules survived it — and it discarded its own map, so the result
  could never be mapped back. It now warns and behaves as `-Pseudonymize`.

### Added
- **`-Pseudonymize`** — aliases every tenant-specific GUID (`OBJ-004`, `POL-002`,
  `TENANT-001`) reversibly via the dictionary. Microsoft first-party app ids and
  built-in role template ids are allowlisted and stay readable.
- **`-NoNames`** (skip the dictionary entirely) and **`-Names <path>`** (point an
  offline render at a dictionary elsewhere on disk).
- **`scripts/Export-CapSafeBundle.ps1`** — assembles `<snapshot>/safe/` with only
  name-free artifacts, then verifies it and **fails closed**: any surviving name,
  unallowlisted GUID or IP-shaped string deletes the bundle and throws.
- **`scripts/Restore-CapNames.ps1`** — maps a reviewer's `.md`/`.html`/`.json`/`.csv`
  output back to real names locally, with **snapshot binding** as a hard gate.
- **`scripts/modules/CapNames.psm1`** — dictionary construction, masking, restore,
  the well-known-id allowlist and the leak test.
- **`manifest.json` per-file `containsNames` flag**, plus `pseudonymized`,
  `namesSplit` and `dictionary` metadata.
- **[docs/SAFEEXPORT.md](docs/SAFEEXPORT.md)** — the two-file contract, the upload
  checklist and an honest residual-risk statement.

## [schemaVersion 2.0] — baseline

- Export captures CA policies, named locations, authentication strengths and
  authentication contexts, plus an embedded `nameMap` for offline name resolution.
- Enrichment captures users (`id`, UPN, `displayName`, `accountEnabled`, `userType`,
  `onPremisesSyncEnabled`, last sign-in), groups and owners, privileged role
  assignments, and MFA capability.
- `getByIds` resolves users, groups, service principals, directory roles and
  applications; unresolved ids (e.g. deleted objects) are omitted and surface as raw
  GUIDs in the report.
