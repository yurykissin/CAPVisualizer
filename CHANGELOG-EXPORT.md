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
that consumers must be aware of. **Current: `2.0`.**

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

_No collector/schema changes pending._

## [schemaVersion 2.0] — baseline

- Export captures CA policies, named locations, authentication strengths and
  authentication contexts, plus an embedded `nameMap` for offline name resolution.
- Enrichment captures users (`id`, UPN, `displayName`, `accountEnabled`, `userType`,
  `onPremisesSyncEnabled`, last sign-in), groups and owners, privileged role
  assignments, and MFA capability.
- `getByIds` resolves users, groups, service principals, directory roles and
  applications; unresolved ids (e.g. deleted objects) are omitted and surface as raw
  GUIDs in the report.
