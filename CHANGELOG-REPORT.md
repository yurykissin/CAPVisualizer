# Changelog — Report (JSON → analysis & HTML)

This changelog covers the **analysis and reporting component**: everything that
consumes an existing `export.json` and produces findings, compliance/consolidation
results and the HTML viewer.

> **Golden rule — when does a change land here?**
> A change belongs in *this* file if it only changes **how an existing export is
> analysed or presented** (new findings/audit checks, compliance or consolidation
> logic, report layout, viewer tabs, styles). **These changes need no new export** —
> re-run offline against your existing snapshot:
>
> ```
> ./scripts/Invoke-CapVisualizer.ps1 -FromJson ./output/<timestamp> -OutputRoot ./output/
> ```
>
> Changes that alter what is collected from Entra or the JSON shape go in
> [`CHANGELOG-EXPORT.md`](./CHANGELOG-EXPORT.md) instead and **do** require a fresh
> export.

## Compatibility

The analyzer reads exports at `metadata.schemaVersion` (see the collector changelog).
If a report feature needs data not present in an older schema, note the **minimum
schema version** on that entry so users know a re-export is required.

## Component scope (files owned by the report side)

- Analysis engines: `CapNormalize`, `CapAudit`, `CapCompliance`, `CapConsolidate`,
  `CapFindings`, `CapAnalyze`, `CapScope`, `CapWhatIf`, `CapTest`, `CapDelta`,
  `CapAuthMethods`, `CapReport`, `CapVisual` (all under `scripts/modules/`).
- Viewer assets: `assets/template.html`, `assets/app.js`, `assets/styles.css`.
- Baseline / reference packs: `assets/reference/baselines/*` (e.g. CISA SCuBA
  `MS.AAD.*`).
- Offline orchestrators: the `-FromJson` path of `scripts/Invoke-CapVisualizer.ps1`,
  and `Invoke-CapConsolidate.ps1`, `Invoke-CapAnalyze.ps1`, `Invoke-CapTest.ps1`,
  `Invoke-CapWhatIf.ps1`, `Compare-CapSnapshot.ps1`, `Get-CapUserScope.ps1`.

---

## [Unreleased]

### Added
- **Audit check `combined-risk-conditions`** — flags a single policy that conditions
  on both user risk *and* sign-in risk. Entra ORs the two signals under one grant
  control, preventing the recommended distinct responses (secure password change for
  user risk vs. MFA for sign-in risk). Maps to CISA SCuBA MS.AAD.2.1 / MS.AAD.2.3.
- **"References & attributions"** in the report footer and `DISCLAIMER.md` (CISA
  SCuBA / ScubaGear CC0-1.0, NIST 800-53 public domain, MITRE ATT&CK® attribution).
- **Compare-policies viewer tab** — pick two policies from one export, collapsible
  synced accordions, highlighted diff table, "show only differences" toggle, and a
  "same target users" filter.
- **Consolidation engine** (`CapConsolidate` / `Invoke-CapConsolidate.ps1`) — exact
  duplicate, overlap and merge clustering, dead-weight and baseline-completeness gaps,
  estimated policy-count reduction.
- **Self-explaining findings** — `Summary` (generic) and `Logic` ("how detected")
  added to `New-CapFinding`; the viewer renders "Why it matters" (threat) and "How
  detected" (logic) and always shows the description.
- **New finding `disabled-privileged-account`** — a privileged role held by an account
  with `accountEnabled = false`. _(Requires schema ≥ 2.0, which already carries
  `accountEnabled`; no re-export needed for current exports.)_

### Changed
- Inactive-privileged-account threshold default lowered 90 → 30 days.

### Fixed
- StrictMode `.Count`-on-scalar errors in `CapAudit` / `CapCompliance` (wrap the whole
  pipeline in `@(...)`, not just the input).
- Relative `-OutputRoot` / `-OutputPath` crash in `Save-CapJson` and `New-CapVisual`
  (`WriteAllText` resolved relative paths against the process cwd; now normalized via
  `GetUnresolvedProviderPathFromPSPath`).
- Grouped findings no longer drop the per-object description.

## [baseline]

- Audit (contradictions, legacy-auth coverage, exemption exposure), SCuBA compliance
  scoring, risk-scored findings, what-if / scope evaluation, snapshot delta, and the
  HTML viewer.
