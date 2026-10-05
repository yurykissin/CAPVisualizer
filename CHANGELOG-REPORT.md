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
  `CapFindings`, `CapScope`, `CapTest`, `CapDelta`,
  `CapAuthMethods`, `CapReport`, `CapVisual` (all under `scripts/modules/`).
- Viewer assets: `assets/template.html`, `assets/app.js`, `assets/styles.css`.
- Baseline / reference packs: `assets/reference/baselines/*` (e.g. CISA SCuBA
  `MS.AAD.*`).
- Offline orchestrators: the `-FromJson` path of `scripts/Invoke-CapVisualizer.ps1`,
  and `Invoke-CapConsolidate.ps1`, `Invoke-CapTest.ps1`,
  `Compare-CapSnapshot.ps1`, `Get-CapUserScope.ps1`.

---

## [Unreleased]

### Added
- **Output and baseline provenance** — exports, manifests, safe-review bundles,
  and the viewer now identify the CAPVisualizer version and Git commit. The CISA
  SCuBA 1.6 pack is pinned to an exact upstream commit and preserves each
  official versioned control identifier.
- **Baseline drift check** — `Test-CapBaselineCurrency.ps1` compares the packaged
  control revisions with the current upstream baseline without adding network
  access to normal tenant runs.
- **Cross-platform unattended certificate authentication** — app-only runs now
  accept `-CertificatePath` (plus optional `-CertificatePassword`) for PFX-based
  authentication on macOS/Linux, while retaining certificate-store thumbprint
  authentication for Windows.
- **Safe snapshot retention** — `Remove-CapSnapshot.ps1` previews by default and
  only removes expired timestamped snapshot directories directly beneath the
  resolved output root. It rejects broad roots and never follows links.
- **Repository governance** — added pull-request CI, CODEOWNERS, and a private
  vulnerability-reporting policy.

### Removed
- **Offline what-if and gap permutation** — removed the standalone what-if
  evaluator, gap-permutation engine, and the assertion DSL's `whatif` type.
  Policy-as-code assertions now cover deterministic compliance results and
  finding thresholds only.

### Added
- **Coverage-gap sign-in queries and run instructions in the report** — the
  "Policy usage query" tab becomes **"Sign-in log queries"** and now carries
  three copy-ready KQL queries with a numbered "Before you run these" procedure:
  confirming a diagnostic setting actually exports `SignInLogs` to a workspace,
  obtaining *Log Analytics Reader* on it, opening the Logs editor, and setting
  the observation period in the time-range picker. Alongside the existing
  per-policy usage query, two new queries invert the question and report
  coverage gaps: sign-ins where **no policy applied at all**, and sign-ins where
  **no policy enforced a multifactor grant**.

  Both gap queries substitute a placeholder for an empty
  `ConditionalAccessPolicies` array before expanding it, because `mv-expand` and
  `mv-apply` silently drop those rows — and they are exactly the ungoverned
  sign-ins the queries exist to surface. A query written without it under-reports
  the gap. Report-only results are excluded from the applied counts, since a
  report-only match enforces nothing.

  Every query deliberately omits a `TimeGenerated` filter, which Basic,
  Auxiliary, Bronze, federated, and data lake tables reject with *"Bronze Logs
  table query is missing time range"*; the restriction applies to filtering, so
  `min()`/`max()` inside `summarize` are still used. The MFA query documents that
  a gap is not proof MFA was absent — per-user MFA, security defaults, or an
  existing multifactor claim can satisfy it without a policy grant — and points
  at `AuthenticationRequirement` for the genuine single-factor exposure.

  The tab states that gap output contains user principal names and IP addresses
  and is therefore deliberately outside the name-free safe export. The copy-button
  handler is now generic (`data-query-copy`) instead of bound to one element id.

- **"Export safely" button in the HTML report** — one click saves a single,
  name-free JSON containing the policy structure plus every analysis result, so
  sharing a report for review no longer requires running a second script. A
  dialog first states plainly what was removed, what was kept, and that
  anonymization reduces attribution rather than exploitability. The payload is
  built and leak-tested by PowerShell during the run and embedded verbatim —
  nothing is masked in the browser — and the button is hidden entirely if no
  verified payload could be produced. `Export-CapSafeBundle.ps1` now writes the
  same file as `cap-safe-review-<snapshot>.json`. See
  [docs/SAFEEXPORT.md](docs/SAFEEXPORT.md).
- **Name resolution at build time** — the HTML generator and `report/*` now read
  `raw/names.json` alongside the name-free export. Dictionary present → real names
  render exactly as before; dictionary absent → object ids render and the report
  still builds. All `analysis/*.json` (and the JUnit/SARIF test output) are written
  through the name-free projection. See
  [docs/SAFEEXPORT.md](docs/SAFEEXPORT.md). _(Requires schema ≥ 3.0; 2.x exports are
  auto-split on import.)_
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
- **Unread-condition guard.** The condition keys the analyzer consumes are declared in
  one place, and anything present in the policy but not consumed is reported as a
  warning in the run log, the report, the shareable export and the reviewer digest. A
  test fails on it. This is the systemic answer to the shape-drift class below: when
  Microsoft adds a new shape, the tool now says so instead of silently reporting the
  condition as absent.
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

#### Graph condition shapes read incompletely (policies wrongly reported as dead weight)

A managed-provider policy named `... DO NOT DELETE OR MODIFY` was reported as
targeting nobody and recommended for retirement. It targets a named partner tenant
through the guest/external selector, which the analyzer did not read.

That is the shape of the whole bug class. When Microsoft adds a new shape for an
existing condition, a tool that reads only the old shape does not error - it reports
the condition as **absent**. Absent targeting reads as "does nothing", which reads as
dead weight, which reads as "delete it". The visual report renders raw Graph, so it
stayed correct while every judgement built on it was wrong, which is why this went
unnoticed.

- **Guest and external targeting** is now read from both the legacy literal and the
  modern selector, including comma-separated type lists and the single bare string
  Graph unrolls a lone partner tenant to.
- **The duplicate fingerprint and the what-if evaluator** were taught the same rules,
  so two policies trusting *different* partner tenants no longer fingerprint as
  identical.
- **The retire heuristic is suppressed when the policy name negates it.** A bare
  `delete` was matching inside `DO NOT DELETE`. `do not use` still counts.
- **Also now read:** application filters, Global Secure Access traffic profiles under
  both keys, device lists, the deprecated `deviceStates` block, and service principal
  and agent identity targeting.

## [baseline]

- Audit (contradictions, legacy-auth coverage, exemption exposure), SCuBA compliance
  scoring, risk-scored findings, what-if / scope evaluation, snapshot delta, and the
  HTML viewer.
