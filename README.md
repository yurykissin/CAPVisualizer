# CAPVisualizer

**Export, report on, and visualize all your Microsoft Entra Conditional Access
(CA) policies - fully locally, read-only, and shareable.**

CAPVisualizer is a PowerShell 7 toolkit you download and run on your own
machine. It reads every Conditional Access policy from your Entra tenant and
produces:

- **Detailed reports** in both **JSON** and **CSV** (targets, conditions, grant
  and session controls, blocks, hygiene findings).
- A **self-contained offline HTML** visualization - each policy individually and
  an overview of all of them - that opens in any browser with **no internet**.
  Every assignment, condition, grant and session control is shown with the same
  friendly wording as the Entra portal.
- **Delta reports** so periodic runs show exactly what changed since last time.
- An **offline render mode** (`-FromJson`) that rebuilds the full report + HTML
  from an existing JSON export - **no sign-in, no permissions, no network**.

> [!IMPORTANT]
> CAPVisualizer is **read-only** and runs **entirely locally**. It makes **no
> changes** to your tenant and **shares nothing online** during a run. Please
> read the [Disclaimer](DISCLAIMER.md) before using it. Community project - **not
> affiliated with Microsoft**. Provided "as is", no warranty (MIT).

---

## Why

Conditional Access is the front door of an Entra tenant, but its policies are
hard to review at a glance and drift over time. CAPVisualizer gives you a
point-in-time, offline, auditable picture of your CA posture - and a diff
between snapshots - using the **lowest possible permissions**.

## Quickstart

```bash
# 1. Check prerequisites (PowerShell 7 + Microsoft.Graph.Authentication)
pwsh ./scripts/Test-Prerequisites.ps1 -Install

# 2. Export + report + visualize (interactive read-only sign-in)
pwsh ./scripts/Invoke-CapVisualizer.ps1

# 3. Open the result
#    output/<timestamp>/visual/index.html
```

Names are resolved by default; add `-Delta` to compare against your previous
run, or `-SkipResolveNames` for the minimal `Policy.Read.All`-only footprint.
No consent to spare? Render from a JSON file you already have with
`-FromJson ./policies.json` (fully offline). Full options in
[docs/USAGE.md](docs/USAGE.md).

## Lowest-privilege by design

| Feature | Graph scope | Read-only |
|---------|-------------|-----------|
| Core export / report / visual / delta | `Policy.Read.All` | ✅ |
| Name resolution (default; GUID → display name) | `Directory.Read.All` (or narrower) | ✅ |

No write scopes are ever requested. Use `-SkipResolveNames` for the minimal
`Policy.Read.All`-only footprint. Details: [docs/PERMISSIONS.md](docs/PERMISSIONS.md).

## What each run produces

```
output/<yyyyMMdd-HHmmss>/
  raw/export.json          # verbatim Graph data + directory enrichment
  report/policies.json     # enriched, analysis-ready
  report/policies.csv      # one flattened row per policy
  report/findings.json/csv # hygiene / gap findings
  report/summary.json      # counts and overview
  analysis/audit.json      # contradictions + exemption exposure
  analysis/findings.json   # risk-scored findings (impact x likelihood)
  analysis/compliance.json # CISA SCuBA (MS.AAD.*) control results
  analysis/tests.json      # assertion results (+ .junit.xml / .sarif.json)
  delta/delta.json         # when -Delta and a baseline exist
  visual/index.html        # self-contained offline viewer (all tabs)
  manifest.json            # SHA-256 of every output file
  transcript.txt           # run log (unless -NoTranscript)
```

## Features

- **Full CA export** - policies plus dependencies (named locations,
  authentication strengths, authentication context references).
- **JSON + CSV reports** - both machine- and spreadsheet-friendly.
- **Offline HTML visualization** - per-policy assignment → condition → control
  flow, plus an all-policies overview. Zero external requests (no CDN).
- **Delta / periodic** - immutable timestamped snapshots and field-level diffs
  between runs. See [docs/DELTA.md](docs/DELTA.md).
- **Hygiene / gap checks** - flags report-only/disabled policies, enabled
  policies with no controls, missing legacy-auth block, and "All users" targeting
  with no break-glass exclusion. Flags only - never changes anything.
- **Interactive or unattended auth** - delegated sign-in by default; app
  registration (certificate or secret) for scheduled runs.
- **Redaction** (`-Redact`) - strip tenant id and object GUIDs to share safely.
- **Integrity manifest** - SHA-256 of every output file.
- **Local scheduling helper** - cron / Task Scheduler. See
  [docs/SCHEDULING.md](docs/SCHEDULING.md).
- **Cross-platform** - PowerShell 7 on macOS, Linux, Windows.

## Offline analysis engines

Beyond export and reporting, every run also performs offline reasoning over the
normalized policy set and the read-only directory enrichment - no extra tools, no
network, reproducible from a JSON export via `-FromJson`:

- **Per-user scope** ([docs/SCOPE.md](docs/SCOPE.md)) - which policies actually
  target a principal (direct / via group or role / excluded). `Get-CapUserScope.ps1`.
- **What-if** ([docs/WHATIF.md](docs/WHATIF.md)) - simulate one sign-in; separates
  *definitive* from *signal-dependent* outcomes. `Invoke-CapWhatIf.ps1`.
- **Gap permutation** ([docs/ANALYZE.md](docs/ANALYZE.md)) - permute unspecified
  signals to surface bypasses and no-enforcement paths. `Invoke-CapAnalyze.ps1`.
- **Contradiction audit** ([docs/AUDIT.md](docs/AUDIT.md)) - self-defeating
  include/exclude overlaps, legacy-auth gaps, exemption exposure.
- **Risk-scored findings** ([docs/FINDINGS.md](docs/FINDINGS.md)) - deterministic
  impact x likelihood model with MITRE / CISA / NIST references.
- **Compliance baseline** ([docs/COMPLIANCE.md](docs/COMPLIANCE.md)) - CISA SCuBA
  `MS.AAD.*` control matrix, evaluated from a versioned baseline pack.
- **Assertion engine** ([docs/TESTING.md](docs/TESTING.md)) - declarative JSON
  assertions with JUnit / SARIF / JSON output and CI exit codes.
  `Invoke-CapTest.ps1`.

These are surfaced as extra tabs in the offline viewer and as `analysis/*.json`
files.

### Capability parity

Each engine reproduces the *result and intent* of a well-known community tool,
**authored independently** from public Entra behaviour and open standards:

| CAPVisualizer pillar        | Mirrors the result of | Public standards referenced          |
| --------------------------- | --------------------- | ------------------------------------ |
| Scope / what-if / gap       | CAPSlock (SpecterOps) | Entra CA evaluation model            |
| Contradiction audit         | noCAP                 | Entra CA assignment model            |
| Risk-scored findings        | EntraFalcon           | MITRE ATT&CK, CISA SCuBA, NIST 800-53 |
| Compliance baseline         | ScubaGear             | CISA SCuBA `MS.AAD.*`, NIST 800-53   |
| Assertion / test engine     | Maester               | JUnit, SARIF 2.1.0                   |

> [!NOTE]
> **Independence statement.** No source code, algorithm, or configuration is
> copied from CAPSlock, noCAP, EntraFalcon, ScubaGear, Maester, or any other
> tool. Only observable behaviour and **public** standards - CISA SCuBA control
> IDs (`MS.AAD.*`), NIST 800-53 controls, MITRE ATT&CK technique IDs, and the
> JUnit/SARIF output formats - are referenced. BloodHound/AzureHound and
> ROADtools are explicitly out of scope. Everything stays read-only and offline.

## Layout

```
scripts/
  Invoke-CapVisualizer.ps1     # entry point (export → enrich → report → analysis → visual → delta)
  Test-Prerequisites.ps1       # environment / connectivity doctor
  Compare-CapSnapshot.ps1      # diff two existing snapshots
  Register-CapSchedule.ps1     # local cron / Task Scheduler helper
  Get-CapUserScope.ps1         # per-user policy scope (offline)
  Invoke-CapWhatIf.ps1         # simulate one sign-in (offline)
  Invoke-CapAnalyze.ps1        # gap permutation (offline)
  Invoke-CapTest.ps1           # assertion engine, CI exit codes
  modules/
    CapCommon.psm1             # auth, Graph paging, throttling, hashing, name resolution
    CapExport.psm1             # fetch CA policies + dependencies + directory enrichment
    CapNormalize.psm1          # canonical policy shape (the analysis gate)
    CapReport.psm1             # JSON/CSV reports + hygiene checks + summary
    CapScope.psm1              # per-user scope resolution
    CapWhatIf.psm1             # offline what-if evaluation
    CapAnalyze.psm1            # gap / bypass permutation
    CapAudit.psm1              # contradiction & exemption audit
    CapFindings.psm1           # risk-scored findings model
    CapCompliance.psm1         # CISA SCuBA baseline evaluation
    CapTest.psm1               # assertion engine (JUnit/SARIF/JSON)
    CapVisual.psm1             # render self-contained offline HTML
    CapDelta.psm1              # snapshot comparison engine
assets/                        # HTML template + inlined CSS/JS (offline)
  reference/                   # app groupings, privileged roles, baselines, assertions
arm/                           # OPTIONAL, opt-in Azure scheduling (not local)
docs/                          # USAGE, PERMISSIONS, SCOPE, WHATIF, ANALYZE, AUDIT, FINDINGS, COMPLIANCE, TESTING, DELTA, SCHEDULING, SECURITY
samples/                       # sanitized sample export + offline self-test
```

## Requirements

- [PowerShell 7+](https://learn.microsoft.com/powershell/scripting/install/installing-powershell)
- `Microsoft.Graph.Authentication` module (`Install-Module Microsoft.Graph.Authentication -Scope CurrentUser`)
- An Entra account (or app registration) that can **read** CA policies.

## Try it without a tenant

Render the viewer and reports from bundled sample data (no sign-in):

```bash
pwsh ./samples/Test-Offline.ps1
# open samples/sample-visual.html
```

## Security & privacy

See [docs/SECURITY.md](docs/SECURITY.md) and [DISCLAIMER.md](DISCLAIMER.md).
Output can contain sensitive configuration; `output/` is git-ignored.

## Optional cloud scheduling

A fully-local schedule is the default. If you specifically want the run to
happen **in Azure** (leaving the local-only model), an opt-in ARM/Bicep template
is provided in [`arm/`](arm/README.md):

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fyurykissin%2FCAPVisualizer%2Fmain%2Farm%2Fazuredeploy.json)

## License

[MIT](LICENSE). Not affiliated with or endorsed by Microsoft.
