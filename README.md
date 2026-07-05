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
- **Delta reports** so periodic runs show exactly what changed since last time.

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
Full options in [docs/USAGE.md](docs/USAGE.md).

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
  raw/export.json          # verbatim Graph data (source of truth for diffs)
  report/policies.json     # enriched, analysis-ready
  report/policies.csv      # one flattened row per policy
  report/findings.json/csv # hygiene / gap findings
  report/summary.json      # counts and overview
  delta/delta.json         # when -Delta and a baseline exist
  visual/index.html        # self-contained offline viewer
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

## Layout

```
scripts/
  Invoke-CapVisualizer.ps1     # entry point (export → report → visual → delta)
  Test-Prerequisites.ps1       # environment / connectivity doctor
  Compare-CapSnapshot.ps1      # diff two existing snapshots
  Register-CapSchedule.ps1     # local cron / Task Scheduler helper
  modules/
    CapCommon.psm1             # auth, Graph paging, throttling, hashing, name resolution
    CapExport.psm1             # fetch CA policies + dependencies
    CapReport.psm1             # JSON/CSV reports + hygiene checks + summary
    CapVisual.psm1             # render self-contained offline HTML
    CapDelta.psm1              # snapshot comparison engine
assets/                        # HTML template + inlined CSS/JS (offline)
arm/                           # OPTIONAL, opt-in Azure scheduling (not local)
docs/                          # USAGE, PERMISSIONS, DELTA, SCHEDULING, SECURITY
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
