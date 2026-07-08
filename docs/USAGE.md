# Usage

All commands run locally with PowerShell 7 (`pwsh`). Nothing is uploaded.

## 1. Check prerequisites

```bash
pwsh ./scripts/Test-Prerequisites.ps1            # environment checks
pwsh ./scripts/Test-Prerequisites.ps1 -Install   # also install the Graph auth module for the current user
pwsh ./scripts/Test-Prerequisites.ps1 -TestConnection   # interactive read-only sign-in probe
```

If the module is missing:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

## 2. Run an export (interactive)

```bash
pwsh ./scripts/Invoke-CapVisualizer.ps1
```

You'll be prompted to sign in and consent to read-only `Policy.Read.All` **and
`Directory.Read.All`** (the latter is used to turn GUIDs into display names).
By default sign-in uses the **system-browser authorization-code flow** (PKCE):
a single, SSO-aware browser prompt - the Microsoft-recommended interactive flow.
For headless / SSH sessions with no local browser, add `-UseDeviceCode` to fall
back to the device-code flow (prints a copy/paste URL + one-time code); note that
device-code flow is more phishing-prone, so use it only when necessary. Output
lands in a timestamped folder under `output/`.

### Useful switches

| Switch | Effect |
|--------|--------|
| `-SkipResolveNames` | Do **not** resolve names; show GUIDs and request only `Policy.Read.All`. |
| `-UseDeviceCode` | Use the device-code flow (headless / SSH, no browser) instead of the default system-browser sign-in. |
| `-FromJson <path>` | Offline render mode: build reports + HTML from an existing JSON file, no sign-in, no network. |
| `-Delta` | Compare against the most recent previous snapshot. |
| `-BaselinePath <folder>` | Use a specific snapshot as the delta baseline. |
| `-Redact` | Replace tenant id and object GUIDs with stable pseudonyms (safe to share). |
| `-SkipAnalysis` | Skip the offline analysis engines (audit / findings / compliance / tests); export + report + visual only. |
| `-AssertionPath <path>` | Use a custom JSON assertion pack for the built-in test engine (default: bundled starter pack). |
| `-NoVisual` | Skip HTML generation (JSON/CSV only). |
| `-NoOpen` | Do not auto-open the HTML report in the browser when the run finishes (it opens by default on interactive runs). |
| `-NoTranscript` | Do not write a PowerShell transcript into the snapshot. |
| `-OutputRoot <path>` | Change the output root (default `./output`). |

Example (minimal permissions, GUIDs only):

```bash
pwsh ./scripts/Invoke-CapVisualizer.ps1 -SkipResolveNames -Delta
```

## 2b. Render from existing JSON (fully offline, zero permissions)

If you (or a colleague) cannot grant Graph consent, you can still generate the
full report and HTML from a JSON file you already have - no sign-in, no network:

```bash
pwsh ./scripts/Invoke-CapVisualizer.ps1 -FromJson ./path/to/policies.json
```

`-FromJson` accepts any of:

- A **CAPVisualizer** `export.json` (or a whole snapshot folder). If it was
  produced with name resolution, the embedded `nameMap` is reused so names still
  show - completely offline.
- A **raw Microsoft Graph** response, either a `{ "value": [ ... ] }` object or a
  bare array of policy objects. For example, export it yourself with:

  ```powershell
  (Invoke-MgGraphRequest GET 'v1.0/identity/conditionalAccess/policies').value |
    ConvertTo-Json -Depth 30 | Out-File policies.json
  ```

  Names will show as GUIDs (except well-known Microsoft apps) unless the JSON
  carries a `nameMap`. Everything else - conditions, controls, session controls,
  CSV/JSON reports and the interactive HTML - is produced exactly as in a live run.

## 3. Run unattended (app registration)

For scheduled/unattended runs, register an app with **application**
`Policy.Read.All` (add `Directory.Read.All` for name resolution) and use
certificate auth:

```bash
pwsh ./scripts/Invoke-CapVisualizer.ps1 \
  -TenantId contoso.onmicrosoft.com \
  -ClientId <app-client-id> \
  -CertificateThumbprint <cert-thumbprint> \
  -Delta -NoTranscript
```

Client-secret auth is also supported (`-ClientSecret`), but a certificate is
recommended.

## 4. Open the results

Each run produces:

```
output/<yyyyMMdd-HHmmss>/
  raw/export.json          # verbatim Graph data + directory enrichment (source of truth for diffs)
  report/policies.json     # enriched, analysis-ready
  report/policies.csv      # one row per policy (flattened)
  report/findings.json/csv # hygiene / gap findings
  report/summary.json      # counts and overview
  analysis/audit.json      # contradictions + exemption exposure
  analysis/findings.json   # risk-scored findings (impact x likelihood)
  analysis/compliance.json # CISA SCuBA (MS.AAD.*) control results
  analysis/tests.json      # assertion results (+ tests.junit.xml / tests.sarif.json)
  delta/delta.json         # only when -Delta and a baseline exists
  visual/index.html        # self-contained offline viewer (open in a browser)
  manifest.json            # SHA-256 of every output file
  transcript.txt           # run log (unless -NoTranscript)
```

Open `visual/index.html` in any browser - it works fully offline. The
`analysis/` folder is omitted when you pass `-SkipAnalysis`.

## 5. Run an individual analysis engine (offline)

Each analysis engine is also a standalone script that runs against an existing
export (or snapshot) with **no sign-in and no network**:

```bash
# Which policies actually target a principal (direct / via group or role / excluded)?
pwsh ./scripts/Get-CapUserScope.ps1 -FromJson ./export.json -PrincipalId <object-id>

# Simulate one sign-in (definitive vs signal-dependent outcome).
pwsh ./scripts/Invoke-CapWhatIf.ps1 -FromJson ./export.json -PrincipalId <object-id> \
  -Resource <app-id> -ClientApp browser

# Permute unspecified signals to surface bypasses / no-enforcement paths.
pwsh ./scripts/Invoke-CapAnalyze.ps1 -FromJson ./export.json

# Run a declarative assertion pack; exit code 0 = pass, 1 = failure (CI-friendly).
pwsh ./scripts/Invoke-CapTest.ps1 -FromJson ./export.json \
  -AssertionPath ./my-assertions.json -JUnitPath ./results.xml -SarifPath ./results.sarif.json
```

See [SCOPE.md](SCOPE.md), [WHATIF.md](WHATIF.md), [ANALYZE.md](ANALYZE.md),
[AUDIT.md](AUDIT.md), [FINDINGS.md](FINDINGS.md), [COMPLIANCE.md](COMPLIANCE.md),
and [TESTING.md](TESTING.md) for each engine.

## 6. Compare two arbitrary snapshots

```bash
pwsh ./scripts/Compare-CapSnapshot.ps1 \
  -BaselinePath output/20260101-090000 \
  -CurrentPath  output/20260201-090000
```

See [DELTA.md](DELTA.md) for details.
