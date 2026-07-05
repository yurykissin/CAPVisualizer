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
By default sign-in uses the **device-code flow**: the terminal prints a
copy/paste sign-in URL (`https://microsoft.com/devicelogin`) and a one-time code,
and the browser is opened automatically. Add `-UseWebBrowser` for the classic
system-browser (SSO) flow instead. Output lands in a timestamped folder under
`output/`.

### Useful switches

| Switch | Effect |
|--------|--------|
| `-SkipResolveNames` | Do **not** resolve names; show GUIDs and request only `Policy.Read.All`. |
| `-UseWebBrowser` | Use the classic system-browser sign-in instead of the default device-code flow. |
| `-FromJson <path>` | Offline render mode: build reports + HTML from an existing JSON file, no sign-in, no network. |
| `-Delta` | Compare against the most recent previous snapshot. |
| `-BaselinePath <folder>` | Use a specific snapshot as the delta baseline. |
| `-Redact` | Replace tenant id and object GUIDs with stable pseudonyms (safe to share). |
| `-NoVisual` | Skip HTML generation (JSON/CSV only). |
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
  raw/export.json          # verbatim Graph data (source of truth for diffs)
  report/policies.json     # enriched, analysis-ready
  report/policies.csv      # one row per policy (flattened)
  report/findings.json/csv # hygiene / gap findings
  report/summary.json      # counts and overview
  delta/delta.json         # only when -Delta and a baseline exists
  visual/index.html        # self-contained offline viewer (open in a browser)
  manifest.json            # SHA-256 of every output file
  transcript.txt           # run log (unless -NoTranscript)
```

Open `visual/index.html` in any browser - it works fully offline.

## 5. Compare two arbitrary snapshots

```bash
pwsh ./scripts/Compare-CapSnapshot.ps1 \
  -BaselinePath output/20260101-090000 \
  -CurrentPath  output/20260201-090000
```

See [DELTA.md](DELTA.md) for details.
