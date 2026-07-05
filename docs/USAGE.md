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
Output lands in a timestamped folder under `output/`.

### Useful switches

| Switch | Effect |
|--------|--------|
| `-SkipResolveNames` | Do **not** resolve names; show GUIDs and request only `Policy.Read.All`. |
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
