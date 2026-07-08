# Gap analysis (`Invoke-CapAnalyze.ps1`)

Offline gap-permutation engine. Given a **principal** and a **target resource**,
it enumerates combinations of the sign-in signals that the in-scope Conditional
Access policies actually gate on, runs each combination through the offline
what-if engine, and reports the scenarios that reach the resource with **no
enforced block or MFA** - i.e. coverage gaps and bypass paths.

Everything runs against an exported JSON snapshot (`-FromJson`); no tenant
access is required and results are fully reproducible offline.

## Why

Manually reasoning about "which combination of client app, network, risk and
device state slips through my policy set?" is error-prone. This engine does it
exhaustively over the signals that matter for the specific principal + resource,
so the search stays bounded but complete.

## How it works

1. **Relevant signals only.** For the principal, every policy that is in scope
   (not excluded) contributes the signals it gates on. `ClientApp` is always
   included because legacy authentication is a classic bypass axis. Signals no
   in-scope policy references are not permuted.
2. **Bounded cartesian product.** Each signal has two representative values
   (e.g. `browser` / `exchangeActiveSync`, `none` / `high`, `trusted` /
   `untrusted`). `-MaxScenarios` (default 512) caps the total.
3. **Per-scenario evaluation.** Each combination is scored by `Test-CapWhatIf`.
   A scenario is *protected* when the cumulative outcome is a block or MFA.
4. **Gap classification.** Unprotected scenarios are reported as:
   - `legacy-auth-bypass` - a legacy client reaches the resource unblocked,
   - `report-only-only` - the only applicable protective policy is report-only,
   - `no-enforcement` - reachable with no enforced control.
5. **By-design filter.** A gap that only occurs on a **trusted** network, whose
   untrusted twin *is* protected, is flagged `byDesign` so intentional
   trusted-network relaxations don't drown out actionable findings.

## Usage

```powershell
./scripts/Invoke-CapAnalyze.ps1 `
    -FromJson ./samples/sample-export-enriched.json `
    -PrincipalId 77777777-7777-7777-7777-777777777777 `
    -Resource   00000002-0000-0ff1-ce00-000000000000
```

Options:

| Parameter          | Purpose                                                     |
| ------------------ | ----------------------------------------------------------- |
| `-MaxScenarios`    | Cap on evaluated combinations (default 512).                |
| `-IncludeByDesign` | Also list trusted-network (by-design) gaps.                 |
| `-Jsonl`           | Emit one compact JSON object per gap (for diffing/ingest).  |

## Output

Console summary lists the dimensions permuted, the scenario count, and each
actionable gap with its signal signature and reason. `-Jsonl` emits streamable
records:

```json
{"principalId":"2222...","resource":"0000...","signals":{"ClientApp":"browser","UserRisk":"none"},"gapType":"report-only-only","byDesign":false,"blocked":false,"mfaRequired":false,"reason":"Only report-only policies would apply - no enforcement"}
```

## Independence

Authored independently against the public Entra Conditional Access evaluation
model. No third-party tool code or logic is reused.
