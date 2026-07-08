# Assertion / test engine (`Invoke-CapTest.ps1`)

A declarative, CI-friendly assertion runner. You express expectations about your
Conditional Access posture in a JSON pack; the engine evaluates them against an
export, writes machine-readable results (JUnit / SARIF / JSON), and exits
non-zero on failure - so it can gate a pipeline. It is an **independent DSL**,
not Pester.

## Assertion types

- **compliance** - a baseline control must have an expected result.
  `{ type:"compliance", control:"MS.AAD.1.1", expect:"pass" }`
- **findingThreshold** - the finding set must not contain more than N findings at
  or above a severity.
  `{ type:"findingThreshold", disallowSeverity:"critical", maxCount:0 }`
- **whatif** - a simulated sign-in must yield an expected outcome.
  `{ type:"whatif", principalId:"...", resource:"...", signals:{ ClientApp:"browser" }, expect:{ mfaRequired:true } }`

The engine lazily computes the compliance, findings, and what-if results it needs
from a single export, so one snapshot drives the whole gate offline.

## Usage

```powershell
./scripts/Invoke-CapTest.ps1 `
    -FromJson ./export.json `
    -AssertionPath ./my-assertions.json `
    -JUnitPath ./results.xml -SarifPath ./results.sarif.json
# exit code 0 = all passed, 1 = at least one failed/errored
```

A starter pack ships at
`assets/reference/assertions/starter-assertions.json`. When you run the main
`Invoke-CapVisualizer.ps1`, the same engine runs automatically and writes
`analysis/tests.json`, `analysis/tests.junit.xml`, and
`analysis/tests.sarif.json`; pass `-AssertionPath` to use your own pack.

## Output formats

- **JUnit XML** - for test-result dashboards; failures and errors become
  `<failure>` elements.
- **SARIF 2.1.0** - for code-scanning surfaces; each failing assertion is an
  `error`-level result.
- **JSON** - the full structured result.

## Independence

The assertion DSL, evaluators, and output writers are authored independently. No
third-party tool code or logic is reused.
