# Risk-scored findings (CapFindings)

A uniform, sortable finding model with a deterministic risk score. Runs
automatically as part of `Invoke-CapVisualizer.ps1` (`analysis/findings.json`)
and drives the viewer's **Findings** tab.

## Schema

Each finding:

```
{ id, checkId, title, severity, impact, likelihood, riskScore,
  description, summary, logic, threat, remediation, affectedObjects[], references[] }
```

- **`description`** - the specific, per-object detail (e.g. *"Alice holds Global
  Administrator but has not signed in for 214 day(s)"*).
- **`summary`** - a generic, object-independent one-line description of the
  finding type. The viewer shows this when many objects share one finding (so a
  collapsed *"x29"* row still explains itself), while the per-object detail stays
  in the **Affected** column.
- **`logic`** - the exact detection rule ("how detected"): the condition that
  caused this finding to fire. Rendered in the viewer as *How detected* so a
  reviewer never has to reverse-engineer why a finding appears.
- **`threat`** - why it matters (the risk if left unaddressed). Rendered as
  *Why it matters*.
- **`remediation`** - the fix. **`references`** - public standards (see below).

## Scoring model

`riskScore = impact x likelihood`, each on a 1-5 scale (max 25). Severity is
derived from the score so ordering is objective and reproducible:

| Risk score | Severity |
| ---------- | -------- |
| 20-25      | critical |
| 12-19      | high     |
| 6-11       | medium   |
| 1-5        | low      |

`impact` reflects how damaging the exposure is (e.g. a privileged account exempt
from protection scores 5); `likelihood` reflects how readily it is reached or
abused (e.g. an all-users MFA policy makes a missing-MFA-capability finding more
likely to bite).

## Checks

- **Directory** - ownerless group used as a CA exclusion; user not MFA-capable
  (weighted higher if privileged or if an all-users MFA policy applies); inactive
  privileged account (last sign-in older than the threshold, default 30 days);
  disabled privileged account (an account that still holds a privileged directory
  role while `accountEnabled = false`, leaving a dormant grant that can be
  reactivated).
- **Policy state** - enabled policy with no controls; grant policy with neither
  strong auth nor device compliance; critical (block / MFA / device) policy left
  disabled or report-only; device code / authentication-transfer flow not blocked
  tenant-wide.
- **Promoted audit issues** - every contradiction/exemption issue from
  [AUDIT.md](AUDIT.md), mapped into this schema with impact/likelihood and
  standards references.

The inactivity threshold is configurable via `-InactiveDays` (default 30).

## Every finding is self-explaining

Each finding carries both **why it matters** (`threat`) and **how it was
detected** (`logic`) in addition to the description and remediation, so the
report can be read without cross-referencing the source. Findings that affect
many objects collapse into a single row (`x<n>`) that still shows the generic
`summary` and lists the affected objects in a dedicated column.

## References

`references[]` cite public standards only - MITRE ATT&CK technique IDs, CISA
SCuBA `MS.AAD.*` control IDs, and NIST 800-53 controls. They are references, not
third-party tool code.

## Independence

Authored independently. The scoring model, thresholds, and check logic are
original. No third-party tool code or logic is reused.
