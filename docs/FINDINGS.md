# Risk-scored findings (CapFindings)

A uniform, sortable finding model with a deterministic risk score. Runs
automatically as part of `Invoke-CapVisualizer.ps1` (`analysis/findings.json`)
and drives the viewer's **Findings** tab.

## Schema

Each finding:

```
{ id, checkId, title, severity, impact, likelihood, riskScore,
  description, threat, remediation, affectedObjects[], references[] }
```

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
  privileged account (last sign-in older than the threshold, default 90 days).
- **Policy state** - enabled policy with no controls; grant policy with neither
  strong auth nor device compliance; critical (block / MFA / device) policy left
  disabled or report-only.
- **Promoted audit issues** - every contradiction/exemption issue from
  [AUDIT.md](AUDIT.md), mapped into this schema with impact/likelihood and
  standards references.

## References

`references[]` cite public standards only - MITRE ATT&CK technique IDs, CISA
SCuBA `MS.AAD.*` control IDs, and NIST 800-53 controls. They are references, not
third-party tool code.

## Independence

Authored independently. The scoring model, thresholds, and check logic are
original. No third-party tool code or logic is reused.
