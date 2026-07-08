# Compliance baseline (CapCompliance)

Evaluates the normalized policy set against an independently authored baseline
pack mapped to public **CISA SCuBA** Microsoft Entra ID control identifiers
(`MS.AAD.*`), with NIST 800-53 and MITRE ATT&CK references. Runs automatically as
part of `Invoke-CapVisualizer.ps1` (`analysis/compliance.json`) and drives the
viewer's **Compliance** tab.

## Controls (full MS.AAD baseline)

The pack enumerates the **entire** public CISA SCuBA MS.AAD baseline (34
controls), not only the Conditional Access subset, so the report reflects every
recommended control. Each control carries a `scope`:

- `conditional-access` - evaluated automatically from the read-only CA export
  (result `pass` / `fail`).
- any other scope (`identity-protection`, `auth-methods`, `app-management`,
  `privileged-access`, `external-collaboration`, `logging`, `password-policy`) -
  the setting lives outside Conditional Access, so it is reported as `manual`
  with official guidance on where to verify it.

Conditional-Access-automatable controls:

| Control     | Statement                                                      | Criticality |
| ----------- | -------------------------------------------------------------- | ----------- |
| MS.AAD.1.1  | Legacy authentication SHALL be blocked.                        | SHALL       |
| MS.AAD.2.1  | Users detected as high risk SHALL be blocked.                  | SHALL       |
| MS.AAD.2.3  | Sign-ins detected as high risk SHALL be blocked.               | SHALL       |
| MS.AAD.3.1  | Phishing-resistant MFA SHALL be enforced for all users.        | SHALL       |
| MS.AAD.3.2  | An alternative MFA method SHALL be enforced for all users.     | SHALL       |
| MS.AAD.3.6  | Phishing-resistant MFA SHALL be required for privileged roles. | SHALL       |
| MS.AAD.3.7  | Managed devices SHOULD be required for authentication.         | SHOULD      |
| MS.AAD.3.9  | Device code authentication SHOULD be blocked.                  | SHOULD      |
| MS.AAD.9.1  | Risky AI agents SHALL be blocked.                              | SHALL       |

The remaining controls (MS.AAD.2.2, 3.3-3.5, 3.8, 4.1, 5.x, 6.1, 7.x, 8.x) are
reported as `manual` with guidance, since they are configured outside
Conditional Access.

## Result model

Per control: `{ id, statement, criticality, scope, result, rationale,
evidence[], nist[], mitre[] }` where `result` is `pass` / `fail` / `manual`.
Evidence lists the policies that satisfy the control. The summary reports
pass/fail/manual counts, the number of `automatable` controls, and a pass rate
computed over the automatable (Conditional Access) controls only.

## Versioned pack, minimal code coupling

The baseline lives in
`assets/reference/baselines/cisa-scuba-aad.json` and supplies each control's text,
criticality, and standards references. Evaluation predicates live in
`CapCompliance.psm1` keyed by `checkId`, so a new control that reuses an existing
check can be added to the pack **without code changes**. The pack is versioned
(`baselineVersion`) so baselines can evolve independently.

## Independence

Control identifiers, NIST controls, and MITRE technique IDs are public
references. The baseline pack and all evaluation logic are authored
independently; no third-party tool code or logic is reused.
