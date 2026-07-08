# Compliance baseline (CapCompliance)

Evaluates the normalized policy set against an independently authored baseline
pack mapped to public **CISA SCuBA** Microsoft Entra ID control identifiers
(`MS.AAD.*`), with NIST 800-53 and MITRE ATT&CK references. Runs automatically as
part of `Invoke-CapVisualizer.ps1` (`analysis/compliance.json`) and drives the
viewer's **Compliance** tab.

## Controls (CA subset)

| Control     | Statement                                          | Criticality |
| ----------- | -------------------------------------------------- | ----------- |
| MS.AAD.1.1  | Legacy authentication SHALL be blocked.            | SHALL       |
| MS.AAD.2.1  | High-risk users SHALL be blocked.                  | SHALL       |
| MS.AAD.2.3  | High-risk sign-ins SHALL be blocked.               | SHALL       |
| MS.AAD.3.1  | Phishing-resistant MFA SHALL be enforced (all users). | SHALL    |
| MS.AAD.3.2  | MFA SHOULD be enforced for all users.              | SHOULD      |

## Result model

Per control: `{ id, statement, criticality, result, rationale, evidence[],
nist[], mitre[] }` where `result` is `pass` / `fail` / `manual`. Evidence lists
the policies that satisfy the control. The summary reports pass/fail counts and a
pass rate over automatable controls.

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
