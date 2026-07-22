# Disclaimer

Please read this before running **CAPVisualizer**.

## Read-only by design
CAPVisualizer **only reads** from your Microsoft Entra tenant. It performs **no
writes** of any kind - no create, update, or delete calls are made against
Conditional Access policies or any other object. It cannot change your tenant's
configuration or security posture.

## Runs entirely locally
All Microsoft Graph calls are made directly from the machine you run the tool on
to **your own tenant's** Graph endpoint. CAPVisualizer does **not** send your
data to any third party, does not phone home, and does not require any hosted
service. The generated HTML visualization bundles its assets locally and does
**not** load anything from the internet (no CDN), so it works fully offline.

## Sensitive output
The reports, raw exports, and visualizations produced by CAPVisualizer can
contain **sensitive tenant configuration** (policy targeting, excluded accounts,
named locations, break-glass accounts, object identifiers). Treat the `output/`
directory as sensitive:

- `output/` is excluded from git by default (see `.gitignore`).
- Store, share, and dispose of exports according to your organization's data
  handling policy.
- Use the `-Redact` option if you need to share reports outside your tenant.

## No warranty
This software is provided **"as is"**, without warranty of any kind, express or
implied. See [LICENSE](LICENSE) (MIT). You are responsible for reviewing the
code and validating its behavior before running it against a production tenant.

## Not affiliated with Microsoft
CAPVisualizer is an independent, community project. It is **not** affiliated
with, endorsed by, or sponsored by Microsoft. "Microsoft", "Entra", "Azure",
and "Microsoft Graph" are trademarks of the Microsoft group of companies.

## Independent implementation & third-party names
CAPVisualizer's analysis engines were authored **independently**. No source
code, algorithm, or configuration is copied from any third-party tool. Only
publicly documented behaviour and open standards are referenced - CISA SCuBA
control identifiers (`MS.AAD.*`), NIST 800-53 controls, MITRE ATT&CK technique
IDs, and the JUnit and SARIF output formats. Any other tool names that appear in
the documentation for comparison only (for example CAPSlock/SpecterOps, noCAP,
EntraFalcon, ScubaGear/CISA, and Maester) are the trademarks or property of
their respective owners; CAPVisualizer is not affiliated with, endorsed by, or
derived from any of them.

## References & attributions
CAPVisualizer scores your configuration against, and cites, publicly available
security standards. These may be used freely in commercial and client-facing
deliverables under the licenses noted below. Citing an identifier is a reference
only and does **not** imply that the issuing body endorses CAPVisualizer, its
output, or any assessment produced with it.

| Standard | Used for | License / status | Attribution |
| --- | --- | --- | --- |
| **CISA SCuBA** Secure Configuration Baselines (`MS.AAD.*`) and **ScubaGear** | The Compliance tab and finding references | US Government work; the [`cisagov/ScubaGear`](https://github.com/cisagov/ScubaGear) repository is dedicated to the public domain under **Creative Commons Zero v1.0 (CC0-1.0)** | No attribution required; not endorsed by CISA |
| **NIST SP 800-53** controls (e.g. `AC-2(3)`) | Finding references | US Government publication — **public domain** | No attribution required |
| **MITRE ATT&CK®** technique IDs (e.g. `T1078.004`) | Finding references | Free to use under MITRE's Terms of Use, which **request attribution** | "© The MITRE Corporation. ATT&CK® — https://attack.mitre.org" |
| **JUnit** and **SARIF** output formats | Assertion-engine output | Open, publicly documented schemas | No attribution required |

When incorporating CAPVisualizer output into a report, the recommended practice
is to (a) describe the assessment as being *against* the CISA SCuBA `MS.AAD`
baseline rather than as an official CISA assessment, and (b) include the MITRE
ATT&CK attribution line above wherever ATT&CK content is reproduced. The
generated HTML viewer already carries these attributions in its footer.

Standard **names and marks** (CISA, SCuBA, ScubaGear, NIST, MITRE ATT&CK®) belong
to their respective owners and are referenced descriptively only; they are not
used in CAPVisualizer's own name or branding.

## Least privilege
CAPVisualizer is designed to run with the **lowest practical permissions**. The
core export requires only the read-only `Policy.Read.All` Microsoft Graph scope.
Optional friendly-name resolution requires additional read-only directory
scopes and is **off by default**. See [docs/PERMISSIONS.md](docs/PERMISSIONS.md).
