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

## Least privilege
CAPVisualizer is designed to run with the **lowest practical permissions**. The
core export requires only the read-only `Policy.Read.All` Microsoft Graph scope.
Optional friendly-name resolution requires additional read-only directory
scopes and is **off by default**. See [docs/PERMISSIONS.md](docs/PERMISSIONS.md).
