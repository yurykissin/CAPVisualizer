# Security & privacy notes

## Read-only
CAPVisualizer only issues read operations against Microsoft Graph. It never
creates, updates, or deletes anything in your tenant. The single POST it can
make is the read-only `directoryObjects/getByIds` name lookup, used only when
you pass `-ResolveNames`.

## Local execution, no third parties
All Graph calls go directly from your machine to your tenant's Graph endpoint.
The tool does not send data anywhere else, has no telemetry, and does not phone
home. The generated HTML bundles all CSS/JS inline and loads **nothing** from
the internet (no CDN), so it renders fully offline.

## Sensitive output
Snapshots under `output/` can contain sensitive configuration: policy targeting,
excluded/break-glass accounts, named locations, and object identifiers.

- `output/` is git-ignored by default.
- Treat exports as sensitive data per your organization's policy.
- Use `-Redact` to replace the tenant id and object GUIDs with stable
  pseudonyms before sharing a report externally.

## Credential handling
- **Interactive** auth uses the Microsoft.Graph token cache; CAPVisualizer does
  not persist tokens itself.
- **App auth** prefers a **certificate** (referenced by thumbprint) over a
  client secret. If you must use a secret, pass it as a `SecureString`
  (`-ClientSecret`) and never hard-code it. Do not commit secrets, `.pfx`,
  `.cer`, or `.key` files - they are git-ignored by default.
- The run transcript (`transcript.txt`) captures console output, not tokens.
  Use `-NoTranscript` if you prefer no transcript.

## Integrity
Each snapshot includes `manifest.json` with a SHA-256 hash of every output file,
so you can verify outputs were not tampered with after generation.

## Verify before you trust
This is a community project provided without warranty. Review the source before
running it against a production tenant. It requests only the read scopes listed
in [PERMISSIONS.md](PERMISSIONS.md); if prompted for anything more, stop.
