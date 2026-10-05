# Security & privacy notes

## Read-only
CAPVisualizer only issues read operations against Microsoft Graph. It never
creates, updates, or deletes anything in your tenant. The single POST it can
make is the read-only `directoryObjects/getByIds` name lookup, used as part of
default name resolution (disabled with `-SkipResolveNames`).

## Local execution, no third parties
All Graph calls go directly from your machine to your tenant's Graph endpoint.
The tool does not send data anywhere else, has no telemetry, and does not phone
home. The generated HTML bundles all CSS/JS inline and loads **nothing** from
the internet (no CDN), so it renders fully offline.

## Sensitive output
Snapshots under `output/` can contain sensitive configuration: policy targeting,
excluded/break-glass accounts, named locations, and object identifiers.

- `output/` is git-ignored by default.
- Store snapshots on encrypted storage. Full-disk encryption protects data at
  rest when the machine or disk is lost; it does not replace OS access control.
- Define a retention period appropriate to the tenant and customer. Do not mix
  exports from different customers in a shared directory with broad access.
- Preview expiry with `scripts/Remove-CapSnapshot.ps1 -RetainDays 90`, then use
  `-Apply` only after reviewing the listed paths. The script limits deletion to
  timestamped direct children of the resolved output root.
- Treat exports as sensitive data per your organization's policy.
- **Names are split out.** Each run writes a name-free `raw/export.json` plus a
  local-only `raw/names.json` dictionary. `manifest.json` flags every file with
  `containsNames`, so you can tell at a glance what must stay on the machine.
- **`containsNames = false` does not mean "safe to share."** `raw/export.json`
  carries no display names, but it still contains every object GUID and the
  tenant id in the clear, and the tenant id maps directly to your organization.
  The only artifacts intended to leave the machine are the ones produced by
  **Export safely** or `Export-CapSafeBundle.ps1`, which build an allowlisted
  review artifact and alias those ids. The command-line bundle adds a
  fail-closed file-level leak test.
- Run `scripts/Export-CapSafeBundle.ps1` to assemble a `safe/` folder for
  sharing. It pseudonymizes tenant-specific GUIDs, then **fails closed** - if
  any name, unallowlisted GUID or IP-shaped string survives, the bundle is
  deleted and the run throws.
- Use `scripts/Restore-CapNames.ps1` to map a reviewer's output back to real
  names locally. It refuses a dictionary from a different snapshot.
- `-Redact` is deprecated: it only pseudonymized GUIDs (names survived) and its
  map was discarded, making it one-way. It now behaves as `-Pseudonymize`.
- **Anonymization reduces attribution, not exploitability.** A masked export is
  still a map of where your gaps are. Full detail and the residual-risk
  statement: [SAFEEXPORT.md](SAFEEXPORT.md).

## Credential handling
- **Interactive** auth uses the Microsoft.Graph token cache; CAPVisualizer does
  not persist tokens itself.
- **App auth** prefers a **certificate** (referenced by thumbprint) over a
  client secret. If you must use a secret, pass it as a `SecureString`
  (`-ClientSecret`) and never hard-code it. Do not commit secrets, `.pfx`,
  `.cer`, or `.key` files - they are git-ignored by default.
- Install the certificate and private key for the actual scheduler identity,
  not only the interactive administrator. See [APP-AUTH.md](APP-AUTH.md).
- The run transcript (`transcript.txt`) captures console output, not tokens.
  Use `-NoTranscript` if you prefer no transcript.

## Integrity
Each snapshot includes `manifest.json` with a SHA-256 hash of every output file,
which detects accidental modification and incomplete copies. The plain manifest
is not a signature: someone who deliberately changes a file can regenerate its
hash. For tamper evidence, either record the printed manifest hash outside the
snapshot or run with a prompted SecureString key to add a keyed HMAC:

```powershell
$key = Read-Host 'Manifest HMAC key' -AsSecureString
./scripts/Invoke-CapVisualizer.ps1 -ManifestKey $key
```

Verify hashes, missing or unexpected files, and any HMAC before trusting a
snapshot:

```powershell
./scripts/Test-CapManifest.ps1 -SnapshotPath ./output/<timestamp>
```

Add `-ExpectedManifestHash <sha256>` to compare the out-of-band anchor, and pass
the same SecureString as `-ManifestKey` when the manifest contains an HMAC.

## Verify before you trust
This is a community project provided without warranty. Review the source before
running it against a production tenant. It requests only the read scopes listed
in [PERMISSIONS.md](PERMISSIONS.md); if prompted for anything more, stop.
