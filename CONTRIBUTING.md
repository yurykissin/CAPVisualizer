# Contributing

CAPVisualizer is a read-only security assessment tool. Changes must preserve
least privilege, offline repeatability, and the separation between local tenant
data and shareable safe-review artifacts.

## Before opening a pull request

1. Keep changes focused and update directly affected documentation.
2. Add or update Pester tests for behavior changes.
3. Run:

   ```powershell
   Invoke-Pester -Path ./tests
   ./samples/Test-Offline.ps1
   ./scripts/Test-MarkdownLinks.ps1
   node --check ./assets/app.js
   ```

4. For export-schema changes, update `CHANGELOG-EXPORT.md`. For analysis or
   viewer changes, update `CHANGELOG-REPORT.md`.
5. Never commit tenant exports, name dictionaries, transcripts, certificates,
   secrets, or screenshots containing customer data.

Security vulnerabilities should be reported privately as described in
[`.github/SECURITY.md`](.github/SECURITY.md), not in a public issue.
