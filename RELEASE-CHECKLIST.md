# Release checklist

- [ ] `VERSION` and changelogs describe the release.
- [ ] Pester 5.7.1 passes on Windows, macOS, and Linux.
- [ ] Current Pester passes locally.
- [ ] Offline smoke test and JavaScript syntax check pass.
- [ ] Markdown links and comment-based help pass.
- [ ] Safe export contains only classified analysis and passes leak checks.
- [ ] `Test-CapManifest.ps1` accepts an unchanged snapshot and rejects changes.
- [ ] `Test-CapBaselineCurrency.ps1` reports no SCuBA control drift.
- [ ] No tenant output, dictionaries, transcripts, PFX files, or secrets are tracked.
- [ ] Release notes identify the export schema, safe-bundle schema, and baseline version.
