# Scheduling periodic runs

Unattended scheduled runs require **app-based auth** because interactive sign-in
cannot run without a human. Before using this guide, create the app registration,
grant and admin-consent the required Microsoft Graph **Application**
permissions, upload the certificate's public key, and install its private key
for the operating-system account that will run the schedule. CAPVisualizer does
not provision those prerequisites.

Start with [USAGE.md#3-run-unattended-app-registration](USAGE.md#3-run-unattended-app-registration)
for the checklist, and use [PERMISSIONS.md](PERMISSIONS.md) to select the
permissions for policy-only or full-analysis collection.

## Local scheduling helper

`Register-CapSchedule.ps1` generates the right entry for your OS.

### macOS / Linux (cron)

Preview the crontab line:

```bash
pwsh ./scripts/Register-CapSchedule.ps1 \
  -TenantId contoso.onmicrosoft.com \
  -ClientId 11111111-2222-3333-4444-555555555555 \
  -CertificateThumbprint A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 \
  -Time 03:00
```

Install it:

```bash
pwsh ./scripts/Register-CapSchedule.ps1 \
  -TenantId contoso.onmicrosoft.com \
  -ClientId 11111111-2222-3333-4444-555555555555 \
  -CertificateThumbprint A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 \
  -Time 03:00 -Apply
```

This adds a daily `crontab` line that runs the exporter with `-Delta` and logs
to `output/cron.log`.

### Windows (Task Scheduler)

```powershell
pwsh .\scripts\Register-CapSchedule.ps1 `
  -TenantId contoso.onmicrosoft.com `
  -ClientId 11111111-2222-3333-4444-555555555555 `
  -CertificateThumbprint A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 `
  -Time 03:00 -Apply
```

Registers a daily Scheduled Task named `CAPVisualizer-Daily`.

## Manual scheduling

You can also wire the exporter into any scheduler yourself. The command to run:

```bash
pwsh -NoProfile -File /opt/CAPVisualizer/scripts/Invoke-CapVisualizer.ps1 \
  -TenantId contoso.onmicrosoft.com \
  -ClientId 11111111-2222-3333-4444-555555555555 \
  -CertificateThumbprint A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 \
  -Delta -NoTranscript
```
