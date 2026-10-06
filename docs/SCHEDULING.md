# Scheduling periodic runs

Unattended scheduled runs require **app-based auth** because interactive sign-in
cannot run without a human. Before using this guide, create the app registration,
grant and admin-consent the required Microsoft Graph **Application**
permissions, upload the certificate's public key, and install its private key
for the operating-system account that will run the schedule. CAPVisualizer does
not provision those prerequisites.

Follow [APP-AUTH.md](APP-AUTH.md) to create the app and certificate, and use
[PERMISSIONS.md](PERMISSIONS.md) to select the permissions for policy-only or
full-analysis collection.

## Local scheduling helper

`Register-CapSchedule.ps1` generates the right entry for your OS.

### macOS / Linux (cron)

Preview the crontab line:

```bash
pwsh ./scripts/Register-CapSchedule.ps1 \
  -TenantId contoso.onmicrosoft.com \
  -ClientId 11111111-2222-3333-4444-555555555555 \
  -CertificatePath /secure/capvisualizer.pfx \
  -Time 03:00
```

Install it:

```bash
pwsh ./scripts/Register-CapSchedule.ps1 \
  -TenantId contoso.onmicrosoft.com \
  -ClientId 11111111-2222-3333-4444-555555555555 \
  -CertificatePath /secure/capvisualizer.pfx \
  -Time 03:00 -Apply
```

This adds one marked `# CAPVisualizer-Daily` crontab line. It runs through
`Invoke-CapScheduledRun.ps1`, which prevents overlapping runs and rejects a PFX
readable by group or other users, then logs to `output/cron.log`.

### Windows (Task Scheduler)

```powershell
pwsh .\scripts\Register-CapSchedule.ps1 `
  -TenantId contoso.onmicrosoft.com `
  -ClientId 11111111-2222-3333-4444-555555555555 `
  -CertificateThumbprint A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 `
  -Time 03:00 -Apply
```

Registers a daily Scheduled Task named `CAPVisualizer-Daily` under the identity
running the registration command and configures duplicate triggers to
`IgnoreNew`. The default registration is appropriate only when that identity's
logon type and certificate store remain available. For a service account, gMSA,
or a task that must run while the user is logged off, create the task under that
identity using your organization's credential-management process and verify it
while signed in as that identity.

## Manual scheduling

You can also wire the exporter into any scheduler yourself. The command to run:

```bash
pwsh -NoProfile -File /opt/CAPVisualizer/scripts/Invoke-CapScheduledRun.ps1 \
  -TenantId contoso.onmicrosoft.com \
  -ClientId 11111111-2222-3333-4444-555555555555 \
  -CertificatePath /secure/capvisualizer.pfx
```

The scheduled identity must own or have access to the certificate's private
key. On Windows, a certificate installed only for your interactive user is not
automatically available to another Scheduled Task identity. On macOS/Linux,
restrict the PFX to the cron identity with mode `600`.

The scheduler wrapper keeps an exclusive lock at `output/.capvisualizer.lock`.
The file may remain on disk, but the operating-system lock is released on
process exit; a concurrent trigger fails before authentication instead of
writing into the same run window.

## Snapshot retention

Preview snapshots older than 90 days:

```bash
pwsh ./scripts/Remove-CapSnapshot.ps1 -RetainDays 90
```

After reviewing the exact paths, delete them:

```bash
pwsh ./scripts/Remove-CapSnapshot.ps1 -RetainDays 90 -Apply
```

The script accepts both legacy `yyyyMMdd-HHmmss` and current
`yyyyMMdd-HHmmss-fff[-suffix]` directories directly beneath the resolved output
root, never follows links, and is a dry run unless `-Apply` is specified. Add it
as a separate scheduled command only after choosing and documenting an
appropriate retention period.
