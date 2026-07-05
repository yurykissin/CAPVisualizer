# Scheduling periodic runs

Unattended scheduled runs require **app-based auth** (interactive sign-in cannot
run without a human). Register an app with the **application** permission
`Policy.Read.All` and use certificate auth. See [PERMISSIONS.md](PERMISSIONS.md).

## Local scheduling helper

`Register-CapSchedule.ps1` generates the right entry for your OS.

### macOS / Linux (cron)

Preview the crontab line:

```bash
pwsh ./scripts/Register-CapSchedule.ps1 \
  -TenantId contoso.onmicrosoft.com \
  -ClientId <app-client-id> \
  -CertificateThumbprint <cert-thumbprint> \
  -Time 03:00
```

Install it:

```bash
pwsh ./scripts/Register-CapSchedule.ps1 -TenantId ... -ClientId ... -CertificateThumbprint ... -Apply
```

This adds a daily `crontab` line that runs the exporter with `-Delta` and logs
to `output/cron.log`.

### Windows (Task Scheduler)

```powershell
pwsh .\scripts\Register-CapSchedule.ps1 `
  -TenantId contoso.onmicrosoft.com `
  -ClientId <app-client-id> `
  -CertificateThumbprint <cert-thumbprint> `
  -Time 03:00 -Apply
```

Registers a daily Scheduled Task named `CAPVisualizer-Daily`.

## Manual scheduling

You can also wire the exporter into any scheduler yourself. The command to run:

```
pwsh -NoProfile -File <repo>/scripts/Invoke-CapVisualizer.ps1 \
  -TenantId <tenant> -ClientId <appId> -CertificateThumbprint <thumb> -Delta -NoTranscript
```

## Optional cloud path (leaves the local-only model)

If you specifically want the run to happen in Azure rather than on a local
machine, an **opt-in** ARM/Bicep template is provided under [`../arm/`](../arm).
It provisions an Azure Automation Account with a managed identity and a daily
runbook. **This is not local** - the run executes in Azure and results live in
Azure. Use it only if that trade-off is acceptable. See `arm/README.md`.
