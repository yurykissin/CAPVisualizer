# Optional cloud scheduling (opt-in)

> **This path is not local.** The default CAPVisualizer model runs entirely on
> your machine and shares nothing online. This ARM/Bicep template intentionally
> moves the scheduled run **into Azure** (Azure Automation). The export executes
> in Azure and its results live in Azure, not on your machine. Use it only if
> that trade-off is acceptable. For a fully-local schedule, use
> `scripts/Register-CapSchedule.ps1` instead (see `docs/SCHEDULING.md`).

## What the template provisions

- An **Azure Automation Account** with a **system-assigned managed identity**.
- A **daily schedule** (`CAPVisualizer-Daily`).

## Deploy

Portal: use the **Deploy to Azure** button in the top-level `README.md` (it
points at `arm/azuredeploy.json`).

CLI:

```bash
az deployment group create \
  --resource-group <rg> \
  --template-file arm/azuredeploy.json \
  --parameters @arm/azuredeploy.parameters.json
```

`azuredeploy.json` is compiled from `azuredeploy.bicep`. If you edit the Bicep,
recompile:

```bash
az bicep build --file arm/azuredeploy.bicep
```

## Required manual steps after deployment

The template deploys the account and schedule, but for security these steps are
deliberately manual:

1. **Grant Graph permission to the managed identity.** Take the
   `managedIdentityPrincipalId` output and grant it the Microsoft Graph
   **application** app role `Policy.Read.All` (and optionally `Directory.Read.All`
   for name resolution), then admin-consent. Example with Microsoft Graph
   PowerShell:

   ```powershell
   $mi = Get-MgServicePrincipal -ServicePrincipalId <managedIdentityPrincipalId>
   $graph = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
   $role = $graph.AppRoles | Where-Object { $_.Value -eq 'Policy.Read.All' }
   New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $mi.Id `
     -PrincipalId $mi.Id -ResourceId $graph.Id -AppRoleId $role.Id
   ```

2. **Import the Graph auth module.** In the Automation Account >
   *Shared Resources* > *Modules*, import `Microsoft.Graph.Authentication`
   (runtime PowerShell 7.2).

3. **Create the runbook.** Import an Automation-adapted copy of
   `scripts/Invoke-CapVisualizer.ps1` as a **PowerShell 7.2** runbook. In
   Automation, authenticate with the managed identity:

   ```powershell
   Connect-MgGraph -Identity
   ```

   and write outputs to an Azure resource you control (e.g. a Storage account or
   Log Analytics), since there is no local filesystem to keep.

4. **Link the runbook to the schedule** `CAPVisualizer-Daily`.

## Cost / cleanup

The Automation Account uses the **Free** SKU. Delete the resource group to
remove everything when you are done.
