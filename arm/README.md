# Optional cloud scheduling (opt-in)

> **This path is not local.** The default CAPVisualizer model runs entirely on
> your machine and shares nothing online. This ARM/Bicep template intentionally
> moves the scheduled run **into Azure** (Azure Automation). The export executes
> in Azure and its results live in Azure, not on your machine. Use it only if
> that trade-off is acceptable. For a fully-local schedule, use
> `scripts/Register-CapSchedule.ps1` instead (see `docs/SCHEDULING.md`).

## What the template provisions

This template is a **scaffold only**. It creates:

- An **Azure Automation Account** with a **system-assigned managed identity**.
- An empty **daily schedule** (`CAPVisualizer-Daily`).

It does **not** import a runbook, grant any Graph permission, import the Graph
module, or link anything to the schedule. Deploying it produces no runs until
you complete the [required manual steps](#required-manual-steps-after-deployment).

## Deploy

> [!WARNING]
> Deploying this template alone does **nothing useful**. It only provisions an
> empty Automation Account and an empty daily schedule. There are **no runs, no
> credentials, and no output** until you complete the
> [required manual steps](#required-manual-steps-after-deployment) below. Those
> steps (Graph permission grant + admin consent, module import, runbook import,
> schedule link) are **not optional** for a working setup.

Portal (Deploy to Azure):

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fyurykissin%2FCAPVisualizer%2Fmain%2Farm%2Fazuredeploy.json)

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

> [!IMPORTANT]
> **All four steps below are required.** The template deploys only the account
> and the schedule; without these the schedule fires against nothing and the
> managed identity cannot read any policy. They are kept manual on purpose,
> because granting `Policy.Read.All` application permission with admin consent is
> a privileged action that should not be baked into a public template.

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
