// CAPVisualizer - OPTIONAL cloud scheduling path.
//
// This is opt-in and INTENTIONALLY leaves the "everything runs locally" model:
// it provisions an Azure Automation Account that runs the export in Azure on a
// schedule. Results live in Azure, not on your machine. Use only if that
// trade-off is acceptable. The local scheduler (scripts/Register-CapSchedule.ps1)
// is the default, fully-local option.
//
// After deployment you must still:
//   1. Grant the Automation Account's system-assigned managed identity the
//      Microsoft Graph APPLICATION permission Policy.Read.All (admin consent).
//   2. Import the Microsoft.Graph.Authentication module into the Automation
//      Account (Shared Resources > Modules).
//   3. Import scripts/Invoke-CapVisualizer.ps1 (adapted for Automation, using
//      Connect-MgGraph -Identity) as a PowerShell 7.2 runbook and link it to the
//      created schedule.
// See arm/README.md for full step-by-step guidance.

@description('Azure region for the Automation Account.')
param location string = resourceGroup().location

@description('Name of the Automation Account to create.')
param automationAccountName string = 'capvisualizer-auto'

@description('Name of the daily schedule.')
param scheduleName string = 'CAPVisualizer-Daily'

@description('First run time (ISO 8601). Must be at least 5 minutes in the future at deploy time. Defaults to 10 minutes after deployment; the schedule then repeats daily at that time. Override for a specific daily run time.')
param scheduleStart string = dateTimeAdd(utcNow(), 'PT10M')

resource automation 'Microsoft.Automation/automationAccounts@2023-11-01' = {
  name: automationAccountName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    sku: {
      name: 'Free'
    }
    publicNetworkAccess: true
  }
}

resource schedule 'Microsoft.Automation/automationAccounts/schedules@2023-11-01' = {
  parent: automation
  name: scheduleName
  properties: {
    description: 'Daily read-only Conditional Access export (CAPVisualizer).'
    startTime: scheduleStart
    frequency: 'Day'
    interval: 1
    timeZone: 'UTC'
  }
}

output automationAccountName string = automation.name
output managedIdentityPrincipalId string = automation.identity.principalId
output nextSteps string = 'Grant the printed principalId the Graph app role Policy.Read.All, import Microsoft.Graph.Authentication, and link a runbook to the schedule. See arm/README.md.'
