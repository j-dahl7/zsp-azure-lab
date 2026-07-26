// Zero Standing Privilege Lab - compile-time parameter example only.
// Do not deploy this file directly; scripts/Deploy-Azure.ps1 generates and
// verifies the real ownership UUID before invoking Bicep.

using './main.bicep'

// Required: Deployer's Entra ID object ID (az ad signed-in-user show --query id -o tsv)
param deployerPrincipalId = ''

// Project naming (must be lowercase alphanumeric with hyphens, 3-20 chars)
param projectName = 'zsp-lab'

// Azure region
param location = 'eastus'

// Maximum access duration in minutes (5-1440)
param maxAccessDurationMinutes = 480

// Required ownership inputs. Use scripts/Deploy-Azure.ps1 so these values are
// generated, persisted, and verified before a deployment mutates Azure.
param ownerMarker = 'nine-lives-zsp:azure:v1'
param deploymentId = '00000000-0000-0000-0000-000000000000'

// Optional: Additional tags
param tags = {
  owner: ''
  costCenter: ''
}
