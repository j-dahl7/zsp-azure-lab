// Zero Standing Privilege Lab - Main Orchestrator
// Deploys all Azure infrastructure for ZSP Gateway
//
// Deployment entry point: scripts/Deploy-Azure.ps1
// Do not invoke this template directly. The wrapper performs the manifest and
// live-tag ownership preflight that an ARM upsert cannot enforce by itself.
//
// Note: Entra ID objects (groups, service principals, permissions) are created
// separately via PowerShell scripts due to Azure/Entra timing dependencies.

targetScope = 'subscription'

@description('Project name used for resource naming (lowercase alphanumeric with hyphens)')
@minLength(3)
@maxLength(20)
param projectName string = 'zsp-lab'

@description('Azure region for all resources')
param location string = 'eastus'

@description('Maximum duration for any access grant (minutes)')
@minValue(5)
@maxValue(1440)
param maxAccessDurationMinutes int = 480

@description('Principal ID of the deployer (for Key Vault admin access)')
param deployerPrincipalId string

@description('Additional tags for all resources')
param tags object = {}

@description('Stable lab owner marker recorded in the deployment manifest and Azure tags')
@minLength(1)
param ownerMarker string

@description('Unique deployment identifier recorded in the deployment manifest and Azure tags')
@minLength(36)
@maxLength(36)
param deploymentId string

var ownershipTags = {
  'nlzt-owner': ownerMarker
  'nlzt-deployment': deploymentId
}

// Ownership tags are applied last so caller-provided tags cannot replace them.
var effectiveTags = union(tags, ownershipTags)

// Resource Group
resource resourceGroup 'Microsoft.Resources/resourceGroups@2023-07-01' = {
  name: '${projectName}-rg'
  location: location
  tags: union({
    project: projectName
    environment: 'lab'
    purpose: 'zero-standing-privilege-demo'
  }, effectiveTags)
}

// Monitoring Module - Deploy first as other modules depend on Log Analytics
module monitoring 'modules/monitoring.bicep' = {
  name: 'monitoring-deployment'
  scope: resourceGroup
  params: {
    projectName: projectName
    location: location
    tags: effectiveTags
  }
}

// Core Module - Key Vault, Storage Account
module core 'modules/core.bicep' = {
  name: 'core-deployment'
  scope: resourceGroup
  params: {
    projectName: projectName
    location: location
    deployerPrincipalId: deployerPrincipalId
    tags: effectiveTags
  }
}

// Function Module - Function App, App Service Plan, App Insights
module function 'modules/function.bicep' = {
  name: 'function-deployment'
  scope: resourceGroup
  params: {
    projectName: projectName
    location: location
    logAnalyticsWorkspaceId: monitoring.outputs.logAnalyticsWorkspaceId
    tags: effectiveTags
  }
}

// Outputs for PowerShell scripts
output resourceGroupName string = resourceGroup.name
output resourceGroupId string = resourceGroup.id

// Core outputs
output keyVaultId string = core.outputs.keyVaultId
output keyVaultName string = core.outputs.keyVaultName
output storageAccountId string = core.outputs.storageAccountId
output storageAccountName string = core.outputs.storageAccountName

// Function outputs
output functionAppId string = function.outputs.functionAppId
output functionAppName string = function.outputs.functionAppName
output functionAppUrl string = function.outputs.functionAppUrl
output functionAppPrincipalId string = function.outputs.functionAppPrincipalId

// Monitoring outputs
output logAnalyticsWorkspaceId string = monitoring.outputs.logAnalyticsWorkspaceId
output logAnalyticsWorkspaceCustomerId string = monitoring.outputs.logAnalyticsWorkspaceCustomerId
output dataCollectionEndpointUrl string = monitoring.outputs.dataCollectionEndpointUrl

// Configuration values for Function App (set via Configure-Function.ps1)
output maxAccessDurationMinutes int = maxAccessDurationMinutes
output tenantId string = subscription().tenantId
output subscriptionId string = subscription().subscriptionId
