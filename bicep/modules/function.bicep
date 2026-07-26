// Zero Standing Privilege Lab - Function App Infrastructure
// Deploys: Function App (Flex Consumption), Storage Account, App Insights

targetScope = 'resourceGroup'

@description('Project name for resource naming')
param projectName string

@description('Azure region')
param location string

@description('Log Analytics Workspace ID for App Insights')
param logAnalyticsWorkspaceId string

@description('Tags for all resources')
param tags object = {}

// Generate unique suffix to ensure globally unique resource names
var uniqueSuffix = uniqueString(resourceGroup().id)

// Merge default tags
var resourceTags = union({
  project: projectName
  environment: 'lab'
  purpose: 'zero-standing-privilege-demo'
}, tags)

// Storage account for Function App (Flex Consumption requires blob containers)
resource functionStorage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: take('${replace(projectName, '-', '')}fn${uniqueSuffix}', 24)
  location: location
  tags: resourceTags
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    supportsHttpsTrafficOnly: true
  }
}

// Blob service for Flex Consumption
resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-01-01' = {
  parent: functionStorage
  name: 'default'
}

// Deployment container for Flex Consumption
resource deploymentContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  parent: blobService
  name: 'deployments'
  properties: {
    publicAccess: 'None'
  }
}

// Flex Consumption App Service Plan
resource appServicePlan 'Microsoft.Web/serverfarms@2024-04-01' = {
  name: '${projectName}-plan'
  location: location
  tags: resourceTags
  sku: {
    name: 'FC1'
    tier: 'FlexConsumption'
  }
  kind: 'functionapp'
  properties: {
    reserved: true // Required for Linux
  }
}

// Application Insights
resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: '${projectName}-insights'
  location: location
  tags: resourceTags
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalyticsWorkspaceId
  }
}

// Function App with Flex Consumption
resource functionApp 'Microsoft.Web/sites@2024-04-01' = {
  name: '${projectName}-gw-${uniqueSuffix}'
  location: location
  tags: resourceTags
  kind: 'functionapp,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    functionAppConfig: {
      deployment: {
        storage: {
          type: 'blobContainer'
          value: '${functionStorage.properties.primaryEndpoints.blob}deployments'
          authentication: {
            type: 'StorageAccountConnectionString'
            storageAccountConnectionStringName: 'DEPLOYMENT_STORAGE_CONNECTION_STRING'
          }
        }
      }
      scaleAndConcurrency: {
        maximumInstanceCount: 40
        instanceMemoryMB: 2048
      }
      runtime: {
        name: 'python'
        version: '3.11'
      }
    }
    siteConfig: {
      appSettings: [
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${functionStorage.name};EndpointSuffix=${environment().suffixes.storage};AccountKey=${functionStorage.listKeys().keys[0].value}'
        }
        {
          name: 'DEPLOYMENT_STORAGE_CONNECTION_STRING'
          value: 'DefaultEndpointsProtocol=https;AccountName=${functionStorage.name};EndpointSuffix=${environment().suffixes.storage};AccountKey=${functionStorage.listKeys().keys[0].value}'
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: appInsights.properties.ConnectionString
        }
        {
          name: 'TENANT_ID'
          value: subscription().tenantId
        }
      ]
    }
  }
  dependsOn: [
    deploymentContainer
  ]
}

// Outputs
output functionAppId string = functionApp.id
output functionAppName string = functionApp.name
output functionAppUrl string = 'https://${functionApp.properties.defaultHostName}'
output functionAppPrincipalId string = functionApp.identity.principalId
