// Zero Standing Privilege Lab - Core Infrastructure
// Deploys: Resource Group, Key Vault, Storage Account

targetScope = 'resourceGroup'

@description('Project name for resource naming')
param projectName string

@description('Azure region')
param location string

// Retained for deployment-input compatibility; no standing data-plane role is created.
@description('Legacy deployer input; no Key Vault Administrator grant is created')
#disable-next-line no-unused-params
param deployerPrincipalId string

@description('Tags for all resources')
param tags object = {}

// Generate unique suffix to ensure globally unique resource names
var uniqueSuffix = uniqueString(resourceGroup().id)

// Merge default tags with provided tags
var resourceTags = union({
  project: projectName
  environment: 'lab'
  purpose: 'zero-standing-privilege-demo'
}, tags)

// Key Vault - Target resource for NHI demo
resource keyVault 'Microsoft.KeyVault/vaults@2026-02-01' = {
  name: take('${projectName}-kv${uniqueSuffix}', 24)
  location: location
  tags: resourceTags
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
  }
}

// Demo secret in Key Vault
resource demoSecret 'Microsoft.KeyVault/vaults/secrets@2026-02-01' = {
  parent: keyVault
  name: 'demo-secret'
  properties: {
    value: 'Demo target for time-bound backup access; other authorized administrators may still have access'
  }
}

// Storage Account - Target resource for NHI demo
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: take('${replace(projectName, '-', '')}sa${uniqueSuffix}', 24)
  location: location
  tags: resourceTags
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    supportsHttpsTrafficOnly: true
  }
}

// Blob service
resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-01-01' = {
  parent: storageAccount
  name: 'default'
}

// Backup container
resource backupContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  parent: blobService
  name: 'backups'
  properties: {
    publicAccess: 'None'
  }
}

// Outputs
output keyVaultId string = keyVault.id
output keyVaultName string = keyVault.name
output keyVaultUri string = keyVault.properties.vaultUri
output storageAccountId string = storageAccount.id
output storageAccountName string = storageAccount.name
