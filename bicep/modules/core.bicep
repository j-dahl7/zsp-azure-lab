// Zero Standing Privilege Lab - Core Infrastructure
// Deploys: Resource Group, Key Vault, Storage Account

targetScope = 'resourceGroup'

@description('Project name for resource naming')
param projectName string

@description('Azure region')
param location string

@description('Deployer principal ID for Key Vault admin access')
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
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
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

// Grant deployer Key Vault Administrator role
resource deployerKvAdmin 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, deployerPrincipalId, 'Key Vault Administrator')
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '00482a5a-887f-4fb3-b363-3b7fe8e74483') // Key Vault Administrator
    principalId: deployerPrincipalId
    principalType: 'User'
  }
}

// Demo secret in Key Vault
resource demoSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'demo-secret'
  properties: {
    value: 'This secret should only be accessible during backup window'
  }
  dependsOn: [
    deployerKvAdmin
  ]
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
