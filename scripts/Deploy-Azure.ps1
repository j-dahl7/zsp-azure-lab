#Requires -Version 7.0
<#
.SYNOPSIS
    Deploys Azure infrastructure using Bicep templates.

.DESCRIPTION
    Deploys the following Azure resources:
    - Resource Group
    - Key Vault with RBAC authorization
    - Storage Account with backup container
    - Function App (Linux, Python 3.11)
    - App Service Plan (Flex Consumption)
    - Application Insights
    - Log Analytics Workspace
    - Data Collection Endpoint

.PARAMETER ProjectName
    Project name for resource naming.

.PARAMETER Location
    Azure region for deployment.

.PARAMETER MaxAccessDurationMinutes
    Maximum access duration configuration.

.PARAMETER DeployerPrincipalId
    Object ID of the deployer for Key Vault admin access.

.OUTPUTS
    Key=Value pairs for use by other scripts:
    - RESOURCE_GROUP_NAME
    - RESOURCE_GROUP_ID
    - FUNCTION_APP_NAME
    - FUNCTION_APP_URL
    - FUNCTION_APP_PRINCIPAL_ID
    - KEYVAULT_ID
    - KEYVAULT_NAME
    - STORAGE_ACCOUNT_ID
    - LOG_ANALYTICS_WORKSPACE_CUSTOMER_ID
    - DCR_ENDPOINT_URL
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ProjectName,

    [Parameter(Mandatory)]
    [string]$Location,

    [Parameter(Mandatory)]
    [int]$MaxAccessDurationMinutes,

    [Parameter(Mandatory)]
    [string]$DeployerPrincipalId
)

$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BicepDir = Join-Path (Split-Path -Parent $ScriptDir) "bicep"

Write-Host "Deploying Azure resources..." -ForegroundColor Yellow

# Deploy at subscription scope
$deploymentName = "zsp-lab-$(Get-Date -Format 'yyyyMMddHHmmss')"

$deployment = az deployment sub create `
    --name $deploymentName `
    --location $Location `
    --template-file "$BicepDir/main.bicep" `
    --parameters projectName=$ProjectName `
    --parameters location=$Location `
    --parameters maxAccessDurationMinutes=$MaxAccessDurationMinutes `
    --parameters deployerPrincipalId=$DeployerPrincipalId `
    --output json 2>$null

if ($LASTEXITCODE -ne 0) {
    Write-Error "Bicep deployment failed"
    exit 1
}

$result = $deployment | ConvertFrom-Json

if ($result.properties.provisioningState -ne 'Succeeded') {
    Write-Error "Deployment failed with state: $($result.properties.provisioningState)"
    exit 1
}

$outputs = $result.properties.outputs

# Output configuration for other scripts
Write-Output "RESOURCE_GROUP_NAME=$($outputs.resourceGroupName.value)"
Write-Output "RESOURCE_GROUP_ID=$($outputs.resourceGroupId.value)"
Write-Output "FUNCTION_APP_NAME=$($outputs.functionAppName.value)"
Write-Output "FUNCTION_APP_URL=$($outputs.functionAppUrl.value)"
Write-Output "FUNCTION_APP_PRINCIPAL_ID=$($outputs.functionAppPrincipalId.value)"
Write-Output "KEYVAULT_ID=$($outputs.keyVaultId.value)"
Write-Output "KEYVAULT_NAME=$($outputs.keyVaultName.value)"
Write-Output "STORAGE_ACCOUNT_ID=$($outputs.storageAccountId.value)"
Write-Output "STORAGE_ACCOUNT_NAME=$($outputs.storageAccountName.value)"
Write-Output "LOG_ANALYTICS_WORKSPACE_ID=$($outputs.logAnalyticsWorkspaceId.value)"
Write-Output "LOG_ANALYTICS_WORKSPACE_CUSTOMER_ID=$($outputs.logAnalyticsWorkspaceCustomerId.value)"
Write-Output "DCR_ENDPOINT_URL=$($outputs.dataCollectionEndpointUrl.value)"
Write-Output "TENANT_ID=$($outputs.tenantId.value)"
Write-Output "SUBSCRIPTION_ID=$($outputs.subscriptionId.value)"
Write-Output "MAX_ACCESS_DURATION_MINUTES=$($outputs.maxAccessDurationMinutes.value)"

Write-Host "Azure resources deployed successfully" -ForegroundColor Green
exit 0
