#Requires -Version 7.0
<#
.SYNOPSIS
    Configures the Function App with Entra ID and Azure resource settings.

.DESCRIPTION
    Updates Function App settings with:
    - ZSP group IDs
    - Backup service principal object ID
    - Key Vault and Storage resource IDs
    - Log Analytics configuration
    - Max access duration

.PARAMETER FunctionAppName
    Name of the Function App.

.PARAMETER ResourceGroupName
    Name of the resource group containing the Function App.

.PARAMETER IntuneAdminGroupId
    Object ID of the Intune Admins ZSP group.

.PARAMETER SecurityReaderGroupId
    Object ID of the Security Reader ZSP group.

.PARAMETER BackupSpObjectId
    Object ID of the backup service principal.

.PARAMETER AllowedAdminUserIds
    Comma-separated Entra user object IDs allowed to request human admin access.

.PARAMETER KeyVaultResourceId
    Resource ID of the Key Vault.

.PARAMETER StorageResourceId
    Resource ID of the Storage Account.

.PARAMETER LogAnalyticsWorkspaceId
    Customer ID of the Log Analytics workspace.

.PARAMETER DcrEndpoint
    Data Collection Endpoint URL.

.PARAMETER DceResourceId
    Exact deployed Data Collection Endpoint ARM resource ID for endpoint verification.

.PARAMETER DcrRuleId
    Data Collection Rule immutable ID (dcr-...).

.PARAMETER MaxAccessDurationMinutes
    Maximum access duration in minutes.

.PARAMETER BackupJobSchedule
    NCRONTAB schedule for backup job timer trigger. Default: '0 55 1 * * *' (1:55 AM daily).

.PARAMETER BackupJobDurationMinutes
    Duration in minutes for backup job access grants. Default: 35.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$FunctionAppName,

    [Parameter(Mandatory)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory)]
    [string]$IntuneAdminGroupId,

    [Parameter(Mandatory)]
    [string]$SecurityReaderGroupId,

    [Parameter(Mandatory)]
    [string]$BackupSpObjectId,

    [Parameter(Mandatory)]
    [string]$AllowedAdminUserIds,

    [Parameter(Mandatory)]
    [string]$KeyVaultResourceId,

    [Parameter(Mandatory)]
    [string]$StorageResourceId,

    [Parameter(Mandatory)]
    [string]$LogAnalyticsWorkspaceId,

    [Parameter(Mandatory)]
    [string]$DcrEndpoint,

    [Parameter(Mandatory)]
    [string]$DceResourceId,

    [Parameter(Mandatory)]
    [string]$DcrRuleId,

    [Parameter(Mandatory)]
    [int]$MaxAccessDurationMinutes,

    [Parameter()]
    [string]$BackupJobSchedule = '0 55 1 * * *',

    [Parameter()]
    [int]$BackupJobDurationMinutes = 35
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
. "$PSScriptRoot/Credential-Destinations.ps1"
$DcrEndpoint = Get-VerifiedIngestionEndpoint -Endpoint $DcrEndpoint `
    -DceResourceId $DceResourceId -ResourceGroupName $ResourceGroupName -RuleId $DcrRuleId

Write-Host "Configuring Function App settings..." -ForegroundColor Yellow

# Build settings array
$settings = @(
    "INTUNE_ADMIN_GROUP_ID=$IntuneAdminGroupId"
    "SECURITY_READER_GROUP_ID=$SecurityReaderGroupId"
    "ALLOWED_ADMIN_GROUP_IDS=$IntuneAdminGroupId,$SecurityReaderGroupId"
    "ALLOWED_ADMIN_USER_IDS=$AllowedAdminUserIds"
    "BACKUP_SP_OBJECT_ID=$BackupSpObjectId"
    "KEYVAULT_RESOURCE_ID=$KeyVaultResourceId"
    "STORAGE_RESOURCE_ID=$StorageResourceId"
    "LOG_ANALYTICS_WORKSPACE_ID=$LogAnalyticsWorkspaceId"
    "DCR_ENDPOINT=$DcrEndpoint"
    "DCR_RULE_ID=$DcrRuleId"
    "MAX_ACCESS_DURATION_MINUTES=$MaxAccessDurationMinutes"
    "BACKUP_JOB_SCHEDULE=$BackupJobSchedule"
    "BACKUP_JOB_DURATION_MINUTES=$BackupJobDurationMinutes"
)

# Update Function App settings
Write-Host "  Updating app settings..." -ForegroundColor Cyan
az functionapp config appsettings set `
    --name $FunctionAppName `
    --resource-group $ResourceGroupName `
    --settings $settings `
    --output none 2>$null

if ($LASTEXITCODE -ne 0) {
    throw "Failed to update Function App settings"
}

Write-Host "  Settings configured:" -ForegroundColor Green
foreach ($setting in $settings) {
    $key = ($setting -split '=')[0]
    Write-Host "    - $key" -ForegroundColor Gray
}

Write-Host "Function App configured successfully" -ForegroundColor Green
exit 0
