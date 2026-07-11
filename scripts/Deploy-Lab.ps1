#Requires -Version 7.0
<#
.SYNOPSIS
    Deploys the Zero Standing Privilege lab infrastructure.

.DESCRIPTION
    Main orchestrator script that deploys:
    1. Azure resources via Bicep (Resource Group, Key Vault, Storage, Function App, Log Analytics, DCE)
    2. Entra ID objects (ZSP groups, service principals, directory roles)
    3. ZSPAudit_CL custom table and Data Collection Rule (DCR)
    4. Graph API permissions and RBAC roles for the Function App managed identity
    5. Function App configuration with Entra object IDs, DCR endpoint, and schedule
    6. Function App code deployment
    7. Smoke test

.PARAMETER ProjectName
    Project name for resource naming. Lowercase alphanumeric with hyphens, 3-20 chars.

.PARAMETER Location
    Azure region for deployment. Default: eastus

.PARAMETER MaxAccessDurationMinutes
    Maximum duration for any access grant. Default: 480 (8 hours)

.PARAMETER SkipFunctionDeploy
    Skip deploying Function App code (useful for re-running after code changes)

.PARAMETER SkipTest
    Skip running the smoke test after deployment

.PARAMETER ExpectedIntuneAdminGroupId
    Existing Intune Admins group object ID from the original deployment. For a
    rerun, provide this together with all other Expected*ObjectId parameters.

.PARAMETER ExpectedSecurityReaderGroupId
    Existing Security Reader group object ID from the original deployment.

.PARAMETER ExpectedBackupAppObjectId
    Existing backup application registration object ID (not its client ID).

.PARAMETER ExpectedBackupSpObjectId
    Existing backup service principal object ID.

.EXAMPLE
    ./Deploy-Lab.ps1
    Deploys with default settings (zsp-lab in eastus)

.EXAMPLE
    ./Deploy-Lab.ps1 -ProjectName "my-zsp" -Location "westus2"
    Deploys with custom project name and region

.EXAMPLE
    ./Deploy-Lab.ps1 -ProjectName "my-zsp" `
      -ExpectedIntuneAdminGroupId "<OBJECT_ID>" `
      -ExpectedSecurityReaderGroupId "<OBJECT_ID>" `
      -ExpectedBackupAppObjectId "<OBJECT_ID>" `
      -ExpectedBackupSpObjectId "<OBJECT_ID>"
    Safely reruns against the exact Entra objects from the original deployment.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidatePattern('^[a-z0-9-]+$')]
    [ValidateLength(3, 20)]
    [string]$ProjectName = 'zsp-lab',

    [Parameter()]
    [string]$Location = 'eastus',

    [Parameter()]
    [ValidateRange(5, 1440)]
    [int]$MaxAccessDurationMinutes = 480,

    [Parameter()]
    [switch]$SkipFunctionDeploy,

    [Parameter()]
    [switch]$SkipTest,

    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$ExpectedIntuneAdminGroupId,

    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$ExpectedSecurityReaderGroupId,

    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$ExpectedBackupAppObjectId,

    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$ExpectedBackupSpObjectId
)

$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Helper: Write JSON to temp file for cross-platform az rest compatibility
# Avoids PS 7.0-7.2 Windows bug where double quotes are stripped from native command args
$script:_jsonTempFiles = @()
function New-JsonBodyFile {
    param([Parameter(Mandatory)][string]$Json)
    $f = (New-TemporaryFile).FullName
    [System.IO.File]::WriteAllText($f, $Json, [System.Text.Encoding]::UTF8)
    $script:_jsonTempFiles += $f
    return "@$f"
}
$LabRoot = Split-Path -Parent $ScriptDir

Write-Host "`n=== Zero Standing Privilege Lab Deployment ===" -ForegroundColor Cyan
Write-Host "Project: $ProjectName"
Write-Host "Location: $Location"
Write-Host "Max Duration: $MaxAccessDurationMinutes minutes"
Write-Host ""

# Verify prerequisites
Write-Host "Checking prerequisites..." -ForegroundColor Yellow
$azVersion = az version --output json 2>$null | ConvertFrom-Json
if (-not $azVersion) {
    throw "Azure CLI not found. Install from https://aka.ms/installazurecli"
}
Write-Host "  Azure CLI: $($azVersion.'azure-cli')" -ForegroundColor Green

# Check logged in
$account = az account show --output json 2>$null | ConvertFrom-Json
if (-not $account) {
    throw "Not logged in to Azure. Run 'az login' first."
}
Write-Host "  Subscription: $($account.name)" -ForegroundColor Green
Write-Host "  Tenant: $($account.tenantId)" -ForegroundColor Green

# Get deployer principal ID
$deployerPrincipalId = az ad signed-in-user show --query id -o tsv 2>$null
if (-not $deployerPrincipalId) {
    throw "Could not get signed-in user. Ensure you're logged in with 'az login'."
}
Write-Host "  Deployer: $deployerPrincipalId" -ForegroundColor Green

Write-Host ""

# Step 1: Deploy Azure Resources
Write-Host "Step 1/7: Deploying Azure resources (Bicep)..." -ForegroundColor Cyan
$deploymentOutput = & "$ScriptDir/Deploy-Azure.ps1" `
    -ProjectName $ProjectName `
    -Location $Location `
    -MaxAccessDurationMinutes $MaxAccessDurationMinutes `
    -DeployerPrincipalId $deployerPrincipalId

if ($LASTEXITCODE -ne 0) {
    throw "Azure deployment failed"
}

# Parse deployment outputs
$outputs = $deploymentOutput | Where-Object { $_ -match '^[A-Z_]+=' }
$config = @{}
foreach ($line in $outputs) {
    $parts = $line -split '=', 2
    if ($parts.Count -eq 2) {
        $config[$parts[0]] = $parts[1]
    }
}

# Validate critical deployment outputs
$requiredKeys = @(
    'RESOURCE_GROUP_NAME', 'RESOURCE_GROUP_ID', 'FUNCTION_APP_NAME',
    'FUNCTION_APP_PRINCIPAL_ID', 'LOG_ANALYTICS_WORKSPACE_ID',
    'SUBSCRIPTION_ID', 'DCR_ENDPOINT_URL'
)
foreach ($key in $requiredKeys) {
    if (-not $config[$key]) {
        throw "Missing required deployment output: $key. Check Deploy-Azure.ps1 completed successfully."
    }
}

Write-Host "  Resource Group: $($config['RESOURCE_GROUP_NAME'])" -ForegroundColor Green
Write-Host "  Function App: $($config['FUNCTION_APP_NAME'])" -ForegroundColor Green
Write-Host ""

# Step 2: Create Entra ID Objects
Write-Host "Step 2/7: Creating Entra ID objects..." -ForegroundColor Cyan
$entraParameters = @{ ProjectName = $ProjectName }
if (-not [string]::IsNullOrWhiteSpace($ExpectedIntuneAdminGroupId)) {
    $entraParameters['ExpectedIntuneAdminGroupId'] = $ExpectedIntuneAdminGroupId
}
if (-not [string]::IsNullOrWhiteSpace($ExpectedSecurityReaderGroupId)) {
    $entraParameters['ExpectedSecurityReaderGroupId'] = $ExpectedSecurityReaderGroupId
}
if (-not [string]::IsNullOrWhiteSpace($ExpectedBackupAppObjectId)) {
    $entraParameters['ExpectedBackupAppObjectId'] = $ExpectedBackupAppObjectId
}
if (-not [string]::IsNullOrWhiteSpace($ExpectedBackupSpObjectId)) {
    $entraParameters['ExpectedBackupSpObjectId'] = $ExpectedBackupSpObjectId
}
$entraOutput = & "$ScriptDir/Setup-EntraID.ps1" @entraParameters

if ($LASTEXITCODE -ne 0) {
    throw "Entra ID setup failed"
}

# Parse Entra outputs
foreach ($line in $entraOutput) {
    if ($line -match '^[A-Z_]+=') {
        $parts = $line -split '=', 2
        if ($parts.Count -eq 2) {
            $config[$parts[0]] = $parts[1]
        }
    }
}

$requiredEntraKeys = @(
    'ENTRA_TENANT_ID', 'INTUNE_ADMIN_GROUP_ID', 'SECURITY_READER_GROUP_ID',
    'BACKUP_APP_OBJECT_ID', 'BACKUP_SP_OBJECT_ID', 'BACKUP_SP_CLIENT_ID'
)
foreach ($key in $requiredEntraKeys) {
    if (-not $config[$key]) {
        throw "Missing required Entra setup output: $key. No downstream permissions will be configured."
    }
}

Write-Host "  Intune Admin Group: $($config['INTUNE_ADMIN_GROUP_ID'])" -ForegroundColor Green
Write-Host "  Security Reader Group: $($config['SECURITY_READER_GROUP_ID'])" -ForegroundColor Green
Write-Host "  Backup App Object: $($config['BACKUP_APP_OBJECT_ID'])" -ForegroundColor Green
Write-Host "  Backup SP: $($config['BACKUP_SP_OBJECT_ID'])" -ForegroundColor Green
Write-Host ""

# Step 3: Create Custom Table and Data Collection Rule
Write-Host "Step 3/7: Creating ZSPAudit_CL table and Data Collection Rule..." -ForegroundColor Cyan

$workspaceId = $config['LOG_ANALYTICS_WORKSPACE_ID']
$workspaceName = ($workspaceId -split '/')[-1]
$rgName = $config['RESOURCE_GROUP_NAME']
$dceId = "/subscriptions/$($config['SUBSCRIPTION_ID'])/resourceGroups/$rgName/providers/Microsoft.Insights/dataCollectionEndpoints/$ProjectName-dce"

# Create custom table
Write-Host "  Creating ZSPAudit_CL custom table..." -ForegroundColor Cyan
$tableBody = @{
    properties = @{
        schema = @{
            name = "ZSPAudit_CL"
            columns = @(
                @{ name = "TimeGenerated"; type = "datetime" }
                @{ name = "EventType"; type = "string" }
                @{ name = "IdentityType"; type = "string" }
                @{ name = "PrincipalId"; type = "string" }
                @{ name = "PrincipalName"; type = "string" }
                @{ name = "Target"; type = "string" }
                @{ name = "TargetType"; type = "string" }
                @{ name = "Role"; type = "string" }
                @{ name = "DurationMinutes"; type = "int" }
                @{ name = "Justification"; type = "string" }
                @{ name = "TicketId"; type = "string" }
                @{ name = "WorkflowId"; type = "string" }
                @{ name = "ExpiresAt"; type = "string" }
                @{ name = "RequestedBy"; type = "string" }
                @{ name = "Result"; type = "string" }
                @{ name = "ErrorMessage"; type = "string" }
            )
        }
    }
} | ConvertTo-Json -Depth 10 -Compress

az rest --method PUT `
    --uri "https://management.azure.com${workspaceId}/tables/ZSPAudit_CL?api-version=2022-10-01" `
    --headers "Content-Type=application/json" `
    --body (New-JsonBodyFile $tableBody) `
    --output none

if ($LASTEXITCODE -ne 0) {
    throw "Failed to create ZSPAudit_CL custom table. Check deployer has Log Analytics Contributor on the workspace."
}

Write-Host "    ZSPAudit_CL table created" -ForegroundColor Green

# Create Data Collection Rule
Write-Host "  Creating Data Collection Rule..." -ForegroundColor Cyan
$dcrBody = @{
    location = $Location
    properties = @{
        dataCollectionEndpointId = $dceId
        streamDeclarations = @{
            "Custom-ZSPAudit_CL" = @{
                columns = @(
                    @{ name = "TimeGenerated"; type = "datetime" }
                    @{ name = "EventType"; type = "string" }
                    @{ name = "IdentityType"; type = "string" }
                    @{ name = "PrincipalId"; type = "string" }
                    @{ name = "PrincipalName"; type = "string" }
                    @{ name = "Target"; type = "string" }
                    @{ name = "TargetType"; type = "string" }
                    @{ name = "Role"; type = "string" }
                    @{ name = "DurationMinutes"; type = "int" }
                    @{ name = "Justification"; type = "string" }
                    @{ name = "TicketId"; type = "string" }
                    @{ name = "WorkflowId"; type = "string" }
                    @{ name = "ExpiresAt"; type = "string" }
                    @{ name = "RequestedBy"; type = "string" }
                    @{ name = "Result"; type = "string" }
                    @{ name = "ErrorMessage"; type = "string" }
                )
            }
        }
        dataFlows = @(
            @{
                streams = @("Custom-ZSPAudit_CL")
                destinations = @("$workspaceName")
                transformKql = "source"
                outputStream = "Custom-ZSPAudit_CL"
            }
        )
        destinations = @{
            logAnalytics = @(
                @{
                    workspaceResourceId = $workspaceId
                    name = $workspaceName
                }
            )
        }
    }
} | ConvertTo-Json -Depth 10 -Compress

$dcrJson = az rest --method PUT `
    --uri "https://management.azure.com/subscriptions/$($config['SUBSCRIPTION_ID'])/resourceGroups/$rgName/providers/Microsoft.Insights/dataCollectionRules/$ProjectName-dcr?api-version=2022-06-01" `
    --headers "Content-Type=application/json" `
    --body (New-JsonBodyFile $dcrBody) `
    --output json

if ($LASTEXITCODE -ne 0) {
    throw "Failed to create Data Collection Rule. Check deployer has Monitoring Contributor on the resource group."
}

$dcrResult = $dcrJson | ConvertFrom-Json
$dcrRuleId = $dcrResult.properties.immutableId
if (-not $dcrRuleId) {
    throw "DCR created but immutableId not found in response. Check the DCR resource in the portal."
}
$config['DCR_RULE_ID'] = $dcrRuleId
Write-Host "    DCR created with immutableId: $dcrRuleId" -ForegroundColor Green
Write-Host ""

# Step 4: Grant Graph API Permissions
Write-Host "Step 4/7: Granting Graph API permissions..." -ForegroundColor Cyan
$dcrScope = "/subscriptions/$($config['SUBSCRIPTION_ID'])/resourceGroups/$rgName/providers/Microsoft.Insights/dataCollectionRules/$ProjectName-dcr"
& "$ScriptDir/Grant-Permissions.ps1" `
    -FunctionAppPrincipalId $config['FUNCTION_APP_PRINCIPAL_ID'] `
    -ResourceGroupId $config['RESOURCE_GROUP_ID'] `
    -DcrScope $dcrScope

if ($LASTEXITCODE -ne 0) {
    throw "Permission grants failed"
}
Write-Host ""

# Step 5: Configure Function App
Write-Host "Step 5/7: Configuring Function App..." -ForegroundColor Cyan
& "$ScriptDir/Configure-Function.ps1" `
    -FunctionAppName $config['FUNCTION_APP_NAME'] `
    -ResourceGroupName $config['RESOURCE_GROUP_NAME'] `
    -IntuneAdminGroupId $config['INTUNE_ADMIN_GROUP_ID'] `
    -SecurityReaderGroupId $config['SECURITY_READER_GROUP_ID'] `
    -BackupSpObjectId $config['BACKUP_SP_OBJECT_ID'] `
    -AllowedAdminUserIds $deployerPrincipalId `
    -KeyVaultResourceId $config['KEYVAULT_ID'] `
    -StorageResourceId $config['STORAGE_ACCOUNT_ID'] `
    -LogAnalyticsWorkspaceId $config['LOG_ANALYTICS_WORKSPACE_CUSTOMER_ID'] `
    -DcrEndpoint $config['DCR_ENDPOINT_URL'] `
    -DcrRuleId $config['DCR_RULE_ID'] `
    -MaxAccessDurationMinutes $MaxAccessDurationMinutes

if ($LASTEXITCODE -ne 0) {
    throw "Function App configuration failed"
}
Write-Host ""

# Step 6: Deploy Function Code
if (-not $SkipFunctionDeploy) {
    Write-Host "Step 6/7: Deploying Function App code..." -ForegroundColor Cyan

    $functionDir = Join-Path $LabRoot "function"

    # Deploy using Azure CLI
    Push-Location $functionDir
    try {
        func azure functionapp publish $config['FUNCTION_APP_NAME'] --python 2>&1 | ForEach-Object {
            if ($_ -match 'error|failed' -and $_ -notmatch 'SCM_') {
                Write-Host "  $_" -ForegroundColor Red
            } elseif ($_ -match 'Deployment successful|Functions in') {
                Write-Host "  $_" -ForegroundColor Green
            }
        }
    }
    catch {
        # Fallback to zip deploy if func CLI not available
        Write-Host "  func CLI not available, using zip deploy..." -ForegroundColor Yellow

        $tempDir = if ($env:TEMP) { $env:TEMP } elseif ($env:TMPDIR) { $env:TMPDIR } else { '/tmp' }
        $zipPath = Join-Path $tempDir "function-deploy.zip"
        Compress-Archive -Path "$functionDir/*" -DestinationPath $zipPath -Force

        az functionapp deployment source config-zip `
            --resource-group $config['RESOURCE_GROUP_NAME'] `
            --name $config['FUNCTION_APP_NAME'] `
            --src $zipPath `
            --build-remote true `
            --output none

        Remove-Item $zipPath -Force
        Write-Host "  Deployment complete" -ForegroundColor Green
    }
    finally {
        Pop-Location
    }
}
else {
    Write-Host "Step 6/7: Skipping Function App code deployment" -ForegroundColor Yellow
}
Write-Host ""

# Step 7: Run smoke test
if (-not $SkipTest) {
    Write-Host "Step 7/7: Running smoke test..." -ForegroundColor Cyan

    # Retrieve the function key for authenticated requests
    $functionKey = az functionapp keys list `
        --name $config['FUNCTION_APP_NAME'] `
        --resource-group $config['RESOURCE_GROUP_NAME'] `
        --query "functionKeys.default" -o tsv 2>$null

    if (-not $functionKey) {
        Write-Host "  WARNING: Could not retrieve function key, skipping smoke test" -ForegroundColor Yellow
    }
    else {
        & "$ScriptDir/Test-Lab.ps1" `
            -FunctionAppUrl $config['FUNCTION_APP_URL'] `
            -FunctionKey $functionKey `
            -BackupSpObjectId $config['BACKUP_SP_OBJECT_ID'] `
            -KeyVaultResourceId $config['KEYVAULT_ID']
    }
}

# Cleanup temp files
$script:_jsonTempFiles | ForEach-Object { Remove-Item $_ -Force -ErrorAction SilentlyContinue }

# Summary
Write-Host "`n=== Deployment Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "Function App URL: $($config['FUNCTION_APP_URL'])" -ForegroundColor Cyan
Write-Host ""
Write-Host "Endpoints:"
Write-Host "  Health:     $($config['FUNCTION_APP_URL'])/api/health"
Write-Host "  NHI Access: $($config['FUNCTION_APP_URL'])/api/nhi-access"
Write-Host "  Admin Access: $($config['FUNCTION_APP_URL'])/api/admin-access"
Write-Host ""
Write-Host "ZSP Groups:"
Write-Host "  Intune Admins:   $($config['INTUNE_ADMIN_GROUP_ID'])"
Write-Host "  Security Reader: $($config['SECURITY_READER_GROUP_ID'])"
Write-Host ""
Write-Host "Backup Service Principal: $($config['BACKUP_SP_OBJECT_ID'])"
Write-Host ""
Write-Host "Safe rerun (immutable Entra IDs are mandatory once these names exist):"
$safeRerunCommand = "./scripts/Deploy-Lab.ps1 -ProjectName `"$ProjectName`" -ExpectedIntuneAdminGroupId `"$($config['INTUNE_ADMIN_GROUP_ID'])`" -ExpectedSecurityReaderGroupId `"$($config['SECURITY_READER_GROUP_ID'])`" -ExpectedBackupAppObjectId `"$($config['BACKUP_APP_OBJECT_ID'])`" -ExpectedBackupSpObjectId `"$($config['BACKUP_SP_OBJECT_ID'])`""
Write-Host $safeRerunCommand -ForegroundColor DarkGray
Write-Host ""
Write-Host "Test NHI access with:"
Write-Host @"
curl -X POST "$($config['FUNCTION_APP_URL'])/api/nhi-access" \
  -H "Content-Type: application/json" \
  -H "x-functions-key: <FUNCTION_KEY>" \
  -d '{
    "sp_object_id": "$($config['BACKUP_SP_OBJECT_ID'])",
    "scope": "$($config['KEYVAULT_ID'])",
    "role": "Key Vault Secrets User",
    "duration_minutes": 5,
    "workflow_id": "manual-test"
  }'
"@ -ForegroundColor DarkGray
Write-Host "The POST returns a Durable Functions management payload (HTTP 202)." -ForegroundColor Yellow
Write-Host "Poll its statusQueryGetUri until customStatus.status is 'active' before using the access." -ForegroundColor Yellow
