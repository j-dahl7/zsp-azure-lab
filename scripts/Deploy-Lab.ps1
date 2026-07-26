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
    Optional exact Intune Admins group object ID. The deployment manifest
    supplies all four Entra IDs automatically on a normal rerun; provide all
    Expected*ObjectId parameters only to assert or explicitly reuse exact IDs.

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
    [string]$ManifestPath = (Join-Path (Split-Path -Parent $PSScriptRoot) '.zsp-deployment.json'),

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
$PSNativeCommandUseErrorActionPreference = $false
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
    -DeployerPrincipalId $deployerPrincipalId `
    -ManifestPath $ManifestPath

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
    'FUNCTION_APP_URL', 'FUNCTION_APP_PRINCIPAL_ID', 'KEYVAULT_ID',
    'KEYVAULT_NAME', 'STORAGE_ACCOUNT_ID', 'STORAGE_ACCOUNT_NAME',
    'LOG_ANALYTICS_WORKSPACE_ID', 'LOG_ANALYTICS_WORKSPACE_CUSTOMER_ID',
    'SUBSCRIPTION_ID', 'TENANT_ID', 'DCR_ENDPOINT_URL', 'DEPLOYMENT_ID',
    'AZURE_OWNER_MARKER', 'DEPLOYMENT_MANIFEST_PATH'
)
foreach ($key in $requiredKeys) {
    if (-not $config[$key]) {
        throw "Missing required deployment output: $key. Check Deploy-Azure.ps1 completed successfully."
    }
}

Write-Host "  Resource Group: $($config['RESOURCE_GROUP_NAME'])" -ForegroundColor Green
Write-Host "  Function App: $($config['FUNCTION_APP_NAME'])" -ForegroundColor Green
Write-Host ""

$deploymentManifestPath = $config['DEPLOYMENT_MANIFEST_PATH']
if (-not (Test-Path -LiteralPath $deploymentManifestPath -PathType Leaf)) {
    throw "Deploy-Azure.ps1 did not persist the required manifest '$deploymentManifestPath'."
}
try {
    $azureManifest = Get-Content -LiteralPath $deploymentManifestPath -Raw | ConvertFrom-Json
}
catch {
    throw "Deployment manifest '$deploymentManifestPath' is invalid JSON."
}
if ([int]$azureManifest.schema_version -ne 2 -or
    [string]$azureManifest.status -notin @('azure_deployed', 'identities_configured', 'deployed_unvalidated', 'validated') -or
    [string]$azureManifest.project_name -cne $ProjectName -or
    [string]$azureManifest.azure_owner_marker -cne $config['AZURE_OWNER_MARKER'] -or
    [string]$azureManifest.deployment_id -cne $config['DEPLOYMENT_ID'] -or
    -not [string]::Equals([string]$azureManifest.tenant_id, [string]$account.tenantId, [System.StringComparison]::OrdinalIgnoreCase) -or
    -not [string]::Equals([string]$azureManifest.subscription_id, [string]$account.id, [System.StringComparison]::OrdinalIgnoreCase) -or
    -not [string]::Equals([string]$azureManifest.resource_group_id, [string]$config['RESOURCE_GROUP_ID'], [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'The Azure deployment manifest does not match the verified deployment outputs and active account.'
}

# Step 2: Create Entra ID Objects
Write-Host "Step 2/7: Creating Entra ID objects..." -ForegroundColor Cyan
$entraParameters = @{ ProjectName = $ProjectName }
$entraIdentityMap = @(
    @{ Parameter = 'ExpectedIntuneAdminGroupId'; Input = $ExpectedIntuneAdminGroupId; Field = 'intune_admin_group_id' },
    @{ Parameter = 'ExpectedSecurityReaderGroupId'; Input = $ExpectedSecurityReaderGroupId; Field = 'security_reader_group_id' },
    @{ Parameter = 'ExpectedBackupAppObjectId'; Input = $ExpectedBackupAppObjectId; Field = 'backup_app_object_id' },
    @{ Parameter = 'ExpectedBackupSpObjectId'; Input = $ExpectedBackupSpObjectId; Field = 'backup_service_principal_id' }
)
$allRecordedEntraFields = @(
    'intune_admin_group_id', 'security_reader_group_id', 'backup_app_object_id',
    'backup_service_principal_id', 'backup_service_principal_app_id'
)
$recordedEntraFieldCount = @(
    $allRecordedEntraFields | Where-Object {
        $azureManifest.PSObject.Properties.Name -contains $_ -and
        -not [string]::IsNullOrWhiteSpace([string]$azureManifest.($_))
    }
).Count
if ($recordedEntraFieldCount -notin @(0, $allRecordedEntraFields.Count)) {
    throw 'Deployment manifest contains a partial Entra identity set. Refusing ambiguous reuse.'
}
foreach ($mapping in $entraIdentityMap) {
    if ($recordedEntraFieldCount -eq $allRecordedEntraFields.Count) {
        $recordedValue = [string]$azureManifest.($mapping.Field)
        if (-not [string]::IsNullOrWhiteSpace([string]$mapping.Input) -and
            -not [string]::Equals([string]$mapping.Input, $recordedValue, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "$($mapping.Parameter) does not match the exact ID recorded in the deployment manifest."
        }
        $entraParameters[$mapping.Parameter] = $recordedValue
    }
    elseif (-not [string]::IsNullOrWhiteSpace([string]$mapping.Input)) {
        $entraParameters[$mapping.Parameter] = [string]$mapping.Input
    }
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
if (-not [string]::Equals([string]$config['ENTRA_TENANT_ID'], [string]$account.tenantId, [System.StringComparison]::OrdinalIgnoreCase) -or
    -not [string]::Equals([string]$config['TENANT_ID'], [string]$account.tenantId, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Entra setup and Azure deployment tenant IDs do not match the active tenant.'
}

Write-Host "  Intune Admin Group: $($config['INTUNE_ADMIN_GROUP_ID'])" -ForegroundColor Green
Write-Host "  Security Reader Group: $($config['SECURITY_READER_GROUP_ID'])" -ForegroundColor Green
Write-Host "  Backup App Object: $($config['BACKUP_APP_OBJECT_ID'])" -ForegroundColor Green
Write-Host "  Backup SP: $($config['BACKUP_SP_OBJECT_ID'])" -ForegroundColor Green
Write-Host ""

# Persist only immutable identifiers and provenance (never credentials) so cleanup
# can address exact objects instead of deleting by non-unique display name.
$provenanceMarker = "nine-lives-zsp:v1;tenant=$($config['ENTRA_TENANT_ID']);project=$ProjectName"
$deploymentManifest = [ordered]@{
    schema_version                  = 2
    status                          = 'identities_configured'
    project_name                   = $ProjectName
    location                       = [string]$azureManifest.location
    provenance_marker              = $provenanceMarker
    azure_owner_marker             = $config['AZURE_OWNER_MARKER']
    deployment_id                  = $config['DEPLOYMENT_ID']
    tenant_id                      = $config['ENTRA_TENANT_ID']
    subscription_id                = $config['SUBSCRIPTION_ID']
    resource_group_name            = $config['RESOURCE_GROUP_NAME']
    resource_group_id              = $config['RESOURCE_GROUP_ID']
    intune_admin_group_id          = $config['INTUNE_ADMIN_GROUP_ID']
    security_reader_group_id       = $config['SECURITY_READER_GROUP_ID']
    backup_app_object_id           = $config['BACKUP_APP_OBJECT_ID']
    backup_service_principal_id    = $config['BACKUP_SP_OBJECT_ID']
    backup_service_principal_app_id = $config['BACKUP_SP_CLIENT_ID']
}
function Save-DeploymentManifest {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('identities_configured', 'deployed_unvalidated', 'validated')]
        [string]$Status
    )

    $deploymentManifest['status'] = $Status
    $manifestTempPath = "$deploymentManifestPath.tmp.$PID.$([guid]::NewGuid().ToString('N'))"
    try {
        [System.IO.File]::WriteAllText(
            $manifestTempPath,
            ($deploymentManifest | ConvertTo-Json -Depth 4),
            [System.Text.UTF8Encoding]::new($false)
        )
        Move-Item -LiteralPath $manifestTempPath -Destination $deploymentManifestPath -Force
    }
    finally {
        if (Test-Path -LiteralPath $manifestTempPath) {
            Remove-Item -LiteralPath $manifestTempPath -Force
        }
    }
}
Save-DeploymentManifest -Status 'identities_configured'
Write-Host "  Cleanup manifest: $deploymentManifestPath" -ForegroundColor Green

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

    # Deploy with Core Tools when available. A nonzero publish result is a hard
    # failure; fallback is used only when Core Tools is not installed.
    Push-Location $functionDir
    try {
        $funcCommand = Get-Command func -ErrorAction SilentlyContinue
        if ($funcCommand) {
            $publishOutput = & $funcCommand.Source azure functionapp publish $config['FUNCTION_APP_NAME'] --python 2>&1
            $publishExitCode = $LASTEXITCODE
            $publishOutput | ForEach-Object {
                if ($_ -match 'error|failed' -and $_ -notmatch 'SCM_') {
                    Write-Host "  $_" -ForegroundColor Red
                }
                elseif ($_ -match 'Deployment successful|Functions in') {
                    Write-Host "  $_" -ForegroundColor Green
                }
            }
            if ($publishExitCode -ne 0) {
                throw "Function Core Tools publish failed with exit code $publishExitCode."
            }
            Write-Host '  Function deployment command completed successfully' -ForegroundColor Green
        }
        else {
            Write-Host "  func CLI not available, using remote zip deployment..." -ForegroundColor Yellow

            $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
            $packageToken = "$PID-$([guid]::NewGuid().ToString('N'))"
            $packageRoot = [System.IO.Path]::GetFullPath((Join-Path $tempRoot "zsp-function-$packageToken"))
            $zipPath = [System.IO.Path]::GetFullPath((Join-Path $tempRoot "zsp-function-$packageToken.zip"))
            $expectedTempParent = $tempRoot.TrimEnd([char[]]'\/')
            if (-not [string]::Equals(
                    [System.IO.Path]::GetDirectoryName($packageRoot),
                    $expectedTempParent,
                    [System.StringComparison]::OrdinalIgnoreCase
                ) -or
                -not [string]::Equals(
                    [System.IO.Path]::GetDirectoryName($zipPath),
                    $expectedTempParent,
                    [System.StringComparison]::OrdinalIgnoreCase
                )) {
                throw 'Refusing to create a Function package outside the operating-system temporary directory.'
            }

            # Package only reviewed runtime files. Never upload gitignored local
            # settings, virtual environments, tests, caches, or arbitrary files.
            $deploymentFiles = @(
                'access_safety.py', 'admin_access.py', 'audit.py',
                'function_app.py', 'nhi_access.py', 'host.json',
                'requirements.txt', 'pins.txt'
            )
            try {
                $null = New-Item -ItemType Directory -Path $packageRoot
                foreach ($deploymentFile in $deploymentFiles) {
                    $sourcePath = Join-Path $functionDir $deploymentFile
                    if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
                        throw "Required Function deployment file is missing: $deploymentFile"
                    }
                    Copy-Item -LiteralPath $sourcePath -Destination $packageRoot
                }
                Compress-Archive -Path (Join-Path $packageRoot '*') -DestinationPath $zipPath -Force

                az functionapp deployment source config-zip `
                    --resource-group $config['RESOURCE_GROUP_NAME'] `
                    --name $config['FUNCTION_APP_NAME'] `
                    --src $zipPath `
                    --build-remote true `
                    --output none
                $zipDeployExitCode = $LASTEXITCODE
                if ($zipDeployExitCode -ne 0) {
                    throw "Remote zip deployment failed with Azure CLI exit code $zipDeployExitCode."
                }
                Write-Host '  Remote zip deployment completed successfully' -ForegroundColor Green
            }
            finally {
                if (Test-Path -LiteralPath $zipPath) {
                    Remove-Item -LiteralPath $zipPath -Force
                }
                if (Test-Path -LiteralPath $packageRoot -PathType Container) {
                    Remove-Item -LiteralPath $packageRoot -Recurse -Force
                }
            }
        }
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
    $functionKeyExitCode = $LASTEXITCODE

    if ($functionKeyExitCode -ne 0 -or [string]::IsNullOrWhiteSpace([string]$functionKey)) {
        throw 'Could not retrieve the Function key required for the smoke test. Use -SkipTest only for an intentional unvalidated deployment.'
    }

    & "$ScriptDir/Test-Lab.ps1" `
        -FunctionAppUrl $config['FUNCTION_APP_URL'] `
        -FunctionKey $functionKey `
        -BackupSpObjectId $config['BACKUP_SP_OBJECT_ID'] `
        -KeyVaultResourceId $config['KEYVAULT_ID'] `
        -WaitForRevocation
    $smokeTestExitCode = $LASTEXITCODE
    if ($smokeTestExitCode -ne 0) {
        throw "ZSP smoke test failed with exit code $smokeTestExitCode. Deployment is not complete."
    }
}

# Cleanup temp files
$script:_jsonTempFiles | ForEach-Object { Remove-Item $_ -Force -ErrorAction SilentlyContinue }

$finalManifestStatus = if ($SkipTest) { 'deployed_unvalidated' } else { 'validated' }
Save-DeploymentManifest -Status $finalManifestStatus

# Summary. Never claim a fully validated deployment when validation was skipped.
if ($SkipTest) {
    Write-Host "`n=== Deployment Finished - Smoke Test Skipped ===" -ForegroundColor Yellow
    Write-Host 'Run scripts/Test-Lab.ps1 and verify revocation before treating this deployment as validated.' -ForegroundColor Yellow
}
else {
    Write-Host "`n=== Deployment Complete and Smoke-Tested ===" -ForegroundColor Green
}
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
Write-Host "Safe rerun (the manifest reuses these exact Entra IDs automatically):"
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
