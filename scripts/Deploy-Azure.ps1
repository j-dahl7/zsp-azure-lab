#Requires -Version 7.0
<#
.SYNOPSIS
    Deploys provenance-bound Azure infrastructure using Bicep.

.DESCRIPTION
    Refuses to adopt an existing resource group unless a versioned local
    manifest and the live resource-group ID and ownership tags all match. For a
    new deployment, writes a recoverable planned manifest before the first
    Azure mutation, deploys the Bicep template, verifies the live tags, and
    advances the manifest to azure_deployed.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9-]+$')]
    [ValidateLength(3, 20)]
    [string]$ProjectName,

    [Parameter(Mandatory)]
    [string]$Location,

    [Parameter(Mandatory)]
    [ValidateRange(5, 1440)]
    [int]$MaxAccessDurationMinutes,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$DeployerPrincipalId,

    [Parameter()]
    [string]$ManifestPath = (Join-Path (Split-Path -Parent $PSScriptRoot) '.zsp-deployment.json')
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BicepDir = Join-Path (Split-Path -Parent $ScriptDir) 'bicep'
$OwnerMarker = 'nine-lives-zsp:azure:v1'
$OwnerTag = 'nlzt-owner'
$DeploymentTag = 'nlzt-deployment'
$AllowedManifestStates = @(
    'planned', 'azure_deployed', 'identities_configured',
    'deployed_unvalidated', 'validated'
)
$ManifestPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ManifestPath)

function Normalize-ResourceId {
    param([Parameter(Mandatory)][string]$ResourceId)
    return $ResourceId.TrimEnd('/').ToLowerInvariant()
}

function Assert-AzSucceeded {
    param(
        [Parameter(Mandatory)][int]$ExitCode,
        [Parameter(Mandatory)][string]$Operation
    )
    if ($ExitCode -ne 0) {
        throw "$Operation failed with Azure CLI exit code $ExitCode."
    }
}

function Read-DeploymentManifest {
    param([Parameter(Mandatory)][string]$Path)
    try {
        return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    }
    catch {
        throw "Deployment manifest '$Path' is not valid JSON: $($_.Exception.Message)"
    }
}

function Assert-CoreManifest {
    param(
        [Parameter(Mandatory)][object]$Manifest,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ExpectedResourceGroupName,
        [Parameter(Mandatory)][string]$ExpectedResourceGroupId
    )

    $requiredFields = @(
        'schema_version', 'status', 'project_name', 'location',
        'provenance_marker', 'azure_owner_marker', 'deployment_id',
        'tenant_id', 'subscription_id', 'resource_group_name', 'resource_group_id'
    )
    foreach ($field in $requiredFields) {
        if ($Manifest.PSObject.Properties.Name -notcontains $field -or
            [string]::IsNullOrWhiteSpace([string]$Manifest.$field)) {
            throw "Deployment manifest is missing required field '$field'."
        }
    }
    if ([int]$Manifest.schema_version -ne 2) {
        throw "Unsupported deployment manifest schema '$($Manifest.schema_version)'."
    }
    if ($AllowedManifestStates -notcontains [string]$Manifest.status) {
        throw "Unsupported deployment manifest state '$($Manifest.status)'."
    }
    if ([string]$Manifest.project_name -cne $ProjectName) {
        throw "Deployment manifest project '$($Manifest.project_name)' does not match '$ProjectName'."
    }
    if (-not [string]::Equals([string]$Manifest.location, $Location, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Deployment manifest location '$($Manifest.location)' does not match '$Location'."
    }
    if ([string]$Manifest.azure_owner_marker -cne $OwnerMarker) {
        throw 'Deployment manifest Azure owner marker is invalid.'
    }
    $expectedProvenance = "nine-lives-zsp:v1;tenant=$TenantId;project=$ProjectName"
    if ([string]$Manifest.provenance_marker -cne $expectedProvenance) {
        throw 'Deployment manifest Entra provenance marker is invalid.'
    }
    $parsedDeploymentId = [guid]::Empty
    if (-not [guid]::TryParse([string]$Manifest.deployment_id, [ref]$parsedDeploymentId)) {
        throw 'Deployment manifest deployment_id is not a UUID.'
    }
    if (-not [string]::Equals([string]$Manifest.tenant_id, $TenantId, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Deployment manifest tenant does not match the active tenant.'
    }
    if (-not [string]::Equals([string]$Manifest.subscription_id, $SubscriptionId, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Deployment manifest subscription does not match the active subscription.'
    }
    if ([string]$Manifest.resource_group_name -cne $ExpectedResourceGroupName) {
        throw 'Deployment manifest resource-group name is inconsistent with the project.'
    }
    if ((Normalize-ResourceId ([string]$Manifest.resource_group_id)) -ne
        (Normalize-ResourceId $ExpectedResourceGroupId)) {
        throw 'Deployment manifest resource-group ID is inconsistent with its subscription and name.'
    }
}

function Write-DeploymentManifest {
    param(
        [Parameter(Mandatory)][ValidateSet('planned', 'azure_deployed', 'identities_configured', 'deployed_unvalidated', 'validated')][string]$Status,
        [Parameter(Mandatory)][string]$DeploymentId,
        [Parameter()][object]$ExistingManifest
    )

    $manifestDirectory = Split-Path -Parent $ManifestPath
    if (-not (Test-Path -LiteralPath $manifestDirectory -PathType Container)) {
        throw "Manifest directory does not exist: $manifestDirectory"
    }

    $manifestData = [ordered]@{
        schema_version       = 2
        status               = $Status
        project_name         = $ProjectName
        location             = $Location
        provenance_marker    = "nine-lives-zsp:v1;tenant=$tenantId;project=$ProjectName"
        azure_owner_marker   = $OwnerMarker
        deployment_id        = $DeploymentId
        tenant_id            = $tenantId
        subscription_id      = $subscriptionId
        resource_group_name  = $resourceGroupName
        resource_group_id    = $expectedResourceGroupId
    }

    $entraFields = @(
        'intune_admin_group_id', 'security_reader_group_id',
        'backup_app_object_id', 'backup_service_principal_id',
        'backup_service_principal_app_id'
    )
    if ($ExistingManifest) {
        foreach ($field in $entraFields) {
            if ($ExistingManifest.PSObject.Properties.Name -contains $field -and
                -not [string]::IsNullOrWhiteSpace([string]$ExistingManifest.$field)) {
                $manifestData[$field] = [string]$ExistingManifest.$field
            }
        }
    }

    $temporaryPath = "$ManifestPath.tmp.$PID.$([guid]::NewGuid().ToString('N'))"
    try {
        [System.IO.File]::WriteAllText(
            $temporaryPath,
            ($manifestData | ConvertTo-Json -Depth 5),
            [System.Text.UTF8Encoding]::new($false)
        )
        Move-Item -LiteralPath $temporaryPath -Destination $ManifestPath -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
    }
}

function Get-VerifiedResourceGroup {
    param(
        [Parameter(Mandatory)][string]$DeploymentId,
        [Parameter(Mandatory)][string]$ExpectedResourceGroupId
    )

    $resourceGroupJson = az group show `
        --subscription $subscriptionId `
        --name $resourceGroupName `
        --output json 2>$null
    $showExitCode = $LASTEXITCODE
    Assert-AzSucceeded -ExitCode $showExitCode -Operation "Read resource group '$resourceGroupName'"
    try {
        $resourceGroup = $resourceGroupJson | ConvertFrom-Json
    }
    catch {
        throw "Azure returned invalid JSON for resource group '$resourceGroupName'."
    }

    if ((Normalize-ResourceId ([string]$resourceGroup.id)) -ne
        (Normalize-ResourceId $ExpectedResourceGroupId)) {
        throw 'Live resource-group ID does not match the deployment manifest.'
    }
    if ([string]$resourceGroup.tags.$OwnerTag -cne $OwnerMarker) {
        throw "Live resource group is missing the exact '$OwnerTag' ownership tag. Refusing to adopt it."
    }
    if ([string]$resourceGroup.tags.$DeploymentTag -cne $DeploymentId) {
        throw "Live resource group is missing the exact '$DeploymentTag' deployment tag. Refusing to adopt it."
    }
    return $resourceGroup
}

Write-Host 'Reading Azure account and resource-group ownership state...' -ForegroundColor Yellow
$accountJson = az account show --output json 2>$null
$accountExitCode = $LASTEXITCODE
Assert-AzSucceeded -ExitCode $accountExitCode -Operation 'Read active Azure account'
try {
    $account = $accountJson | ConvertFrom-Json
}
catch {
    throw 'Azure CLI returned invalid account JSON.'
}
if (-not $account.id -or -not $account.tenantId) {
    throw 'Azure CLI account response is missing the subscription or tenant ID.'
}

$subscriptionId = [string]$account.id
$tenantId = [string]$account.tenantId
$resourceGroupName = "$ProjectName-rg"
$expectedResourceGroupId = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName"

$existsText = az group exists `
    --subscription $subscriptionId `
    --name $resourceGroupName `
    --output tsv 2>$null
$existsExitCode = $LASTEXITCODE
Assert-AzSucceeded -ExitCode $existsExitCode -Operation "Check resource group '$resourceGroupName'"
$resourceGroupExists = switch (([string]$existsText).Trim().ToLowerInvariant()) {
    'true' { $true }
    'false' { $false }
    default { throw "Azure returned an invalid existence result for resource group '$resourceGroupName'." }
}

$manifest = $null
$deploymentId = $null
if (Test-Path -LiteralPath $ManifestPath -PathType Leaf) {
    $manifest = Read-DeploymentManifest -Path $ManifestPath
    Assert-CoreManifest `
        -Manifest $manifest `
        -TenantId $tenantId `
        -SubscriptionId $subscriptionId `
        -ExpectedResourceGroupName $resourceGroupName `
        -ExpectedResourceGroupId $expectedResourceGroupId
    $deploymentId = [string]$manifest.deployment_id
}

if ($resourceGroupExists) {
    if (-not $manifest) {
        throw "Resource group '$resourceGroupName' already exists, but exact deployment manifest '$ManifestPath' is missing. Refusing to adopt it."
    }
    $null = Get-VerifiedResourceGroup `
        -DeploymentId $deploymentId `
        -ExpectedResourceGroupId ([string]$manifest.resource_group_id)
    Write-Host "  Verified owned resource-group rerun: $expectedResourceGroupId" -ForegroundColor Green
}
else {
    if ($manifest) {
        if ([string]$manifest.status -ne 'planned') {
            throw "Deployment manifest '$ManifestPath' is in state '$($manifest.status)', but its recorded resource group is absent. Refusing stale-state reuse."
        }
        Write-Host "  Resuming planned deployment: $deploymentId" -ForegroundColor Yellow
    }
    else {
        $deploymentId = [guid]::NewGuid().ToString()
        Write-DeploymentManifest -Status 'planned' -DeploymentId $deploymentId
        $manifest = Read-DeploymentManifest -Path $ManifestPath
        Write-Host "  Recorded new deployment plan: $ManifestPath" -ForegroundColor Green
    }
}

Write-Host 'Deploying Azure resources...' -ForegroundColor Yellow
$deploymentToken = $deploymentId.Replace('-', '').Substring(0, 12)
$deploymentName = "zsp-$ProjectName-$deploymentToken"
$deploymentJson = az deployment sub create `
    --name $deploymentName `
    --subscription $subscriptionId `
    --location $Location `
    --template-file "$BicepDir/main.bicep" `
    --parameters projectName=$ProjectName `
    --parameters location=$Location `
    --parameters maxAccessDurationMinutes=$MaxAccessDurationMinutes `
    --parameters deployerPrincipalId=$DeployerPrincipalId `
    --parameters ownerMarker=$OwnerMarker `
    --parameters deploymentId=$deploymentId `
    --output json 2>$null
$deploymentExitCode = $LASTEXITCODE
if ($deploymentExitCode -ne 0) {
    throw "Bicep deployment failed with exit code $deploymentExitCode. The planned manifest was retained for exact retry or cleanup."
}

try {
    $result = $deploymentJson | ConvertFrom-Json
}
catch {
    throw 'Azure returned invalid deployment JSON. The manifest was retained.'
}
if ([string]$result.properties.provisioningState -ne 'Succeeded') {
    throw "Deployment failed with state '$($result.properties.provisioningState)'. The manifest was retained."
}

$outputs = $result.properties.outputs
$requiredOutputs = @(
    'resourceGroupName', 'resourceGroupId', 'functionAppName', 'functionAppId', 'functionAppUrl',
    'functionAppPrincipalId', 'keyVaultId', 'keyVaultName', 'storageAccountId',
    'storageAccountName', 'logAnalyticsWorkspaceId',
    'logAnalyticsWorkspaceCustomerId', 'dataCollectionEndpointUrl',
    'tenantId', 'subscriptionId', 'maxAccessDurationMinutes'
)
foreach ($outputName in $requiredOutputs) {
    if ($outputs.PSObject.Properties.Name -notcontains $outputName -or
        [string]::IsNullOrWhiteSpace([string]$outputs.$outputName.value)) {
        throw "Azure deployment output '$outputName' is missing. The manifest was retained."
    }
}
if ([string]$outputs.resourceGroupName.value -cne $resourceGroupName -or
    (Normalize-ResourceId ([string]$outputs.resourceGroupId.value)) -ne
    (Normalize-ResourceId $expectedResourceGroupId)) {
    throw 'Azure deployment returned an unexpected resource-group identity.'
}
if (-not [string]::Equals([string]$outputs.tenantId.value, $tenantId, [System.StringComparison]::OrdinalIgnoreCase) -or
    -not [string]::Equals([string]$outputs.subscriptionId.value, $subscriptionId, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Azure deployment outputs do not match the active tenant and subscription.'
}

$null = Get-VerifiedResourceGroup `
    -DeploymentId $deploymentId `
    -ExpectedResourceGroupId $expectedResourceGroupId

$nextManifestStatus = if ($manifest -and [string]$manifest.status -notin @('planned', 'azure_deployed')) {
    [string]$manifest.status
}
else {
    'azure_deployed'
}
Write-DeploymentManifest `
    -Status $nextManifestStatus `
    -DeploymentId $deploymentId `
    -ExistingManifest $manifest

Write-Output "RESOURCE_GROUP_NAME=$($outputs.resourceGroupName.value)"
Write-Output "RESOURCE_GROUP_ID=$($outputs.resourceGroupId.value)"
Write-Output "FUNCTION_APP_NAME=$($outputs.functionAppName.value)"
Write-Output "FUNCTION_APP_ID=$($outputs.functionAppId.value)"
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
Write-Output "DEPLOYMENT_ID=$deploymentId"
Write-Output "AZURE_OWNER_MARKER=$OwnerMarker"
Write-Output "DEPLOYMENT_MANIFEST_PATH=$ManifestPath"

Write-Host "Azure resources deployed with verified provenance '$deploymentId'." -ForegroundColor Green
