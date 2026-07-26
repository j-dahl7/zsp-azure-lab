#Requires -Version 7.0
<#
.SYNOPSIS
    Safely removes resources recorded by a ZSP lab deployment.

.DESCRIPTION
    Reads the deployment-generated .zsp-deployment.json manifest, verifies the
    active tenant/subscription, exact Azure resource-group ID and ownership
    tags, and every present Entra object's immutable identity and provenance
    before the first delete. Cleanup is retryable and retains the manifest until
    every recorded Entra object and the Azure resource group are confirmed
    absent.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9-]+$')]
    [string]$ConfirmProject,

    [Parameter()]
    [string]$ManifestPath = (Join-Path (Split-Path -Parent $PSScriptRoot) '.zsp-deployment.json'),

    [Parameter()]
    [switch]$DestroyAzureResources
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$OwnerMarker = 'nine-lives-zsp:azure:v1'
$OwnerTag = 'nlzt-owner'
$DeploymentTag = 'nlzt-deployment'
$AllowedManifestStates = @(
    'planned', 'azure_deployed', 'identities_configured',
    'deployed_unvalidated', 'validated'
)

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

function Get-GraphObjectByExactId {
    param(
        [Parameter(Mandatory)][ValidateSet('groups', 'applications', 'servicePrincipals')][string]$EntitySet,
        [Parameter(Mandatory)][string]$ObjectId,
        [Parameter(Mandatory)][string]$Select
    )

    $encodedFilter = [System.Uri]::EscapeDataString("id eq '$ObjectId'")
    $encodedSelect = [System.Uri]::EscapeDataString($Select)
    $responseJson = az rest --method GET `
        --url "https://graph.microsoft.com/v1.0/$EntitySet?`$filter=$encodedFilter&`$select=$encodedSelect" `
        --output json
    $lookupExitCode = $LASTEXITCODE
    Assert-AzSucceeded -ExitCode $lookupExitCode -Operation "Read exact $EntitySet object '$ObjectId'"
    try {
        $response = $responseJson | ConvertFrom-Json
    }
    catch {
        throw "Microsoft Graph returned invalid JSON while reading '$ObjectId'."
    }
    if ($response.PSObject.Properties.Name -notcontains 'value') {
        throw "Microsoft Graph response for '$ObjectId' has no value collection."
    }
    $matches = @($response.value | Where-Object {
        [string]::Equals([string]$_.id, $ObjectId, [System.StringComparison]::OrdinalIgnoreCase)
    })
    if ($matches.Count -gt 1) {
        throw "Microsoft Graph returned duplicate exact-ID matches for '$ObjectId'."
    }
    if ($matches.Count -eq 0) {
        return $null
    }
    return $matches[0]
}

function Assert-OwnedGroup {
    param(
        [Parameter(Mandatory)][object]$Group,
        [Parameter(Mandatory)][string]$ObjectId,
        [Parameter(Mandatory)][string]$ExpectedDisplayName,
        [Parameter(Mandatory)][string]$ExpectedMarker
    )

    if ([string]$Group.displayName -cne $ExpectedDisplayName) {
        throw "Group '$ObjectId' has an unexpected display name."
    }
    if (-not ([string]$Group.description).Contains("[$ExpectedMarker]", [System.StringComparison]::Ordinal)) {
        throw "Group '$ObjectId' does not carry this deployment's provenance marker."
    }

    $membersJson = az rest --method GET `
        --url "https://graph.microsoft.com/v1.0/groups/$ObjectId/members?`$select=id&`$top=1" `
        --output json
    $memberExitCode = $LASTEXITCODE
    Assert-AzSucceeded -ExitCode $memberExitCode -Operation "Read direct members for group '$ObjectId'"
    try {
        $members = $membersJson | ConvertFrom-Json
    }
    catch {
        throw "Microsoft Graph returned invalid membership JSON for group '$ObjectId'."
    }
    if ($members.PSObject.Properties.Name -notcontains 'value') {
        throw "Unable to verify membership for group '$ObjectId'."
    }
    if (@($members.value).Count -gt 0) {
        throw "Group '$ObjectId' still has direct members. Revoke active access before cleanup."
    }
}

$ManifestPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ManifestPath)
if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
    throw "Cleanup manifest not found: $ManifestPath. Refusing name-based discovery."
}
try {
    $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
}
catch {
    throw "Cleanup manifest '$ManifestPath' is invalid JSON."
}

$coreFields = @(
    'schema_version', 'status', 'project_name', 'location',
    'provenance_marker', 'azure_owner_marker', 'deployment_id',
    'tenant_id', 'subscription_id', 'resource_group_name', 'resource_group_id'
)
foreach ($field in $coreFields) {
    if ($manifest.PSObject.Properties.Name -notcontains $field -or
        [string]::IsNullOrWhiteSpace([string]$manifest.$field)) {
        throw "Cleanup manifest is missing required field '$field'."
    }
}
if ([int]$manifest.schema_version -ne 2) {
    throw "Unsupported cleanup manifest schema '$($manifest.schema_version)'."
}
if ($AllowedManifestStates -notcontains [string]$manifest.status) {
    throw "Unsupported cleanup manifest state '$($manifest.status)'."
}
if ($ConfirmProject -cne [string]$manifest.project_name) {
    throw "-ConfirmProject must exactly match manifest project '$($manifest.project_name)'."
}
if ([string]$manifest.azure_owner_marker -cne $OwnerMarker) {
    throw 'Cleanup manifest Azure owner marker is invalid.'
}
$expectedMarker = "nine-lives-zsp:v1;tenant=$($manifest.tenant_id);project=$($manifest.project_name)"
if ([string]$manifest.provenance_marker -cne $expectedMarker) {
    throw 'Cleanup manifest provenance marker is invalid.'
}
$parsedDeploymentId = [guid]::Empty
if (-not [guid]::TryParse([string]$manifest.deployment_id, [ref]$parsedDeploymentId)) {
    throw 'Cleanup manifest deployment_id is not a UUID.'
}
$expectedResourceGroupName = "$($manifest.project_name)-rg"
if ([string]$manifest.resource_group_name -cne $expectedResourceGroupName) {
    throw 'Resource-group name in the manifest is inconsistent with the project.'
}
$expectedResourceGroupId = "/subscriptions/$($manifest.subscription_id)/resourceGroups/$expectedResourceGroupName"
if ((Normalize-ResourceId ([string]$manifest.resource_group_id)) -ne
    (Normalize-ResourceId $expectedResourceGroupId)) {
    throw 'Resource-group ID in the manifest is inconsistent with its subscription and name.'
}

$entraFields = @(
    'intune_admin_group_id', 'security_reader_group_id', 'backup_app_object_id',
    'backup_service_principal_id', 'backup_service_principal_app_id'
)
$presentEntraFieldCount = @(
    $entraFields | Where-Object {
        $manifest.PSObject.Properties.Name -contains $_ -and
        -not [string]::IsNullOrWhiteSpace([string]$manifest.($_))
    }
).Count
if ($presentEntraFieldCount -notin @(0, $entraFields.Count)) {
    throw 'Cleanup manifest contains a partial Entra identity set.'
}
if ([string]$manifest.status -notin @('planned', 'azure_deployed') -and
    $presentEntraFieldCount -ne $entraFields.Count) {
    throw "Cleanup manifest state '$($manifest.status)' must contain the full Entra identity set."
}

$accountJson = az account show --output json
$accountExitCode = $LASTEXITCODE
Assert-AzSucceeded -ExitCode $accountExitCode -Operation 'Read active Azure account'
try {
    $account = $accountJson | ConvertFrom-Json
}
catch {
    throw 'Azure CLI returned invalid account JSON.'
}
if (-not [string]::Equals([string]$account.tenantId, [string]$manifest.tenant_id, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Current tenant '$($account.tenantId)' does not match manifest tenant '$($manifest.tenant_id)'."
}
if (-not [string]::Equals([string]$account.id, [string]$manifest.subscription_id, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Current subscription '$($account.id)' does not match manifest subscription '$($manifest.subscription_id)'."
}

# Azure ownership is verified before any Graph or Azure deletion.
$existsText = az group exists `
    --subscription $manifest.subscription_id `
    --name $manifest.resource_group_name `
    --output tsv
$existsExitCode = $LASTEXITCODE
Assert-AzSucceeded -ExitCode $existsExitCode -Operation "Check resource group '$($manifest.resource_group_name)'"
$resourceGroupExists = switch (([string]$existsText).Trim().ToLowerInvariant()) {
    'true' { $true }
    'false' { $false }
    default { throw "Azure returned an invalid existence result for resource group '$($manifest.resource_group_name)'." }
}
if ($resourceGroupExists) {
    $resourceGroupJson = az group show `
        --subscription $manifest.subscription_id `
        --name $manifest.resource_group_name `
        --output json
    $showExitCode = $LASTEXITCODE
    Assert-AzSucceeded -ExitCode $showExitCode -Operation "Read resource group '$($manifest.resource_group_name)'"
    try {
        $resourceGroup = $resourceGroupJson | ConvertFrom-Json
    }
    catch {
        throw 'Azure CLI returned invalid resource-group JSON.'
    }
    if ((Normalize-ResourceId ([string]$resourceGroup.id)) -ne
        (Normalize-ResourceId ([string]$manifest.resource_group_id))) {
        throw 'Live resource-group ID does not match the cleanup manifest.'
    }
    if ([string]$resourceGroup.tags.$OwnerTag -cne $OwnerMarker) {
        throw "Live resource group is missing the exact '$OwnerTag' ownership tag. No resources were deleted."
    }
    if ([string]$resourceGroup.tags.$DeploymentTag -cne [string]$manifest.deployment_id) {
        throw "Live resource group is missing the exact '$DeploymentTag' deployment tag. No resources were deleted."
    }
}

$targets = @()
if ($presentEntraFieldCount -eq $entraFields.Count) {
    $intuneGroup = Get-GraphObjectByExactId `
        -EntitySet groups `
        -ObjectId ([string]$manifest.intune_admin_group_id) `
        -Select 'id,displayName,description'
    if ($intuneGroup) {
        Assert-OwnedGroup `
            -Group $intuneGroup `
            -ObjectId ([string]$manifest.intune_admin_group_id) `
            -ExpectedDisplayName 'SG-Intune-Admins-ZSP' `
            -ExpectedMarker $expectedMarker
        $targets += @{
            Type = 'group'
            EntitySet = 'groups'
            Id = [string]$manifest.intune_admin_group_id
            Url = "https://graph.microsoft.com/v1.0/groups/$($manifest.intune_admin_group_id)"
        }
    }

    $securityGroup = Get-GraphObjectByExactId `
        -EntitySet groups `
        -ObjectId ([string]$manifest.security_reader_group_id) `
        -Select 'id,displayName,description'
    if ($securityGroup) {
        Assert-OwnedGroup `
            -Group $securityGroup `
            -ObjectId ([string]$manifest.security_reader_group_id) `
            -ExpectedDisplayName 'SG-Security-Reader-ZSP' `
            -ExpectedMarker $expectedMarker
        $targets += @{
            Type = 'group'
            EntitySet = 'groups'
            Id = [string]$manifest.security_reader_group_id
            Url = "https://graph.microsoft.com/v1.0/groups/$($manifest.security_reader_group_id)"
        }
    }

    $expectedApplicationName = "$($manifest.project_name)-backup-sp"
    $application = Get-GraphObjectByExactId `
        -EntitySet applications `
        -ObjectId ([string]$manifest.backup_app_object_id) `
        -Select 'id,appId,displayName,notes,tags'
    if ($application) {
        if ([string]$application.displayName -cne $expectedApplicationName -or
            -not [string]::Equals([string]$application.appId, [string]$manifest.backup_service_principal_app_id, [System.StringComparison]::OrdinalIgnoreCase) -or
            [string]$application.notes -cne $expectedMarker -or
            @($application.tags) -notcontains 'nine-lives-zsp:v1') {
            throw 'Backup application identity or provenance does not match the manifest.'
        }
        $targets += @{
            Type = 'application'
            EntitySet = 'applications'
            Id = [string]$manifest.backup_app_object_id
            Url = "https://graph.microsoft.com/v1.0/applications/$($manifest.backup_app_object_id)"
        }
    }

    $servicePrincipal = Get-GraphObjectByExactId `
        -EntitySet servicePrincipals `
        -ObjectId ([string]$manifest.backup_service_principal_id) `
        -Select 'id,appId,displayName'
    if ($servicePrincipal) {
        if ([string]$servicePrincipal.displayName -cne $expectedApplicationName -or
            -not [string]::Equals([string]$servicePrincipal.appId, [string]$manifest.backup_service_principal_app_id, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'Backup service-principal identity does not match the manifest.'
        }
        $targets = @(@{
            Type = 'service principal'
            EntitySet = 'servicePrincipals'
            Id = [string]$manifest.backup_service_principal_id
            Url = "https://graph.microsoft.com/v1.0/servicePrincipals/$($manifest.backup_service_principal_id)"
        }) + $targets
    }
}

if ($WhatIfPreference) {
    foreach ($target in $targets) {
        $null = $PSCmdlet.ShouldProcess("$($target.Type) $($target.Id)", 'Delete exact provenance-verified Entra object')
    }
    if ($DestroyAzureResources -and $resourceGroupExists) {
        $null = $PSCmdlet.ShouldProcess($expectedResourceGroupId, 'Delete exact owner-tagged ZSP lab resource group')
    }
    Write-Host 'Cleanup preview completed; no resources or manifest files were changed.' -ForegroundColor Yellow
    return
}

$deleteDeclined = $false
foreach ($target in $targets) {
    if ($PSCmdlet.ShouldProcess("$($target.Type) $($target.Id)", 'Delete exact provenance-verified Entra object')) {
        az rest --method DELETE --url $target.Url --output none
        $deleteExitCode = $LASTEXITCODE
        Assert-AzSucceeded -ExitCode $deleteExitCode -Operation "Delete exact $($target.Type) '$($target.Id)'"
    }
    else {
        $deleteDeclined = $true
    }
}
if ($deleteDeclined) {
    throw 'One or more exact Entra deletions were declined. Azure deletion was not started and the manifest was retained.'
}

# Confirm exact Entra IDs are absent before an Azure resource-group delete.
if ($targets.Count -gt 0) {
    $remainingTargets = @($targets)
    for ($attempt = 1; $attempt -le 5 -and $remainingTargets.Count -gt 0; $attempt++) {
        $remainingTargets = @($remainingTargets | Where-Object {
            $target = $_
            $object = Get-GraphObjectByExactId `
                -EntitySet $target.EntitySet `
                -ObjectId $target.Id `
                -Select 'id'
            return $null -ne $object
        })
        if ($remainingTargets.Count -gt 0 -and $attempt -lt 5) {
            Start-Sleep -Seconds 2
        }
    }
    if ($remainingTargets.Count -gt 0) {
        throw 'One or more exact Entra objects still exist after delete requests. Azure deletion was not started and the manifest was retained.'
    }
}

if ($DestroyAzureResources -and $resourceGroupExists) {
    if (-not $PSCmdlet.ShouldProcess($expectedResourceGroupId, 'Delete exact owner-tagged ZSP lab resource group')) {
        throw 'Azure resource-group deletion was declined. The manifest was retained.'
    }
    az group delete `
        --subscription $manifest.subscription_id `
        --name $manifest.resource_group_name `
        --yes `
        --no-wait
    $groupDeleteExitCode = $LASTEXITCODE
    Assert-AzSucceeded -ExitCode $groupDeleteExitCode -Operation "Delete exact resource group '$expectedResourceGroupId'"
    Write-Host 'Exact cleanup requests succeeded. The manifest was retained for asynchronous Azure deletion verification.' -ForegroundColor Green
    return
}

if ($resourceGroupExists) {
    Write-Host 'Exact Entra cleanup completed. The owner-tagged Azure resource group and manifest were retained.' -ForegroundColor Green
    return
}

if ($PSCmdlet.ShouldProcess($ManifestPath, 'Remove manifest after every recorded resource is confirmed absent')) {
    Remove-Item -LiteralPath $ManifestPath -Force
    Write-Host 'Cleanup completed: every manifest-recorded resource is absent and the manifest was removed.' -ForegroundColor Green
}
else {
    Write-Host 'Every manifest-recorded resource is absent; the manifest was retained by request.' -ForegroundColor Yellow
}
