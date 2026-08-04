#Requires -Version 7.0
<#
.SYNOPSIS
    Grants Graph API and Azure RBAC permissions to the Function App managed identity.

.DESCRIPTION
    Grants the following permissions with admin consent:
    - GroupMember.ReadWrite.All (Graph API): Add/remove group members
    - Directory.Read.All (Graph API): Read directory objects
    - RoleManagement.ReadWrite.Directory (Graph API): Manage membership of role-assignable groups
    - User Access Administrator (Azure RBAC): Manage role assignments on resource group
    - Monitoring Metrics Publisher (Azure RBAC): Send audit logs to DCR

.PARAMETER FunctionAppPrincipalId
    Object ID of the Function App's managed identity.

.PARAMETER ResourceGroupId
    Resource ID of the resource group for RBAC assignment.

.PARAMETER DcrScope
    Resource ID of the Data Collection Rule for Monitoring Metrics Publisher role.

.PARAMETER MaxRetries
    Maximum retry attempts for propagation delays. Default: 5

.PARAMETER RetryDelaySeconds
    Seconds to wait between retries. Default: 10
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$FunctionAppPrincipalId,

    [Parameter(Mandatory)]
    [string]$ResourceGroupId,

    [Parameter()]
    [string]$DcrScope,

    [Parameter()]
    [int]$MaxRetries = 5,

    [Parameter()]
    [int]$RetryDelaySeconds = 10
)

$ErrorActionPreference = 'Stop'

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

function Assert-AzCommandSucceeded {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Operation
    )

    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "Azure CLI failed to $Operation (exit code $exitCode)."
    }
}

# Well-known IDs
$MsGraphAppId = '00000003-0000-0000-c000-000000000000'
$GroupMemberReadWriteAllId = '62a82d76-70ea-41e2-9197-370581804d09'
$DirectoryReadAllId = '7ab1d382-f21e-4acd-a863-ba3e13f7da61'
$RoleManagementReadWriteDirectoryId = '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8'
$UserAccessAdminRoleId = '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9'

Write-Host "Granting permissions to Function App managed identity..." -ForegroundColor Yellow

# Get Microsoft Graph service principal
Write-Host "  Looking up Microsoft Graph service principal..." -ForegroundColor Cyan
$msgraph = az ad sp show --id $MsGraphAppId --output json 2>$null | ConvertFrom-Json

if (-not $msgraph) {
    throw "Could not find Microsoft Graph service principal"
}
$msgraphObjectId = $msgraph.id
Write-Host "    Found: $msgraphObjectId" -ForegroundColor Green

# Grant GroupMember.ReadWrite.All
Write-Host "  Granting GroupMember.ReadWrite.All..." -ForegroundColor Cyan
$existingGroupPerm = az rest --method GET `
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$FunctionAppPrincipalId/appRoleAssignments" `
    --output json 2>$null | ConvertFrom-Json

$hasGroupPerm = $existingGroupPerm.value | Where-Object { $_.appRoleId -eq $GroupMemberReadWriteAllId }

if ($hasGroupPerm) {
    Write-Host "    Already granted" -ForegroundColor Green
}
else {
    $body = @{
        principalId = $FunctionAppPrincipalId
        resourceId = $msgraphObjectId
        appRoleId = $GroupMemberReadWriteAllId
    } | ConvertTo-Json -Compress

    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            az rest --method POST `
                --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$FunctionAppPrincipalId/appRoleAssignments" `
                --headers "Content-Type=application/json" `
                --body (New-JsonBodyFile $body) `
                --output none 2>$null
            Assert-AzCommandSucceeded -Operation 'grant GroupMember.ReadWrite.All'
            Write-Host "    Granted" -ForegroundColor Green
            break
        }
        catch {
            if ($i -eq $MaxRetries) {
                throw "Failed to grant GroupMember.ReadWrite.All after $MaxRetries attempts"
            }
            Write-Host "    Retry $i/$MaxRetries..." -ForegroundColor Yellow
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }
}

# Grant Directory.Read.All
Write-Host "  Granting Directory.Read.All..." -ForegroundColor Cyan
$hasDirectoryPerm = $existingGroupPerm.value | Where-Object { $_.appRoleId -eq $DirectoryReadAllId }

if ($hasDirectoryPerm) {
    Write-Host "    Already granted" -ForegroundColor Green
}
else {
    $body = @{
        principalId = $FunctionAppPrincipalId
        resourceId = $msgraphObjectId
        appRoleId = $DirectoryReadAllId
    } | ConvertTo-Json -Compress

    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            az rest --method POST `
                --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$FunctionAppPrincipalId/appRoleAssignments" `
                --headers "Content-Type=application/json" `
                --body (New-JsonBodyFile $body) `
                --output none 2>$null
            Assert-AzCommandSucceeded -Operation 'grant Directory.Read.All'
            Write-Host "    Granted" -ForegroundColor Green
            break
        }
        catch {
            if ($i -eq $MaxRetries) {
                throw "Failed to grant Directory.Read.All after $MaxRetries attempts"
            }
            Write-Host "    Retry $i/$MaxRetries..." -ForegroundColor Yellow
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }
}

# Grant RoleManagement.ReadWrite.Directory (required for role-assignable group membership)
#
# Trade-off, stated plainly: this is standing, tenant-wide privilege, and it is the
# one piece of standing privilege this lab does not eliminate. Graph requires it to
# change the membership of a role-assignable group - GroupMember.ReadWrite.All is
# not sufficient - so the gateway cannot do its job without it.
#
# What it means: this permission can assign any directory role, including Global
# Administrator. The lab moves standing privilege off *people* and into *one
# audited workload*; it does not make it disappear. Treat the Function App as a
# Tier 0 asset - its identity is as powerful as a standing Global Admin.
#
# In production, prefer PIM for Groups or Entra Entitlement Management, which
# provide the same just-in-time membership without a standing grant of this scope.
Write-Host "  Granting RoleManagement.ReadWrite.Directory..." -ForegroundColor Cyan
$hasRoleMgmtPerm = $existingGroupPerm.value | Where-Object { $_.appRoleId -eq $RoleManagementReadWriteDirectoryId }

if ($hasRoleMgmtPerm) {
    Write-Host "    Already granted" -ForegroundColor Green
}
else {
    $body = @{
        principalId = $FunctionAppPrincipalId
        resourceId = $msgraphObjectId
        appRoleId = $RoleManagementReadWriteDirectoryId
    } | ConvertTo-Json -Compress

    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            az rest --method POST `
                --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$FunctionAppPrincipalId/appRoleAssignments" `
                --headers "Content-Type=application/json" `
                --body (New-JsonBodyFile $body) `
                --output none 2>$null
            Assert-AzCommandSucceeded -Operation 'grant RoleManagement.ReadWrite.Directory'
            Write-Host "    Granted" -ForegroundColor Green
            break
        }
        catch {
            if ($i -eq $MaxRetries) {
                throw "Failed to grant RoleManagement.ReadWrite.Directory after $MaxRetries attempts"
            }
            Write-Host "    Retry $i/$MaxRetries..." -ForegroundColor Yellow
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }
}

# Grant User Access Administrator RBAC role on resource group
Write-Host "  Granting User Access Administrator on resource group..." -ForegroundColor Cyan
$existingRbac = az role assignment list `
    --assignee $FunctionAppPrincipalId `
    --scope $ResourceGroupId `
    --role "User Access Administrator" `
    --output json 2>$null | ConvertFrom-Json

if ($existingRbac -and $existingRbac.Count -gt 0) {
    Write-Host "    Already granted" -ForegroundColor Green
}
else {
    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            az role assignment create `
                --assignee-object-id $FunctionAppPrincipalId `
                --assignee-principal-type ServicePrincipal `
                --role "User Access Administrator" `
                --scope $ResourceGroupId `
                --output none 2>$null
            Assert-AzCommandSucceeded -Operation 'grant User Access Administrator'
            Write-Host "    Granted" -ForegroundColor Green
            break
        }
        catch {
            if ($i -eq $MaxRetries) {
                throw "Failed to grant User Access Administrator after $MaxRetries attempts"
            }
            Write-Host "    Retry $i/$MaxRetries..." -ForegroundColor Yellow
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }
}

# Grant Monitoring Metrics Publisher on DCR (for audit log ingestion)
if ($DcrScope) {
    Write-Host "  Granting Monitoring Metrics Publisher on DCR..." -ForegroundColor Cyan
    $existingMonitor = az role assignment list `
        --assignee $FunctionAppPrincipalId `
        --scope $DcrScope `
        --role "Monitoring Metrics Publisher" `
        --output json 2>$null | ConvertFrom-Json

    if ($existingMonitor -and $existingMonitor.Count -gt 0) {
        Write-Host "    Already granted" -ForegroundColor Green
    }
    else {
        for ($i = 1; $i -le $MaxRetries; $i++) {
            try {
                az role assignment create `
                    --assignee-object-id $FunctionAppPrincipalId `
                    --assignee-principal-type ServicePrincipal `
                    --role "Monitoring Metrics Publisher" `
                    --scope $DcrScope `
                    --output none 2>$null
                Assert-AzCommandSucceeded -Operation 'grant Monitoring Metrics Publisher'
                Write-Host "    Granted" -ForegroundColor Green
                break
            }
            catch {
                if ($i -eq $MaxRetries) {
                    throw "Failed to grant Monitoring Metrics Publisher after $MaxRetries attempts"
                }
                Write-Host "    Retry $i/$MaxRetries..." -ForegroundColor Yellow
                Start-Sleep -Seconds $RetryDelaySeconds
            }
        }
    }
}

# Cleanup temp files
$script:_jsonTempFiles | ForEach-Object { Remove-Item $_ -Force -ErrorAction SilentlyContinue }

Write-Host "Permissions granted successfully" -ForegroundColor Green
exit 0
