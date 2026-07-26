#Requires -Version 7.0
<#
.SYNOPSIS
    Creates Entra ID objects for Zero Standing Privilege lab.

.DESCRIPTION
    Creates the following Entra ID objects with retry logic for eventual consistency:
    - SG-Intune-Admins-ZSP: Security group for Intune Administrator role
    - SG-Security-Reader-ZSP: Security group for Security Reader role
    - Activates and assigns directory roles to groups
    - Backup service principal with zero initial permissions

.PARAMETER ProjectName
    Project name for resource naming.

.PARAMETER MaxRetries
    Maximum retry attempts for propagation delays. Default: 10

.PARAMETER RetryDelaySeconds
    Seconds to wait between retries. Default: 10

.PARAMETER ExpectedIntuneAdminGroupId
    Object ID created by an earlier successful run. Required with every other
    Expected*ObjectId parameter when reusing existing Entra objects.

.PARAMETER ExpectedSecurityReaderGroupId
    Object ID created by an earlier successful run.

.PARAMETER ExpectedBackupAppObjectId
    Application registration object ID (not its client/application ID) created
    by an earlier successful run.

.PARAMETER ExpectedBackupSpObjectId
    Service principal object ID created by an earlier successful run.

.OUTPUTS
    Key=Value pairs for use by other scripts:
    - INTUNE_ADMIN_GROUP_ID
    - SECURITY_READER_GROUP_ID
    - ENTRA_TENANT_ID
    - BACKUP_APP_OBJECT_ID
    - BACKUP_SP_OBJECT_ID
    - BACKUP_SP_CLIENT_ID
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9-]+$')]
    [ValidateLength(3, 20)]
    [string]$ProjectName,

    [Parameter()]
    [int]$MaxRetries = 10,

    [Parameter()]
    [int]$RetryDelaySeconds = 10,

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

# Well-known directory role template IDs
$IntuneAdminRoleTemplateId = '3a2c62db-5318-420d-8d74-23affee5d9d5'
$SecurityReaderRoleTemplateId = '5d6b6bb7-de71-4623-b4af-96380a352509'

function Wait-ForObject {
    param(
        [string]$ObjectType,
        [string]$ObjectId,
        [int]$MaxRetries,
        [int]$RetryDelaySeconds
    )

    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            switch ($ObjectType) {
                'group' {
                    $result = az ad group show --group $ObjectId --output json 2>$null | ConvertFrom-Json
                }
                'sp' {
                    $result = az ad sp show --id $ObjectId --output json 2>$null | ConvertFrom-Json
                }
                'app' {
                    $result = az ad app show --id $ObjectId --output json 2>$null | ConvertFrom-Json
                }
            }
            if ($result) {
                return $true
            }
        }
        catch {
            # Object not yet available
        }

        if ($i -lt $MaxRetries) {
            Write-Host "    Waiting for $ObjectType to propagate (attempt $i/$MaxRetries)..." -ForegroundColor Yellow
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }

    return $false
}

function Resolve-ExistingDirectoryObject {
    <#
    .SYNOPSIS
        Resolves an existing object only when its immutable ID was supplied.

    .DESCRIPTION
        Display names are not unique in Entra ID. A single untrusted name match
        is therefore a collision, not proof that this lab owns the object. More
        than one exact match is always ambiguous, even when one ID is expected.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowEmptyCollection()]
        [object[]]$Candidates = @(),

        [Parameter(Mandatory)]
        [string]$DisplayName,

        [Parameter()]
        [string]$ExpectedObjectId,

        [Parameter(Mandatory)]
        [string]$ObjectKind
    )

    $exactMatches = @(
        $Candidates | Where-Object {
            $_ -and [string]::Equals(
                [string]$_.displayName,
                $DisplayName,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        }
    )

    if ($exactMatches.Count -gt 1) {
        $ids = ($exactMatches | ForEach-Object { [string]$_.id }) -join ', '
        throw "Display-name collision: multiple $ObjectKind objects are named '$DisplayName' ($ids). Refusing to choose one."
    }

    if ($exactMatches.Count -eq 0) {
        if (-not [string]::IsNullOrWhiteSpace($ExpectedObjectId)) {
            throw "Expected $ObjectKind '$DisplayName' with object ID '$ExpectedObjectId', but no exact name match exists in this tenant."
        }
        return $null
    }

    $candidate = $exactMatches[0]
    if ([string]::IsNullOrWhiteSpace($ExpectedObjectId)) {
        throw "Untrusted display-name collision: $ObjectKind '$DisplayName' already exists with object ID '$($candidate.id)'. Refusing to auto-adopt it; supply the complete Expected*ObjectId set from the original deployment."
    }

    if (-not [string]::Equals(
            [string]$candidate.id,
            $ExpectedObjectId,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
        throw "Object-ID mismatch for $ObjectKind '$DisplayName': expected '$ExpectedObjectId', found '$($candidate.id)'."
    }

    return $candidate
}

function Get-DirectoryObjectsByDisplayName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('group', 'application', 'servicePrincipal')]
        [string]$DirectoryObjectType,

        [Parameter(Mandatory)]
        [string]$DisplayName
    )

    switch ($DirectoryObjectType) {
        'group' {
            $results = @(
                az ad group list --display-name $DisplayName --output json 2>$null | ConvertFrom-Json
            )
        }
        'application' {
            $results = @(
                az ad app list --display-name $DisplayName --all --output json 2>$null | ConvertFrom-Json
            )
        }
        'servicePrincipal' {
            $results = @(
                az ad sp list --display-name $DisplayName --all --output json 2>$null | ConvertFrom-Json
            )
        }
    }

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to search for $DirectoryObjectType objects named '$DisplayName'."
    }
    return $results
}

function Wait-ForExpectedDirectoryObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('group', 'application', 'servicePrincipal')]
        [string]$DirectoryObjectType,

        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][string]$ExpectedObjectId,
        [Parameter(Mandatory)][int]$MaxRetries,
        [Parameter(Mandatory)][int]$RetryDelaySeconds
    )

    $objectKind = switch ($DirectoryObjectType) {
        'group' { 'group' }
        'application' { 'application' }
        'servicePrincipal' { 'service principal' }
    }
    $lastError = $null

    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            $candidates = @(
                Get-DirectoryObjectsByDisplayName `
                    -DirectoryObjectType $DirectoryObjectType `
                    -DisplayName $DisplayName
            )
            return Resolve-ExistingDirectoryObject `
                -Candidates $candidates `
                -DisplayName $DisplayName `
                -ExpectedObjectId $ExpectedObjectId `
                -ObjectKind $objectKind
        }
        catch {
            $lastError = $_
            # Ambiguity and identity mismatch can never be fixed by waiting.
            if ($_.Exception.Message -match 'Display-name collision|Object-ID mismatch|Untrusted display-name collision') {
                throw
            }
        }

        if ($i -lt $MaxRetries) {
            Write-Host "    Waiting for $objectKind name lookup to propagate (attempt $i/$MaxRetries)..." -ForegroundColor Yellow
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }

    throw "Expected $objectKind '$DisplayName' with ID '$ExpectedObjectId' did not become uniquely discoverable. Last error: $($lastError.Exception.Message)"
}

function Get-GraphDirectoryObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('groups', 'applications', 'servicePrincipals')]
        [string]$Collection,

        [Parameter(Mandatory)]
        [string]$ObjectId,

        [Parameter(Mandatory)]
        [string]$Select
    )

    $result = az rest --method GET `
        --uri "https://graph.microsoft.com/v1.0/$Collection/${ObjectId}?`$select=$Select" `
        --output json 2>$null | ConvertFrom-Json
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0 -or -not $result -or -not $result.id) {
        throw "Unable to read $Collection object '$ObjectId' from Microsoft Graph."
    }
    return $result
}

function Assert-ZspGroupIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ObjectId,
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][string]$MailNickname,
        [Parameter(Mandatory)][string]$ProvenanceMarker
    )

    $group = Get-GraphDirectoryObject `
        -Collection 'groups' `
        -ObjectId $ObjectId `
        -Select 'id,displayName,description,mailEnabled,mailNickname,securityEnabled,isAssignableToRole'

    if (-not [string]::Equals([string]$group.id, $ObjectId, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Microsoft Graph returned the wrong group object for '$ObjectId'."
    }
    if (-not [string]::Equals([string]$group.displayName, $DisplayName, [System.StringComparison]::Ordinal)) {
        throw "Group '$ObjectId' does not have the expected display name '$DisplayName'."
    }
    if (-not [string]::Equals([string]$group.mailNickname, $MailNickname, [System.StringComparison]::Ordinal)) {
        throw "Group '$ObjectId' does not have the expected mail nickname '$MailNickname'."
    }
    if (-not ([string]$group.description).Contains("[$ProvenanceMarker]", [System.StringComparison]::Ordinal)) {
        throw "Group '$ObjectId' is missing the expected tenant/project provenance marker. Refusing to use it."
    }
    if ($null -eq $group.mailEnabled -or [bool]$group.mailEnabled) {
        throw "Group '$ObjectId' must be mail-disabled."
    }
    if (-not [bool]$group.securityEnabled -or -not [bool]$group.isAssignableToRole) {
        throw "Group '$ObjectId' must be a role-assignable security group."
    }

    return $group
}

function Assert-NoDirectGroupMembers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$MembershipResponse,
        [Parameter(Mandatory)][string]$ObjectId,
        [Parameter(Mandatory)][string]$DisplayName
    )

    $valueProperty = $MembershipResponse.PSObject.Properties['value']
    if ($null -eq $valueProperty) {
        throw "Microsoft Graph returned an invalid membership response for group '$DisplayName' ($ObjectId)."
    }

    $directMembers = @($valueProperty.Value)
    if ($directMembers.Count -gt 0) {
        $memberIds = ($directMembers | ForEach-Object { [string]$_.id }) -join ', '
        throw "Privileged ZSP group '$DisplayName' ($ObjectId) contains direct member(s): $memberIds. Refusing to assign or reuse its directory role; revoke all active grants first."
    }
}

function Assert-ZspGroupHasNoDirectMembers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ObjectId,
        [Parameter(Mandatory)][string]$DisplayName
    )

    $membershipResponse = az rest --method GET `
        --uri "https://graph.microsoft.com/v1.0/groups/${ObjectId}/members?`$select=id&`$top=1" `
        --output json 2>$null | ConvertFrom-Json
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0 -or -not $membershipResponse) {
        throw "Unable to verify that privileged ZSP group '$DisplayName' ($ObjectId) has no direct members."
    }

    Assert-NoDirectGroupMembers `
        -MembershipResponse $membershipResponse `
        -ObjectId $ObjectId `
        -DisplayName $DisplayName
}

function Assert-ZspApplicationIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ObjectId,
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][string]$ProvenanceMarker,
        [Parameter(Mandatory)][string]$ProvenanceTag
    )

    $application = Get-GraphDirectoryObject `
        -Collection 'applications' `
        -ObjectId $ObjectId `
        -Select 'id,appId,displayName,notes,signInAudience,tags'

    if (-not [string]::Equals([string]$application.id, $ObjectId, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Microsoft Graph returned the wrong application object for '$ObjectId'."
    }
    if (-not [string]::Equals([string]$application.displayName, $DisplayName, [System.StringComparison]::Ordinal)) {
        throw "Application '$ObjectId' does not have the expected display name '$DisplayName'."
    }
    if (-not [string]::Equals([string]$application.notes, $ProvenanceMarker, [System.StringComparison]::Ordinal)) {
        throw "Application '$ObjectId' is missing the expected tenant/project provenance marker. Refusing to use it."
    }
    if (@($application.tags) -notcontains $ProvenanceTag) {
        throw "Application '$ObjectId' is missing the expected ZSP ownership tag."
    }
    if ($application.signInAudience -ne 'AzureADMyOrg') {
        throw "Application '$ObjectId' is not single-tenant (AzureADMyOrg)."
    }
    $parsedAppId = [guid]::Empty
    if (-not [guid]::TryParse([string]$application.appId, [ref]$parsedAppId)) {
        throw "Application '$ObjectId' has an invalid client/application ID."
    }

    return $application
}

function Assert-ZspServicePrincipalIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ObjectId,
        [Parameter(Mandatory)][string]$ApplicationId,
        [Parameter(Mandatory)][string]$DisplayName
    )

    $servicePrincipal = Get-GraphDirectoryObject `
        -Collection 'servicePrincipals' `
        -ObjectId $ObjectId `
        -Select 'id,appId,displayName,servicePrincipalType'

    if (-not [string]::Equals([string]$servicePrincipal.id, $ObjectId, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Microsoft Graph returned the wrong service principal object for '$ObjectId'."
    }
    if (-not [string]::Equals([string]$servicePrincipal.appId, $ApplicationId, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Service principal '$ObjectId' is not linked to the expected application '$ApplicationId'."
    }
    if (-not [string]::Equals([string]$servicePrincipal.displayName, $DisplayName, [System.StringComparison]::Ordinal)) {
        throw "Service principal '$ObjectId' does not have the expected display name '$DisplayName'."
    }
    if ($servicePrincipal.servicePrincipalType -ne 'Application') {
        throw "Service principal '$ObjectId' has unexpected type '$($servicePrincipal.servicePrincipalType)'."
    }

    return $servicePrincipal
}

try {
Write-Host "Creating Entra ID objects..." -ForegroundColor Yellow

$intuneGroupName = "SG-Intune-Admins-ZSP"
$intuneGroupMailNickname = 'SG-Intune-Admins-ZSP'
$securityGroupName = "SG-Security-Reader-ZSP"
$securityGroupMailNickname = 'SG-Security-Reader-ZSP'
$backupAppName = "$ProjectName-backup-sp"

$tenantId = (az account show --query tenantId --output tsv 2>$null).Trim()
$tenantQueryExitCode = $LASTEXITCODE
$parsedTenantId = [guid]::Empty
if ($tenantQueryExitCode -ne 0 -or -not [guid]::TryParse($tenantId, [ref]$parsedTenantId)) {
    throw "Unable to determine a valid Entra tenant ID from the active Azure CLI account."
}

$provenanceTag = 'nine-lives-zsp:v1'
$provenanceMarker = "$provenanceTag;tenant=$tenantId;project=$ProjectName"

# A rerun must provide the complete immutable identity set. Mixing trusted IDs
# with name-based discovery could still connect newly-created objects to an
# attacker-controlled or unrelated object.
$expectedObjectIds = @(
    $ExpectedIntuneAdminGroupId,
    $ExpectedSecurityReaderGroupId,
    $ExpectedBackupAppObjectId,
    $ExpectedBackupSpObjectId
)
$providedExpectedObjectIds = @($expectedObjectIds | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
if ($providedExpectedObjectIds.Count -ne 0 -and $providedExpectedObjectIds.Count -ne $expectedObjectIds.Count) {
    throw "For a safe rerun, supply all four Expected*ObjectId parameters together. Partial object adoption is not allowed."
}

# Preflight every display name before creating anything. Azure CLI's
# --display-name option can return prefix matches, so the resolver performs its
# own ordinal-ignore-case exact comparison and rejects ambiguity.
Write-Host "  Preflighting Entra display names and provenance..." -ForegroundColor Cyan
$intuneGroupCandidates = @(
    Get-DirectoryObjectsByDisplayName -DirectoryObjectType 'group' -DisplayName $intuneGroupName
)
$securityGroupCandidates = @(
    Get-DirectoryObjectsByDisplayName -DirectoryObjectType 'group' -DisplayName $securityGroupName
)
$backupAppCandidates = @(
    Get-DirectoryObjectsByDisplayName -DirectoryObjectType 'application' -DisplayName $backupAppName
)
$backupSpCandidates = @(
    Get-DirectoryObjectsByDisplayName -DirectoryObjectType 'servicePrincipal' -DisplayName $backupAppName
)

$existingIntuneGroup = Resolve-ExistingDirectoryObject `
    -Candidates $intuneGroupCandidates `
    -DisplayName $intuneGroupName `
    -ExpectedObjectId $ExpectedIntuneAdminGroupId `
    -ObjectKind 'group'
$existingSecurityGroup = Resolve-ExistingDirectoryObject `
    -Candidates $securityGroupCandidates `
    -DisplayName $securityGroupName `
    -ExpectedObjectId $ExpectedSecurityReaderGroupId `
    -ObjectKind 'group'
$existingBackupApp = Resolve-ExistingDirectoryObject `
    -Candidates $backupAppCandidates `
    -DisplayName $backupAppName `
    -ExpectedObjectId $ExpectedBackupAppObjectId `
    -ObjectKind 'application'
$existingBackupSp = Resolve-ExistingDirectoryObject `
    -Candidates $backupSpCandidates `
    -DisplayName $backupAppName `
    -ExpectedObjectId $ExpectedBackupSpObjectId `
    -ObjectKind 'service principal'

# Validate every trusted existing object, including the marker that binds it to
# this tenant/project and the immutable application-to-SP relationship, before
# any directory roles or permissions are assigned.
if ($providedExpectedObjectIds.Count -eq $expectedObjectIds.Count) {
    $intuneGroupId = [string]$existingIntuneGroup.id
    $securityGroupId = [string]$existingSecurityGroup.id
    $backupAppObjectId = [string]$existingBackupApp.id
    $backupSpObjectId = [string]$existingBackupSp.id

    $null = Assert-ZspGroupIdentity `
        -ObjectId $intuneGroupId `
        -DisplayName $intuneGroupName `
        -MailNickname $intuneGroupMailNickname `
        -ProvenanceMarker $provenanceMarker
    $null = Assert-ZspGroupIdentity `
        -ObjectId $securityGroupId `
        -DisplayName $securityGroupName `
        -MailNickname $securityGroupMailNickname `
        -ProvenanceMarker $provenanceMarker
    $verifiedBackupApp = Assert-ZspApplicationIdentity `
        -ObjectId $backupAppObjectId `
        -DisplayName $backupAppName `
        -ProvenanceMarker $provenanceMarker `
        -ProvenanceTag $provenanceTag
    $backupAppId = [string]$verifiedBackupApp.appId
    $null = Assert-ZspServicePrincipalIdentity `
        -ObjectId $backupSpObjectId `
        -ApplicationId $backupAppId `
        -DisplayName $backupAppName
}

# Create or use the explicitly verified Intune Admins ZSP group.
Write-Host "  Preparing $intuneGroupName group..." -ForegroundColor Cyan
if ($existingIntuneGroup) {
    Write-Host "    Verified existing group: $intuneGroupId" -ForegroundColor Green
}
else {
    $groupBody = @{
        displayName = $intuneGroupName
        description = "ZSP group for Intune administration. Members are added/removed automatically by ZSP Gateway. Do not modify manually. [$provenanceMarker]"
        mailEnabled = $false
        mailNickname = $intuneGroupMailNickname
        securityEnabled = $true
        isAssignableToRole = $true
    } | ConvertTo-Json -Compress

    $intuneGroup = az rest --method POST `
        --uri "https://graph.microsoft.com/v1.0/groups" `
        --headers "Content-Type=application/json" `
        --body (New-JsonBodyFile $groupBody) `
        --output json 2>$null | ConvertFrom-Json

    if ($LASTEXITCODE -ne 0 -or -not $intuneGroup.id) {
        throw "Failed to create Intune Admins group"
    }
    $intuneGroupId = $intuneGroup.id
    Write-Host "    Created: $intuneGroupId" -ForegroundColor Green

    # Wait for propagation
    if (-not (Wait-ForObject -ObjectType 'group' -ObjectId $intuneGroupId -MaxRetries $MaxRetries -RetryDelaySeconds $RetryDelaySeconds)) {
        throw "Group failed to propagate: $intuneGroupId"
    }

    $null = Wait-ForExpectedDirectoryObject `
        -DirectoryObjectType 'group' `
        -DisplayName $intuneGroupName `
        -ExpectedObjectId $intuneGroupId `
        -MaxRetries $MaxRetries `
        -RetryDelaySeconds $RetryDelaySeconds
    $null = Assert-ZspGroupIdentity `
        -ObjectId $intuneGroupId `
        -DisplayName $intuneGroupName `
        -MailNickname $intuneGroupMailNickname `
        -ProvenanceMarker $provenanceMarker
}

# Create or use the explicitly verified Security Reader ZSP group.
Write-Host "  Preparing $securityGroupName group..." -ForegroundColor Cyan
if ($existingSecurityGroup) {
    Write-Host "    Verified existing group: $securityGroupId" -ForegroundColor Green
}
else {
    $groupBody = @{
        displayName = $securityGroupName
        description = "ZSP group for Security Reader access. Members are added/removed automatically by ZSP Gateway. [$provenanceMarker]"
        mailEnabled = $false
        mailNickname = $securityGroupMailNickname
        securityEnabled = $true
        isAssignableToRole = $true
    } | ConvertTo-Json -Compress

    $securityGroup = az rest --method POST `
        --uri "https://graph.microsoft.com/v1.0/groups" `
        --headers "Content-Type=application/json" `
        --body (New-JsonBodyFile $groupBody) `
        --output json 2>$null | ConvertFrom-Json

    if ($LASTEXITCODE -ne 0 -or -not $securityGroup.id) {
        throw "Failed to create Security Reader group"
    }
    $securityGroupId = $securityGroup.id
    Write-Host "    Created: $securityGroupId" -ForegroundColor Green

    # Wait for propagation
    if (-not (Wait-ForObject -ObjectType 'group' -ObjectId $securityGroupId -MaxRetries $MaxRetries -RetryDelaySeconds $RetryDelaySeconds)) {
        throw "Group failed to propagate: $securityGroupId"
    }

    $null = Wait-ForExpectedDirectoryObject `
        -DirectoryObjectType 'group' `
        -DisplayName $securityGroupName `
        -ExpectedObjectId $securityGroupId `
        -MaxRetries $MaxRetries `
        -RetryDelaySeconds $RetryDelaySeconds
    $null = Assert-ZspGroupIdentity `
        -ObjectId $securityGroupId `
        -DisplayName $securityGroupName `
        -MailNickname $securityGroupMailNickname `
        -ProvenanceMarker $provenanceMarker
}

# A provenance-valid group can still be unsafe if a prior or unauthorized grant
# remains active. Verify both groups are empty before assigning or reusing their
# privileged directory roles.
Write-Host "  Verifying privileged ZSP groups have no direct members..." -ForegroundColor Cyan
Assert-ZspGroupHasNoDirectMembers -ObjectId $intuneGroupId -DisplayName $intuneGroupName
Assert-ZspGroupHasNoDirectMembers -ObjectId $securityGroupId -DisplayName $securityGroupName

# Activate and assign Intune Administrator role
Write-Host "  Activating Intune Administrator role..." -ForegroundColor Cyan
$intuneRole = az rest --method GET `
    --uri "https://graph.microsoft.com/v1.0/directoryRoles?`$filter=roleTemplateId eq '$IntuneAdminRoleTemplateId'" `
    --output json 2>$null | ConvertFrom-Json

if (-not $intuneRole.value -or $intuneRole.value.Count -eq 0) {
    # Activate the role
    $activateBody = @{ roleTemplateId = $IntuneAdminRoleTemplateId } | ConvertTo-Json -Compress
    $intuneRole = az rest --method POST `
        --uri "https://graph.microsoft.com/v1.0/directoryRoles" `
        --headers "Content-Type=application/json" `
        --body (New-JsonBodyFile $activateBody) `
        --output json 2>$null | ConvertFrom-Json

    if (-not $intuneRole.id) {
        throw "Failed to activate Intune Administrator role"
    }
    $intuneRoleId = $intuneRole.id
    Write-Host "    Activated role: $intuneRoleId" -ForegroundColor Green
}
else {
    $intuneRoleId = $intuneRole.value[0].id
    Write-Host "    Role already active: $intuneRoleId" -ForegroundColor Green
}

# Assign group to Intune Administrator role
Write-Host "  Assigning group to Intune Administrator role..." -ForegroundColor Cyan
$existingIntuneMember = az rest --method GET `
    --uri "https://graph.microsoft.com/v1.0/directoryRoles/$intuneRoleId/members?`$select=id" `
    --output json 2>$null | ConvertFrom-Json
$intuneMemberLookupExitCode = $LASTEXITCODE
$intuneMemberValueProperty = if ($existingIntuneMember) {
    $existingIntuneMember.PSObject.Properties['value']
}
else {
    $null
}
if (
    $intuneMemberLookupExitCode -ne 0 -or
    $null -eq $intuneMemberValueProperty -or
    $null -eq $intuneMemberValueProperty.Value
) {
    throw "Unable to verify the Intune Administrator role membership before assignment."
}

$existingIntuneMember = @(
    $existingIntuneMember.value | Where-Object {
        [string]::Equals([string]$_.id, $intuneGroupId, [System.StringComparison]::OrdinalIgnoreCase)
    }
)
if ($existingIntuneMember.Count -eq 0) {
    $memberBody = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$intuneGroupId" } | ConvertTo-Json -Compress
    az rest --method POST `
        --uri "https://graph.microsoft.com/v1.0/directoryRoles/$intuneRoleId/members/`$ref" `
        --headers "Content-Type=application/json" `
        --body (New-JsonBodyFile $memberBody) `
        --output none 2>$null
    $intuneMemberAssignmentExitCode = $LASTEXITCODE
    if ($intuneMemberAssignmentExitCode -ne 0) {
        throw "Failed to assign the Intune Administrator group to its directory role."
    }
    Write-Host "    Assignment created" -ForegroundColor Green
}
else {
    Write-Host "    Already assigned" -ForegroundColor Green
}

# Activate and assign Security Reader role
Write-Host "  Activating Security Reader role..." -ForegroundColor Cyan
$securityRole = az rest --method GET `
    --uri "https://graph.microsoft.com/v1.0/directoryRoles?`$filter=roleTemplateId eq '$SecurityReaderRoleTemplateId'" `
    --output json 2>$null | ConvertFrom-Json

if (-not $securityRole.value -or $securityRole.value.Count -eq 0) {
    # Activate the role
    $activateBody = @{ roleTemplateId = $SecurityReaderRoleTemplateId } | ConvertTo-Json -Compress
    $securityRole = az rest --method POST `
        --uri "https://graph.microsoft.com/v1.0/directoryRoles" `
        --headers "Content-Type=application/json" `
        --body (New-JsonBodyFile $activateBody) `
        --output json 2>$null | ConvertFrom-Json

    if (-not $securityRole.id) {
        throw "Failed to activate Security Reader role"
    }
    $securityRoleId = $securityRole.id
    Write-Host "    Activated role: $securityRoleId" -ForegroundColor Green
}
else {
    $securityRoleId = $securityRole.value[0].id
    Write-Host "    Role already active: $securityRoleId" -ForegroundColor Green
}

# Assign group to Security Reader role
Write-Host "  Assigning group to Security Reader role..." -ForegroundColor Cyan
$existingSecurityMember = az rest --method GET `
    --uri "https://graph.microsoft.com/v1.0/directoryRoles/$securityRoleId/members?`$select=id" `
    --output json 2>$null | ConvertFrom-Json
$securityMemberLookupExitCode = $LASTEXITCODE
$securityMemberValueProperty = if ($existingSecurityMember) {
    $existingSecurityMember.PSObject.Properties['value']
}
else {
    $null
}
if (
    $securityMemberLookupExitCode -ne 0 -or
    $null -eq $securityMemberValueProperty -or
    $null -eq $securityMemberValueProperty.Value
) {
    throw "Unable to verify the Security Reader role membership before assignment."
}

$existingSecurityMember = @(
    $existingSecurityMember.value | Where-Object {
        [string]::Equals([string]$_.id, $securityGroupId, [System.StringComparison]::OrdinalIgnoreCase)
    }
)
if ($existingSecurityMember.Count -eq 0) {
    $memberBody = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$securityGroupId" } | ConvertTo-Json -Compress
    az rest --method POST `
        --uri "https://graph.microsoft.com/v1.0/directoryRoles/$securityRoleId/members/`$ref" `
        --headers "Content-Type=application/json" `
        --body (New-JsonBodyFile $memberBody) `
        --output none 2>$null
    $securityMemberAssignmentExitCode = $LASTEXITCODE
    if ($securityMemberAssignmentExitCode -ne 0) {
        throw "Failed to assign the Security Reader group to its directory role."
    }
    Write-Host "    Assignment created" -ForegroundColor Green
}
else {
    Write-Host "    Already assigned" -ForegroundColor Green
}

# Create or use the explicitly verified backup application and service principal.
Write-Host "  Preparing backup application and service principal..." -ForegroundColor Cyan
if ($existingBackupApp) {
    Write-Host "    Verified existing application object: $backupAppObjectId" -ForegroundColor Green
    Write-Host "    Verified existing application/client ID: $backupAppId" -ForegroundColor Green
    Write-Host "    Verified existing SP object: $backupSpObjectId" -ForegroundColor Green
}
else {
    # Create a single-tenant application registration carrying a deterministic
    # marker that binds it to this tenant and project.
    $applicationBody = @{
        displayName = $backupAppName
        signInAudience = 'AzureADMyOrg'
        notes = $provenanceMarker
        tags = @($provenanceTag)
    } | ConvertTo-Json -Depth 4 -Compress

    $backupApp = az rest --method POST `
        --uri 'https://graph.microsoft.com/v1.0/applications' `
        --headers 'Content-Type=application/json' `
        --body (New-JsonBodyFile $applicationBody) `
        --output json 2>$null | ConvertFrom-Json

    if ($LASTEXITCODE -ne 0 -or -not $backupApp.id -or -not $backupApp.appId) {
        throw "Failed to create backup application"
    }
    $backupAppObjectId = [string]$backupApp.id
    $backupAppId = [string]$backupApp.appId
    Write-Host "    Created application object: $backupAppObjectId" -ForegroundColor Green
    Write-Host "    Created application/client ID: $backupAppId" -ForegroundColor Green

    # Wait for app to propagate
    if (-not (Wait-ForObject -ObjectType 'app' -ObjectId $backupAppId -MaxRetries $MaxRetries -RetryDelaySeconds $RetryDelaySeconds)) {
        throw "Application failed to propagate: $backupAppId"
    }

    $null = Wait-ForExpectedDirectoryObject `
        -DirectoryObjectType 'application' `
        -DisplayName $backupAppName `
        -ExpectedObjectId $backupAppObjectId `
        -MaxRetries $MaxRetries `
        -RetryDelaySeconds $RetryDelaySeconds
    $verifiedBackupApp = Assert-ZspApplicationIdentity `
        -ObjectId $backupAppObjectId `
        -DisplayName $backupAppName `
        -ProvenanceMarker $provenanceMarker `
        -ProvenanceTag $provenanceTag
    if (-not [string]::Equals([string]$verifiedBackupApp.appId, $backupAppId, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "The created application client ID changed during verification."
    }

    # Recheck the service-principal name immediately before creation. This
    # closes the window between the initial preflight and application creation.
    $preCreateSpMatches = @(
        Get-DirectoryObjectsByDisplayName -DirectoryObjectType 'servicePrincipal' -DisplayName $backupAppName
    )
    $null = Resolve-ExistingDirectoryObject `
        -Candidates $preCreateSpMatches `
        -DisplayName $backupAppName `
        -ObjectKind 'service principal'

    # Only appId is required. Provenance is established by the immutable appId
    # link to the application object verified above.
    $servicePrincipalBody = @{ appId = $backupAppId } | ConvertTo-Json -Compress
    $backupSp = az rest --method POST `
        --uri 'https://graph.microsoft.com/v1.0/servicePrincipals' `
        --headers 'Content-Type=application/json' `
        --body (New-JsonBodyFile $servicePrincipalBody) `
        --output json 2>$null | ConvertFrom-Json

    if ($LASTEXITCODE -ne 0 -or -not $backupSp.id) {
        throw "Failed to create backup service principal"
    }
    $backupSpObjectId = [string]$backupSp.id
    Write-Host "    Created SP: $backupSpObjectId" -ForegroundColor Green

    # Wait for SP to propagate
    if (-not (Wait-ForObject -ObjectType 'sp' -ObjectId $backupSpObjectId -MaxRetries $MaxRetries -RetryDelaySeconds $RetryDelaySeconds)) {
        throw "Service principal failed to propagate: $backupSpObjectId"
    }

    $null = Wait-ForExpectedDirectoryObject `
        -DirectoryObjectType 'servicePrincipal' `
        -DisplayName $backupAppName `
        -ExpectedObjectId $backupSpObjectId `
        -MaxRetries $MaxRetries `
        -RetryDelaySeconds $RetryDelaySeconds
    $null = Assert-ZspServicePrincipalIdentity `
        -ObjectId $backupSpObjectId `
        -ApplicationId $backupAppId `
        -DisplayName $backupAppName
}

Write-Host "Entra ID objects created successfully" -ForegroundColor Green

# Output configuration for other scripts
Write-Output "INTUNE_ADMIN_GROUP_ID=$intuneGroupId"
Write-Output "SECURITY_READER_GROUP_ID=$securityGroupId"
Write-Output "ENTRA_TENANT_ID=$tenantId"
Write-Output "BACKUP_APP_OBJECT_ID=$backupAppObjectId"
Write-Output "BACKUP_SP_OBJECT_ID=$backupSpObjectId"
Write-Output "BACKUP_SP_CLIENT_ID=$backupAppId"
}
finally {
    $script:_jsonTempFiles | ForEach-Object {
        Remove-Item $_ -Force -ErrorAction SilentlyContinue
    }
}

exit 0
