# Read-only validation shared by deployment configuration and smoke-test clients.
# Public Azure only. No credential-bearing request follows a redirect.
function Get-StrictHttpsOrigin {
    param([Parameter(Mandatory)][string]$Value, [Parameter(Mandatory)][string]$HostPattern)
    $parsed = $null
    if (-not [uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$parsed) -or
        $Value -cne $Value.Trim() -or $Value.Contains('\') -or $Value.Contains('%') -or
        $parsed.Scheme -cne 'https' -or $parsed.Port -ne 443 -or
        $parsed.UserInfo -or $parsed.Query -or $parsed.Fragment -or
        $parsed.AbsolutePath -cne '/' -or $parsed.DnsSafeHost -notmatch $HostPattern) {
        throw 'Credential destination must be an exact trusted HTTPS origin without credentials, path, query, or fragment.'
    }
    return 'https://' + $parsed.DnsSafeHost.ToLowerInvariant()
}

function Read-AzureMetadata {
    param([Parameter(Mandatory)][string[]]$Arguments)
    $global:LASTEXITCODE = 0
    $raw = & az @Arguments --output json 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'Azure metadata lookup failed; no application credential was sent.' }
    try { return ($raw | ConvertFrom-Json -ErrorAction Stop) }
    catch { throw 'Azure metadata was not valid JSON; no application credential was sent.' }
}

function Get-OwnedFunctionOrigin {
    param([Parameter(Mandatory)][string]$FunctionAppUrl,
          [Parameter(Mandatory)][string]$FunctionAppResourceId,
          [Parameter(Mandatory)][string]$ManifestPath)
    $origin = Get-StrictHttpsOrigin $FunctionAppUrl '^[a-z0-9-]+(?:\.[a-z0-9-]+)*\.azurewebsites\.net$'
    $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json -ErrorAction Stop
    $account = Read-AzureMetadata @('account', 'show')
    if ($manifest.schema_version -ne 2 -or $manifest.status -notin @('azure_deployed', 'identities_configured', 'deployed_unvalidated', 'validated') -or
        $manifest.azure_owner_marker -cne 'nine-lives-zsp:azure:v1' -or
        $manifest.deployment_id -notmatch '^[0-9a-fA-F-]{36}$' -or
        $manifest.tenant_id -ine $account.tenantId -or $manifest.subscription_id -ine $account.id -or
        $manifest.resource_group_id -ine "/subscriptions/$($account.id)/resourceGroups/$($manifest.resource_group_name)" -or
        $manifest.provenance_marker -cne "nine-lives-zsp:v1;tenant=$($account.tenantId);project=$($manifest.project_name)") {
        throw 'Function credential destination does not match the deployment manifest and active Azure account.'
    }
    $expectedPrefix = [regex]::Escape([string]$manifest.resource_group_id) + '/providers/Microsoft.Web/sites/'
    if ($FunctionAppResourceId -notmatch "^${expectedPrefix}[a-zA-Z0-9-]+$") {
        throw 'Function resource ID is outside the manifest-owned resource group.'
    }
    $group = Read-AzureMetadata @('group', 'show', '--name', [string]$manifest.resource_group_name)
    if ($group.id -ine $manifest.resource_group_id -or $group.tags.'nlzt-owner' -cne $manifest.azure_owner_marker -or
        $group.tags.'nlzt-deployment' -cne $manifest.deployment_id) {
        throw 'Live resource-group ownership differs from the deployment manifest.'
    }
    $app = Read-AzureMetadata @('resource', 'show', '--ids', $FunctionAppResourceId, '--api-version', '2023-12-01')
    if ($app.id -ine $FunctionAppResourceId -or -not $app.properties.defaultHostName) {
        throw 'The exact Function resource hostname could not be verified.'
    }
    $liveOrigin = Get-StrictHttpsOrigin ('https://' + $app.properties.defaultHostName) '^[a-z0-9-]+(?:\.[a-z0-9-]+)*\.azurewebsites\.net$'
    if ($origin -cne $liveOrigin) { throw 'Function URL differs from the exact ARM resource hostname.' }
    return $origin
}

function Get-PrivateStatusUri {
    param([Parameter(Mandatory)][string]$Value, [Parameter(Mandatory)][string]$Origin,
          [Parameter(Mandatory)][string]$InstanceId)
    if ($InstanceId -cnotmatch '^[A-Za-z0-9_-]{1,100}$') { throw 'Invalid lifecycle instance ID.' }
    $expected = "$Origin/api/access-status/$InstanceId"
    if ($Value -cne $expected) { throw 'Status URI is outside the authenticated read-only lifecycle route.' }
    return $expected
}

function Get-VerifiedIngestionEndpoint {
    param([Parameter(Mandatory)][string]$Endpoint,
          [Parameter(Mandatory)][string]$DceResourceId,
          [Parameter(Mandatory)][string]$ResourceGroupName,
          [Parameter(Mandatory)][string]$RuleId)
    $origin = Get-StrictHttpsOrigin $Endpoint '^[a-z0-9-]+\.[a-z0-9-]+\.ingest\.monitor\.azure\.com$'
    if ($RuleId -cnotmatch '^dcr-[a-fA-F0-9]{32}$') { throw 'DCR immutable ID must contain 32 hexadecimal characters.' }
    $account = Read-AzureMetadata @('account', 'show')
    $prefix = [regex]::Escape("/subscriptions/$($account.id)/resourceGroups/$ResourceGroupName/providers/Microsoft.Insights/dataCollectionEndpoints/")
    if ($DceResourceId -notmatch "^${prefix}[a-zA-Z0-9-]+$") { throw 'DCE resource ID is outside the active subscription and resource group.' }
    $dce = Read-AzureMetadata @('resource', 'show', '--ids', $DceResourceId, '--api-version', '2022-06-01')
    if ($dce.id -ine $DceResourceId -or $dce.properties.logsIngestion.endpoint -cne $origin) {
        throw 'DCR endpoint differs from the exact Azure Monitor resource endpoint.'
    }
    return $origin
}
