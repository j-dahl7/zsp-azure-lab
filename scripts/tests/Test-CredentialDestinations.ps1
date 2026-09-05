# Entirely offline: every Azure command is replaced by the local function below.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/../Credential-Destinations.ps1"
$subscription = '11111111-1111-4111-8111-111111111111'
$tenant = '22222222-2222-4222-8222-222222222222'
$deployment = '33333333-3333-4333-8333-333333333333'
$rg = "/subscriptions/$subscription/resourceGroups/test-rg"
$appId = "$rg/providers/Microsoft.Web/sites/test-lab"
$dceId = "$rg/providers/Microsoft.Insights/dataCollectionEndpoints/test-dce"
$endpoint = 'https://test-dce.eastus-1.ingest.monitor.azure.com'
$manifestPath = [IO.Path]::GetTempFileName()
$script:metadataFailure = $false
$script:ownerMismatch = $false
$script:hostMismatch = $false
$script:dceMismatch = $false
$script:calls = 0
function global:az {
    $script:calls++
    $global:LASTEXITCODE = if ($script:metadataFailure) { 71 } else { 0 }
    if ($script:metadataFailure) { return '{}' }
    if ($args[0] -eq 'account') { return (@{id=$subscription; tenantId=$tenant} | ConvertTo-Json) }
    if ($args[0] -eq 'group') {
        $owner = if ($script:ownerMismatch) { 'other' } else { 'nine-lives-zsp:azure:v1' }
        return (@{id=$rg; tags=@{'nlzt-owner'=$owner; 'nlzt-deployment'=$deployment}} | ConvertTo-Json)
    }
    if ($args[0] -eq 'resource' -and $args -contains $appId) {
        $hostname = if ($script:hostMismatch) { 'other.azurewebsites.net' } else { 'test-lab.azurewebsites.net' }
        return (@{id=$appId; properties=@{defaultHostName=$hostname}} | ConvertTo-Json)
    }
    if ($args[0] -eq 'resource' -and $args -contains $dceId) {
        $liveEndpoint = if ($script:dceMismatch) { 'https://other.eastus-1.ingest.monitor.azure.com' } else { $endpoint }
        return (@{id=$dceId; properties=@{logsIngestion=@{endpoint=$liveEndpoint}}} | ConvertTo-Json -Depth 5)
    }
    throw 'Unexpected Azure command in offline test.'
}
function Assert-Fails([scriptblock]$Action) {
    $failed = $false
    try { & $Action | Out-Null } catch { $failed = $true }
    if (-not $failed) { throw 'Expected credential-boundary rejection.' }
}
try {
    @{
        schema_version=2; status='validated'; azure_owner_marker='nine-lives-zsp:azure:v1'
        deployment_id=$deployment; tenant_id=$tenant; subscription_id=$subscription
        resource_group_id=$rg; resource_group_name='test-rg'; project_name='test'
        provenance_marker="nine-lives-zsp:v1;tenant=$tenant;project=test"
    } | ConvertTo-Json | Set-Content -LiteralPath $manifestPath
    $origin = Get-OwnedFunctionOrigin 'https://test-lab.azurewebsites.net' $appId $manifestPath
    if ($origin -cne 'https://test-lab.azurewebsites.net') { throw 'Incorrect origin.' }
    foreach ($bad in @('https://attacker.example', "$origin.attacker.example", "$origin/extra", "$origin/?code=secret", "$origin/#fragment", "$origin`:8443", 'https://user:secret@test-lab.azurewebsites.net')) {
        $before = $script:calls
        Assert-Fails { Get-OwnedFunctionOrigin $bad $appId $manifestPath }
        if ($script:calls -ne $before) { throw 'Invalid origin reached Azure metadata.' }
    }
    $script:hostMismatch = $true
    Assert-Fails { Get-OwnedFunctionOrigin $origin $appId $manifestPath }
    $script:hostMismatch = $false
    $script:ownerMismatch = $true
    Assert-Fails { Get-OwnedFunctionOrigin $origin $appId $manifestPath }
    $script:ownerMismatch = $false
    $script:metadataFailure = $true
    Assert-Fails { Get-OwnedFunctionOrigin $origin $appId $manifestPath }
    $script:metadataFailure = $false
    Assert-Fails { Get-OwnedFunctionOrigin $origin ($appId.Replace('test-rg', 'other-rg')) $manifestPath }
    $expected = "$origin/api/access-status/instance-123"
    if ((Get-PrivateStatusUri $expected $origin 'instance-123') -cne $expected) { throw 'Incorrect status URL.' }
    foreach ($bad in @('https://attacker.example', "$expected`?code=secret", "$expected#fragment", "$origin/runtime/webhooks/durabletask/instances/instance-123", "$origin/api/access-status/other")) {
        Assert-Fails { Get-PrivateStatusUri $bad $origin 'instance-123' }
    }
    Assert-Fails { Get-PrivateStatusUri "$origin/api/access-status/../other" $origin '../other' }
    $rule = 'dcr-' + ('a' * 32)
    if ((Get-VerifiedIngestionEndpoint $endpoint $dceId 'test-rg' $rule) -cne $endpoint) { throw 'Incorrect DCE.' }
    Assert-Fails { Get-VerifiedIngestionEndpoint 'https://attacker.example' $dceId 'test-rg' $rule }
    Assert-Fails { Get-VerifiedIngestionEndpoint $endpoint $dceId 'test-rg' 'dcr-invalid' }
    $script:dceMismatch = $true
    Assert-Fails { Get-VerifiedIngestionEndpoint $endpoint $dceId 'test-rg' $rule }
    $before = $script:calls
    Assert-Fails { & "$PSScriptRoot/../Deploy-Lab.ps1" -SkipFunctionDeploy -SkipTest }
    if ($script:calls -ne $before) { throw 'Missing migration confirmation reached Azure.' }
    Write-Output 'Offline exact destination, native failure, redirect URL, and migration gate regressions passed.'
} finally {
    Remove-Item -LiteralPath $manifestPath -Force
    Remove-Item Function:/az
}
