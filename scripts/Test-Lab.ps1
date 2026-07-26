#Requires -Version 7.0
<#
.SYNOPSIS
    Runs smoke tests on the deployed ZSP lab.

.DESCRIPTION
    Tests the following functionality:
    1. Health endpoint returns 200
    2. NHI access endpoint starts a Durable grant lifecycle and reaches active state
    3. Role assignment is created on target resource
    4. (Optional) Wait for expiry and verify revocation

.PARAMETER FunctionAppUrl
    Base URL of the Function App.

.PARAMETER BackupSpObjectId
    Object ID of the backup service principal for testing.

.PARAMETER KeyVaultResourceId
    Resource ID of the Key Vault for testing access grants.

.PARAMETER FunctionKey
    Function key for authenticating requests.

.PARAMETER WaitForRevocation
    Wait for access to expire and verify revocation (adds delay).

.PARAMETER TestDurationMinutes
    Duration in minutes for test access grant. Default: 2

.EXAMPLE
    ./Test-Lab.ps1 -FunctionAppUrl "https://zsp-lab-gw-abc123.azurewebsites.net" `
                   -FunctionKey "your-function-key" `
                   -BackupSpObjectId "abc123" `
                   -KeyVaultResourceId "/subscriptions/.../Microsoft.KeyVault/vaults/..."
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$FunctionAppUrl,

    [Parameter(Mandatory)]
    [string]$FunctionKey,

    [Parameter(Mandatory)]
    [string]$BackupSpObjectId,

    [Parameter(Mandatory)]
    [string]$KeyVaultResourceId,

    [Parameter()]
    [switch]$WaitForRevocation,

    [Parameter()]
    [int]$TestDurationMinutes = 2
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

Write-Host "`n=== ZSP Lab Smoke Tests ===" -ForegroundColor Cyan

$passed = 0
$failed = 0
$functionHeaders = @{ 'x-functions-key' = $FunctionKey }

function Normalize-ResourceId {
    param([Parameter(Mandatory)][string]$ResourceId)
    return $ResourceId.TrimEnd('/').ToLowerInvariant()
}

# Test 1: Health endpoint
Write-Host "`nTest 1: Health endpoint" -ForegroundColor Yellow
try {
    $healthUrl = "$FunctionAppUrl/api/health"
    $healthResponse = Invoke-RestMethod -Uri $healthUrl -Method GET -Headers $functionHeaders -TimeoutSec 30

    if ($healthResponse.status -eq 'healthy') {
        Write-Host "  PASSED: Health check returned healthy" -ForegroundColor Green
        $passed++
    }
    else {
        Write-Host "  FAILED: Unexpected health status: $($healthResponse.status)" -ForegroundColor Red
        $failed++
    }
}
catch {
    Write-Host "  FAILED: Health check error: $($_.Exception.Message)" -ForegroundColor Red
    $failed++
}

if ($failed -gt 0) {
    Write-Host "`n=== Test Summary ===" -ForegroundColor Cyan
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host 'Health validation failed; no temporary privilege was requested.' -ForegroundColor Red
    exit 1
}

# Test 2: NHI Access endpoint
Write-Host "`nTest 2: NHI Access grant" -ForegroundColor Yellow
$assignmentId = $null
try {
    $nhiUrl = "$FunctionAppUrl/api/nhi-access"
    $body = @{
        sp_object_id = $BackupSpObjectId
        scope = $KeyVaultResourceId
        role = "Key Vault Secrets User"
        duration_minutes = $TestDurationMinutes
        workflow_id = "manual-test"
    } | ConvertTo-Json

    $nhiResponse = Invoke-RestMethod -Uri $nhiUrl -Method POST -Headers $functionHeaders -Body $body -ContentType "application/json" -TimeoutSec 60

    if (-not $nhiResponse.statusQueryGetUri) {
        throw "Durable management response did not include statusQueryGetUri"
    }
    $statusQueryGetUri = [string]$nhiResponse.statusQueryGetUri

    $deadline = (Get-Date).AddSeconds(90)
    $lifecycleStatus = $null
    do {
        Start-Sleep -Seconds 2
        $lifecycleStatus = Invoke-RestMethod -Uri $nhiResponse.statusQueryGetUri -Method GET -TimeoutSec 30
        if ($lifecycleStatus.runtimeStatus -in @('Failed', 'Terminated', 'Canceled')) {
            throw "Lifecycle entered $($lifecycleStatus.runtimeStatus): $($lifecycleStatus.output | ConvertTo-Json -Compress)"
        }
    } until (
        $lifecycleStatus.customStatus.status -eq 'active' -or
        (Get-Date) -ge $deadline
    )

    if ($lifecycleStatus.customStatus.status -ne 'active') {
        throw "Lifecycle did not reach active state before timeout (runtime=$($lifecycleStatus.runtimeStatus))"
    }

    $grant = @($lifecycleStatus.customStatus.grants)[0]
    if (-not $grant.assignment_id) {
        throw "Active lifecycle did not expose its deterministic assignment ID"
    }

    Write-Host "  PASSED: Durable lifecycle is active" -ForegroundColor Green
    Write-Host "    Instance ID: $($nhiResponse.id)" -ForegroundColor Gray
    Write-Host "    Assignment ID: $($grant.assignment_id)" -ForegroundColor Gray
    Write-Host "    Expires at: $($lifecycleStatus.customStatus.expires_at)" -ForegroundColor Gray
    $assignmentId = $grant.assignment_id
    $passed++
}
catch {
    Write-Host "  FAILED: NHI access error: $($_.Exception.Message)" -ForegroundColor Red
    $failed++
}

# Test 3: Verify role assignment exists
Write-Host "`nTest 3: Verify role assignment" -ForegroundColor Yellow
try {
    if (-not $assignmentId) {
        throw 'The lifecycle did not return an assignment ID; exact role verification cannot run.'
    }
    $assignmentJson = az role assignment list `
        --assignee $BackupSpObjectId `
        --scope $KeyVaultResourceId `
        --output json 2>$null
    $assignmentListExitCode = $LASTEXITCODE
    if ($assignmentListExitCode -ne 0) {
        throw "Azure role-assignment lookup failed with exit code $assignmentListExitCode."
    }
    $assignments = $assignmentJson | ConvertFrom-Json
    $expectedAssignmentId = Normalize-ResourceId ([string]$assignmentId)
    $exactAssignments = @($assignments | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_.id) -and
        (Normalize-ResourceId ([string]$_.id)) -eq $expectedAssignmentId
    })

    if ($exactAssignments.Count -eq 1 -and
        [string]$exactAssignments[0].roleDefinitionName -ceq 'Key Vault Secrets User' -and
        [string]::Equals([string]$exactAssignments[0].principalId, $BackupSpObjectId, [System.StringComparison]::OrdinalIgnoreCase) -and
        [string]::Equals(([string]$exactAssignments[0].scope).TrimEnd('/'), $KeyVaultResourceId.TrimEnd('/'), [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Host "  PASSED: Exact lifecycle-owned role assignment found" -ForegroundColor Green
        $passed++
    }
    else {
        Write-Host "  FAILED: Exact role assignment '$assignmentId' did not match the expected principal, scope, and role" -ForegroundColor Red
        $failed++
    }
}
catch {
    Write-Host "  FAILED: Role verification error: $($_.Exception.Message)" -ForegroundColor Red
    $failed++
}

# Test 4: Wait for revocation (optional)
if ($WaitForRevocation) {
    Write-Host "`nTest 4: Wait for revocation" -ForegroundColor Yellow
    $waitSeconds = ($TestDurationMinutes * 60) + 30  # Add 30 seconds buffer
    Write-Host "  Waiting $waitSeconds seconds for access to expire..." -ForegroundColor Gray

    Start-Sleep -Seconds $waitSeconds

    try {
        if (-not $statusQueryGetUri -or -not $assignmentId) {
            throw 'The active lifecycle identity is unavailable; exact revocation cannot be verified.'
        }

        $revocationDeadline = (Get-Date).AddSeconds(90)
        do {
            $revocationStatus = Invoke-RestMethod -Uri $statusQueryGetUri -Method GET -TimeoutSec 30
            if ($revocationStatus.runtimeStatus -in @('Failed', 'Terminated', 'Canceled')) {
                throw "Lifecycle entered $($revocationStatus.runtimeStatus) while waiting for revocation."
            }
            if ($revocationStatus.customStatus.status -ne 'revoked') {
                Start-Sleep -Seconds 2
            }
        } until (
            $revocationStatus.customStatus.status -eq 'revoked' -or
            (Get-Date) -ge $revocationDeadline
        )
        if ($revocationStatus.customStatus.status -ne 'revoked') {
            throw 'Lifecycle did not report revoked state before the verification timeout.'
        }

        $assignmentJson = az role assignment list `
            --assignee $BackupSpObjectId `
            --scope $KeyVaultResourceId `
            --output json 2>$null
        $assignmentListExitCode = $LASTEXITCODE
        if ($assignmentListExitCode -ne 0) {
            throw "Azure revocation lookup failed with exit code $assignmentListExitCode."
        }
        $assignments = $assignmentJson | ConvertFrom-Json
        $expectedAssignmentId = Normalize-ResourceId ([string]$assignmentId)
        $exactAssignments = @($assignments | Where-Object {
            -not [string]::IsNullOrWhiteSpace([string]$_.id) -and
            (Normalize-ResourceId ([string]$_.id)) -eq $expectedAssignmentId
        })

        if ($exactAssignments.Count -eq 0) {
            Write-Host "  PASSED: Lifecycle reported revoked and exact role assignment is absent" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "  FAILED: Exact role assignment '$assignmentId' still exists after lifecycle revocation" -ForegroundColor Red
            $failed++
        }
    }
    catch {
        Write-Host "  FAILED: Revocation verification error: $($_.Exception.Message)" -ForegroundColor Red
        $failed++
    }
}
else {
    Write-Host "`nTest 4: Skipped (use -WaitForRevocation to test)" -ForegroundColor Gray
}

# Summary
Write-Host "`n=== Test Summary ===" -ForegroundColor Cyan
Write-Host "Passed: $passed" -ForegroundColor Green
Write-Host "Failed: $failed" -ForegroundColor $(if ($failed -gt 0) { 'Red' } else { 'Green' })

if ($failed -gt 0) {
    exit 1
}
exit 0
