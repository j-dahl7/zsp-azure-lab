#Requires -Version 7.6
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../Azure-Cli.ps1')
$fixturePowerShell = (Microsoft.PowerShell.Core\Get-Command pwsh -CommandType Application | Select-Object -First 1).Source
function Get-Command {
    param($Name, $ErrorAction)
    if ($Name -ne 'az') { throw 'Only the synthetic Azure command may be resolved.' }
    [pscustomobject]@{ CommandType='Application'; Source=$fixturePowerShell }
}
$result = Invoke-ZspAzJson -Arguments @('-NoProfile','-Command','[Console]::Error.WriteLine("warning"); ''{"ok":true}''')
if (-not $result.ok) { throw 'stderr contaminated stdout JSON.' }
foreach ($case in @(
    @{ reason='Forbidden'; code='AuthorizationFailed'; retry=$false },
    @{ reason='Service Unavailable'; code='ServiceUnavailable'; retry=$true }
)) {
    $message = 'ERROR: ' + $case.reason + '({"error":{"code":"' + $case.code + '","message":"secret-response-body"}})'
    $source = '[Console]::Error.WriteLine(''' + $message + '''); exit 1'
    $failure = $null
    try { Invoke-ZspAzJson -Arguments @('-NoProfile','-Command',$source) } catch { $failure = $_.Exception }
    if (-not $failure -or $failure.Data['AzureCliRetryable'] -ne $case.retry -or $failure.Message -match 'secret-response-body') {
        throw 'Provider failure lost its retry classification or exposed response content.'
    }
    $null = Invoke-ZspAz '-NoProfile' '-Command' $source 3>$null
    if ($LASTEXITCODE -ne 1 -or $script:ZspLastCliError.Data['AzureCliRetryable'] -ne $case.retry) { throw 'Raw CLI compatibility lost exit/error classification.' }
}
Write-Host 'PASS: JSON stream separation, sanitized provider codes and transient-only retry classification.'
