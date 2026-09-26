#Requires -Version 7.6
function Invoke-ZspAzText {
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments,

        [switch]$NotFoundIsNull
    )

    $command = Get-Command az -ErrorAction Stop
    if ($command.CommandType -in @('Function', 'Filter')) {
        # Preserve the offline harness contract while keeping its error stream
        # separate from JSON, just like the native-process path below.
        $errors = [System.Collections.Generic.List[string]]::new()
        $output = @(& az @Arguments 2>&1 | ForEach-Object {
            if ($_ -is [System.Management.Automation.ErrorRecord]) { $errors.Add([string]$_) }
            else { $_ }
        })
        $exitCode = $LASTEXITCODE
        $stderr = $errors -join "`n"
        $text = ($output | Out-String).Trim()
    }
    else {
        $start = [System.Diagnostics.ProcessStartInfo]::new()
        $start.FileName = $command.Source
        if ([System.IO.Path]::GetExtension($start.FileName) -in @('.cmd', '.bat')) {
            # The Windows MSI wrapper expands %* through cmd.exe. Invoke its
            # bundled Python directly so URLs/JSON remain individual arguments.
            $python = [System.IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $command.Source) '../python.exe'))
            if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
                throw 'The Azure CLI batch wrapper has no adjacent bundled python.exe; use a supported native Azure CLI installation.'
            }
            $start.FileName = $python
            foreach ($argument in @('-IBm', 'azure.cli')) { $start.ArgumentList.Add($argument) }
        }
        foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $process = [System.Diagnostics.Process]::new()
        $process.StartInfo = $start
        try {
            if (-not $process.Start()) { throw 'Could not start Azure CLI.' }
            $stdoutTask = $process.StandardOutput.ReadToEndAsync()
            $stderrTask = $process.StandardError.ReadToEndAsync()
            $process.WaitForExit()
            $text = $stdoutTask.GetAwaiter().GetResult().Trim()
            $stderr = $stderrTask.GetAwaiter().GetResult().Trim()
            $exitCode = $process.ExitCode
        }
        finally { $process.Dispose() }
    }
    $global:LASTEXITCODE = $exitCode
    if ($exitCode -ne 0) {
        $errorText = "$stderr`n$text"
        $providerCode = $null
        $reason = $null
        $isNotFound = $false
        if ($errorText -match '(?im)^\s*(?:ERROR:\s*)?\(([A-Za-z][A-Za-z0-9_.]{0,79})\)') {
            $providerCode = $Matches[1]
            $isNotFound = $providerCode -in @('ResourceGroupNotFound', 'ResourceNotFound', 'Request_ResourceNotFound')
        }
        elseif ($errorText.Trim() -match '^(?s)(?:ERROR:\s*)?(?<reason>Bad Request|Unauthorized|Forbidden|Not Found|Conflict|Too Many Requests|Internal Server Error|Service Unavailable|Gateway Timeout)\((?<body>\{.*\})\)$') {
            # az rest wraps the structured provider body in its HTTP reason.
            # Require both the 404 reason and a known absence code; do not
            # search arbitrary message text/identifiers for the digits 404.
            $reason = $Matches.reason
            $bodyText = $Matches.body
            try {
                $candidateCode = [string](($bodyText | ConvertFrom-Json -ErrorAction Stop).error.code)
                if ($candidateCode -match '^[A-Za-z][A-Za-z0-9_.]{0,79}$') { $providerCode = $candidateCode }
                $isNotFound = $reason -eq 'Not Found' -and $providerCode -in @('ResourceGroupNotFound', 'ResourceNotFound', 'Request_ResourceNotFound')
            }
            catch { $isNotFound = $false }
        }
        if ($NotFoundIsNull -and $isNotFound) { $global:LASTEXITCODE = 0; return $null }
        # Callers may handle this error without exposing a response body or an
        # argument containing credentials in a terminal/transcript.
        $errorCode = if ($providerCode) { " ($providerCode)" } else { '' }
        $failure = [System.InvalidOperationException]::new("Azure CLI command failed with exit code $exitCode$errorCode.")
        $failure.Data['AzureCliExitCode'] = $exitCode
        $failure.Data['AzureCliRetryable'] = $providerCode -in @('TooManyRequests', 'Throttled', 'ServiceUnavailable', 'InternalServerError', 'GatewayTimeout', 'PrincipalNotFound', 'Request_ResourceNotFound') -or $reason -in @('Too Many Requests', 'Internal Server Error', 'Service Unavailable', 'Gateway Timeout')
        throw $failure
    }
    if (-not $text) { return $null }
    return $text
}


function Invoke-ZspAzJson {
    param([Parameter(Mandatory)][string[]]$Arguments, [switch]$NotFoundIsNull)
    $text = Invoke-ZspAzText -Arguments $Arguments -NotFoundIsNull:$NotFoundIsNull
    if ($text) { return $text | ConvertFrom-Json }
}

function Invoke-ZspAz {
    # Preserve native exit-code/line-output behavior for existing callers.
    # Diagnostics are bounded provider codes, never raw response bodies/args.
    $script:ZspLastCliError = $null
    $arguments = @($args | ForEach-Object { foreach ($value in @($_)) { [string]$value } })
    try {
        $text = Invoke-ZspAzText -Arguments $arguments
        if ($text) { return ($text -split "\r?\n") }
    }
    catch {
        $script:ZspLastCliError = $_.Exception
        if (-not $_.Exception.Data.Contains('AzureCliExitCode')) { $global:LASTEXITCODE = 1 }
        Write-Warning $_.Exception.Message
    }
}
