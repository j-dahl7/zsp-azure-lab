#Requires -Version 7.6
<#
.SYNOPSIS
    Review or remove explicitly selected legacy broad Graph app-role grants.
.DESCRIPTION
    No grant is inferred to be owned merely because it has a legacy role ID.
    Supply the exact assignment IDs after reviewing their purpose. Every ID is
    preflighted before any deletion and rechecked immediately before its DELETE.
    Supports -WhatIf and never removes other roles or resource assignments.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][guid]$FunctionAppPrincipalId,
    [Parameter(Mandatory)][ValidateCount(1, 16)]
    [ValidatePattern('^[A-Za-z0-9_-]{1,128}$')][string[]]$AssignmentIds
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Azure-Cli.ps1')
$principalId = $FunctionAppPrincipalId.ToString()
$graphAppId = '00000003-0000-0000-c000-000000000000'
$legacyRoles = @('62a82d76-70ea-41e2-9197-370581804d09', '7ab1d382-f21e-4acd-a863-ba3e13f7da61')
$graph = Invoke-ZspAzJson -Arguments @('ad', 'sp', 'show', '--id', $graphAppId, '--only-show-errors', '--output', 'json')
if ($graph.appId -ne $graphAppId -or -not $graph.id) { throw 'Microsoft Graph service principal was not verified.' }
$principal = Invoke-ZspAzJson -Arguments @('ad', 'sp', 'show', '--id', $principalId, '--only-show-errors', '--output', 'json')
if ($principal.id -ne $principalId -or $principal.servicePrincipalType -ne 'ManagedIdentity') { throw 'The exact target is not a verified managed identity.' }
$baseUrl = "https://graph.microsoft.com/v1.0/servicePrincipals/$principalId/appRoleAssignments"

function Read-ExactLegacyAssignment {
    param([string]$AssignmentId)
    $assignment = Invoke-ZspAzJson -Arguments @('rest', '--method', 'GET', '--url', "$baseUrl/$AssignmentId", '--only-show-errors', '--output', 'json') -NotFoundIsNull
    if ($null -eq $assignment) { return $null }
    if ($assignment.id -cne $AssignmentId -or $assignment.principalId -ne $principalId -or
        $assignment.resourceId -ne $graph.id -or $assignment.appRoleId -notin $legacyRoles) {
        throw 'An assignment does not match the exact managed identity, Microsoft Graph resource, and permitted legacy roles. No further deletion is allowed.'
    }
    return $assignment
}

$reviewed = @{}
foreach ($id in @($AssignmentIds | Sort-Object -Unique)) {
    $reviewed[$id] = Read-ExactLegacyAssignment $id
}
foreach ($id in $reviewed.Keys) {
    if ($null -eq $reviewed[$id]) { Write-Host "Assignment $id is already absent."; continue }
    $current = Read-ExactLegacyAssignment $id
    if ($null -eq $current) { continue }
    if ($current.appRoleId -ne $reviewed[$id].appRoleId) { throw 'Assignment changed after review; refusing deletion.' }
    if ($PSCmdlet.ShouldProcess("managed identity $principalId / Graph assignment $id", "Remove reviewed legacy role $($current.appRoleId)")) {
        $null = Invoke-ZspAzJson -Arguments @('rest', '--method', 'DELETE', '--url', "$baseUrl/$id", '--only-show-errors', '--output', 'none')
    }
}
