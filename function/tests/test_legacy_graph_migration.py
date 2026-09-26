"""The opt-in legacy-grant migration uses only explicitly selected exact IDs."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(shutil.which('pwsh'), 'PowerShell is required')
class LegacyGraphMigrationTests(unittest.TestCase):
    def run_case(self, case):
        harness = r'''
$ErrorActionPreference = 'Stop'
$global:deletes = @()
$global:fixturePrincipal = '11111111-1111-4111-8111-111111111111'
$global:fixtureGraph = '22222222-2222-4222-8222-222222222222'
function global:az {
    $global:LASTEXITCODE = 0
    $a = @($args)
    if ($a[0] -eq 'ad') {
        $id = $a[[Array]::IndexOf($a, '--id') + 1]
        if ($id -eq '00000003-0000-0000-c000-000000000000') {
            return (@{ id=$global:fixtureGraph; appId=$id } | ConvertTo-Json -Compress)
        }
        return (@{ id=$global:fixturePrincipal; servicePrincipalType='ManagedIdentity' } | ConvertTo-Json -Compress)
    }
    $method = $a[[Array]::IndexOf($a, '--method') + 1]
    $url = $a[[Array]::IndexOf($a, '--url') + 1]
    $id = ($url -split '/')[-1]
    if ($method -eq 'DELETE') { $global:deletes += $id; return }
    if ($env:ZSP_MIGRATION_CASE -eq 'missing') {
        $global:LASTEXITCODE = 1
        return 'ERROR: Not Found({"error":{"code":"Request_ResourceNotFound","message":"absent"}})'
    }
    $role = if ($id -eq 'legacy-group') { '62a82d76-70ea-41e2-9197-370581804d09' } else { '7ab1d382-f21e-4acd-a863-ba3e13f7da61' }
    $target = $global:fixturePrincipal
    if ($id -eq 'legacy-directory' -and $env:ZSP_MIGRATION_CASE -eq 'foreign') { $target = '33333333-3333-4333-8333-333333333333' }
    if ($id -eq 'legacy-directory' -and $env:ZSP_MIGRATION_CASE -eq 'wrong-role') { $role = '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8' }
    return (@{id=$id;principalId=$target;resourceId=$global:fixtureGraph;appRoleId=$role} | ConvertTo-Json -Compress)
}
$failure = $null
try {
    & $env:ZSP_MIGRATION_SCRIPT -FunctionAppPrincipalId $global:fixturePrincipal -AssignmentIds @('legacy-group','legacy-directory') -WhatIf:($env:ZSP_MIGRATION_CASE -eq 'preview') *> $null
}
catch { $failure = $_.Exception.Message }
$resultJson = @{ failed=($null -ne $failure); deletes=@($global:deletes) } | ConvertTo-Json -Compress
[Console]::WriteLine('RESULT:' + $resultJson)
'''
        env = dict(os.environ, ZSP_MIGRATION_SCRIPT=str(ROOT/'scripts/Remove-LegacyGraphGrants.ps1'), ZSP_MIGRATION_CASE=case)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', encoding='utf-8', delete=False) as script:
            script.write(harness)
            script_path = Path(script.name)
        try:
            result = subprocess.run(['pwsh', '-NoProfile', '-NonInteractive', '-File', str(script_path)], text=True, capture_output=True, env=env, check=True)
            return json.loads(result.stdout.rsplit('RESULT:', 1)[-1])
        finally:
            script_path.unlink()

    def test_preview_and_absence_never_delete(self):
        for case in ('preview', 'missing'):
            with self.subTest(case=case):
                result = self.run_case(case)
                self.assertFalse(result['failed'])
                self.assertEqual(result['deletes'], [])

    def test_every_assignment_is_preflighted_before_deletion(self):
        for case in ('foreign', 'wrong-role'):
            with self.subTest(case=case):
                result = self.run_case(case)
                self.assertTrue(result['failed'])
                self.assertEqual(result['deletes'], [])

    def test_only_exact_selected_legacy_grants_are_removed(self):
        result = self.run_case('valid')
        self.assertFalse(result['failed'])
        self.assertCountEqual(result['deletes'], ['legacy-group', 'legacy-directory'])
