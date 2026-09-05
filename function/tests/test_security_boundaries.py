"""Offline credential-destination and real SDK contract regressions."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'function'))
from security_boundaries import ingestion_endpoint, immutable_dcr_id, status_origin, validate_instance_id


class CredentialBoundaryTests(unittest.TestCase):
    def test_ingestion_origin_is_public_azure_only(self):
        good = 'https://example-dce.eastus-1.ingest.monitor.azure.com'
        self.assertEqual(ingestion_endpoint(good + '/'), good)
        for value in ('https://attacker.example', good + '.attacker.example',
                      good + '/path', good + '?code=secret', good + '#fragment',
                      good.replace('https://', 'http://'), good + ':8443',
                      good.replace('https://', 'https://user:secret@'),
                      'https://example-dce.eastus-1.ingest.monitor.azure.com%2f.attacker.example'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                ingestion_endpoint(value)
        self.assertEqual(immutable_dcr_id('dcr-' + 'A' * 32), 'dcr-' + 'a' * 32)
        for value in ('dcr-x', 'dcr-' + '0' * 31, 'dcr-' + '0' * 33):
            with self.assertRaises(ValueError):
                immutable_dcr_id(value)

    def test_status_origin_uses_platform_host_not_request_host(self):
        self.assertEqual(status_origin('lab.azurewebsites.net', 'https://attacker.example'), 'https://lab.azurewebsites.net')
        for hostname in ('', 'attacker.example', 'lab.azurewebsites.net.attacker.example', 'lab.azurewebsites.net:443'):
            with self.assertRaises(ValueError):
                status_origin(hostname, 'https://lab.azurewebsites.net')
        self.assertEqual(status_origin('', 'http://localhost:7071/api/nhi-access', development=True), 'http://localhost:7071')
        with self.assertRaises(ValueError):
            status_origin('', 'https://attacker.example', development=True)
        for value in ('', '../other', 'a?code=x', 'a' * 101, None):
            with self.assertRaises(ValueError):
                validate_instance_id(value)

    def test_real_sdk_bindings_and_ingestion_redirects(self):
        # A subprocess avoids the SDK stubs intentionally used by other suites.
        result = subprocess.run([sys.executable, str(ROOT / 'function/tests/sdk_security_probe.py')],
                                capture_output=True, text=True, cwd=ROOT, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(shutil.which('pwsh'), 'PowerShell 7 is required')
    def test_powershell_credential_destinations_and_migration_gate(self):
        result = subprocess.run(['pwsh', '-NoProfile', '-File', str(ROOT / 'scripts/tests/Test-CredentialDestinations.ps1')],
                                capture_output=True, text=True, cwd=ROOT, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

