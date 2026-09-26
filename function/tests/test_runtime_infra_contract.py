"""Keep credential-free storage and deployment inputs aligned with the runtime."""
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]

class RuntimeInfrastructureContractTests(unittest.TestCase):
    def test_host_and_deployment_storage_use_identity_with_all_required_services(self):
        source=(ROOT/'bicep/modules/function.bicep').read_text()
        self.assertNotIn('listKeys()', source)
        self.assertNotIn('AccountKey=', source)
        self.assertIn("type: 'SystemAssignedIdentity'", source)
        self.assertIn('allowSharedKeyAccess: false', source)
        for service in ('blob','queue','table'):
            self.assertIn(f"AzureWebJobsStorage__{service}ServiceUri", source)
        for role in ('b7e6dc6d-f1e8-4753-8033-0f276bb0955b','974c5e8b-45b9-4653-ba55-5f855dd0fb88','0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'):
            self.assertIn(role, source)
        self.assertIn('scope: functionStorage', source)
        host=json.loads((ROOT/'function/host.json').read_text())
        self.assertEqual(host['extensions']['durableTask']['storageProvider']['connectionName'], 'AzureWebJobsStorage')
        configuration=(ROOT/'scripts/Configure-Function.ps1').read_text()
        self.assertIn('--setting-names AzureWebJobsStorage DEPLOYMENT_STORAGE_CONNECTION_STRING', configuration)

    def test_target_does_not_reintroduce_standing_deployer_or_shared_key_access(self):
        source=(ROOT/'bicep/modules/core.bicep').read_text()
        self.assertNotIn("resource deployerKvAdmin", source)
        self.assertIn('allowSharedKeyAccess: false', source)
        self.assertEqual(source.count('@2026-02-01'),2)
        self.assertIn('enableRbacAuthorization: true', source)

    def test_rerun_emits_the_recorded_policy_and_exact_manifest_context(self):
        source=(ROOT/'scripts/Deploy-Lab.ps1').read_text()
        rerun=source.split('$safeRerunCommand =',1)[1].split('Write-Host $safeRerunCommand',1)[0]
        for option in ('-ConfirmLifecycleMigration','-Location','-MaxAccessDurationMinutes','-ManifestPath'):
            self.assertIn(option,rerun)
        self.assertIn("$PSBoundParameters.ContainsKey('MaxAccessDurationMinutes')",source)
        self.assertIn('max_access_duration_minutes',source)
