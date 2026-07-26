"""Static and parser contracts for provenance-safe ZSP cleanup."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import unittest


LAB_ROOT = Path(__file__).resolve().parents[2]
DEPLOY_SCRIPT = LAB_ROOT / "scripts" / "Deploy-Lab.ps1"
CLEANUP_SCRIPT = LAB_ROOT / "scripts" / "Cleanup-Lab.ps1"


class CleanupContractTests(unittest.TestCase):
    def test_deploy_writes_identifier_only_manifest(self):
        source = DEPLOY_SCRIPT.read_text(encoding="utf-8-sig")
        self.assertIn(".zsp-deployment.json", source)
        self.assertIn("provenance_marker", source)
        self.assertIn("backup_app_object_id", source)
        manifest_block = source.split("$deploymentManifest = [ordered]@{", 1)[1].split("}", 1)[0].lower()
        self.assertNotIn("function_key", manifest_block)
        self.assertNotIn("client_secret", manifest_block)

    def test_cleanup_refuses_name_based_discovery(self):
        source = CLEANUP_SCRIPT.read_text(encoding="utf-8-sig")
        self.assertIn("Refusing name-based discovery", source)
        self.assertIn("provenance marker", source)
        self.assertIn("still has direct members", source)
        self.assertIn("-ConfirmProject must exactly match", source)
        self.assertNotIn("az ad group delete --group", source)
        self.assertNotIn("--display-name", source)

    @unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 is not available")
    def test_cleanup_script_parses(self):
        command = (
            "$tokens=$null; $errors=$null; "
            "[System.Management.Automation.Language.Parser]::ParseFile("
            "$env:ZSP_CLEANUP_SCRIPT,[ref]$tokens,[ref]$errors) | Out-Null; "
            "if ($errors.Count) { throw ($errors | ForEach-Object Message | Out-String) }"
        )
        result = subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-Command", command],
            env={**os.environ, "ZSP_CLEANUP_SCRIPT": str(CLEANUP_SCRIPT)},
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)


if __name__ == "__main__":
    unittest.main()
