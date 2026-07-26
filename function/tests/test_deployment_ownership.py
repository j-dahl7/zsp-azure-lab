"""Runtime and static contracts for provenance-safe ZSP deployment and cleanup."""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


LAB_ROOT = Path(__file__).resolve().parents[2]
DEPLOY_AZURE = LAB_ROOT / "scripts" / "Deploy-Azure.ps1"
DEPLOY_LAB = LAB_ROOT / "scripts" / "Deploy-Lab.ps1"
CLEANUP = LAB_ROOT / "scripts" / "Cleanup-Lab.ps1"
TEST_LAB = LAB_ROOT / "scripts" / "Test-Lab.ps1"
BICEP = LAB_ROOT / "bicep" / "main.bicep"
REQUIREMENTS = LAB_ROOT / "function" / "requirements.txt"
PINS = LAB_ROOT / "function" / "pins.txt"
PYTHON_VERSION = LAB_ROOT / "function" / ".python-version"
FUNCIGNORE = LAB_ROOT / "function" / ".funcignore"
WORKFLOW = LAB_ROOT / ".github" / "workflows" / "validate.yml"

SUBSCRIPTION_ID = "11111111-1111-4111-8111-111111111111"
TENANT_ID = "22222222-2222-4222-8222-222222222222"
DEPLOYER_ID = "33333333-3333-4333-8333-333333333333"
PROJECT = "zsp-lab"
RESOURCE_GROUP = f"{PROJECT}-rg"
RESOURCE_GROUP_ID = f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}"
OWNER_MARKER = "nine-lives-zsp:azure:v1"
ANSI_CONTROL_SEQUENCE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def plain_process_output(result: subprocess.CompletedProcess) -> str:
    """Remove terminal styling and renderer-inserted line wrapping."""
    unstyled = ANSI_CONTROL_SEQUENCE.sub("", result.stderr + result.stdout)
    return " ".join(token for token in unstyled.split() if token != "|")


class ZspStaticSafetyTests(unittest.TestCase):
    def test_powershell_error_normalizer_preserves_wrapped_message(self) -> None:
        result = subprocess.CompletedProcess(
            args=["pwsh"],
            returncode=1,
            stdout="",
            stderr="\x1b[31mRefusing to\n | adopt it.\x1b[0m",
        )
        self.assertIn("Refusing to adopt it.", plain_process_output(result))

    def test_bicep_has_non_overridable_ownership_tags(self) -> None:
        source = BICEP.read_text(encoding="utf-8")
        self.assertIn("param ownerMarker string", source)
        self.assertIn("param deploymentId string", source)
        self.assertIn("'nlzt-owner': ownerMarker", source)
        self.assertIn("'nlzt-deployment': deploymentId", source)
        self.assertIn("var effectiveTags = union(tags, ownershipTags)", source)
        self.assertEqual(source.count("tags: effectiveTags"), 3)

    def test_deploy_and_cleanup_are_manifest_and_live_tag_bound(self) -> None:
        deploy = DEPLOY_AZURE.read_text(encoding="utf-8-sig")
        cleanup = CLEANUP.read_text(encoding="utf-8-sig")
        for marker in (
            "Refusing to adopt it",
            "Get-VerifiedResourceGroup",
            "nlzt-owner",
            "nlzt-deployment",
            "Write-DeploymentManifest -Status 'planned'",
        ):
            self.assertIn(marker, deploy)
        for marker in (
            "Azure ownership is verified before any Graph or Azure deletion",
            "Get-GraphObjectByExactId",
            "nlzt-owner",
            "nlzt-deployment",
            "manifest was retained",
        ):
            self.assertIn(marker, cleanup)
        self.assertNotIn("2>$null", cleanup)
        self.assertNotIn("--display-name", cleanup)

    def test_failure_paths_cannot_claim_a_validated_deployment(self) -> None:
        deploy = DEPLOY_LAB.read_text(encoding="utf-8-sig")
        smoke = TEST_LAB.read_text(encoding="utf-8-sig")
        failure_check = deploy.index("$smokeTestExitCode -ne 0")
        validated_status = deploy.index("Save-DeploymentManifest -Status $finalManifestStatus")
        success_heading = deploy.index("Deployment Complete and Smoke-Tested")
        self.assertLess(failure_check, validated_status)
        self.assertLess(validated_status, success_heading)
        self.assertIn("Could not retrieve the Function key required for the smoke test", deploy)
        self.assertIn("-WaitForRevocation", deploy)
        self.assertIn("deployed_unvalidated", deploy)
        self.assertNotIn("=== Deployment Complete ===", deploy)
        self.assertLess(
            smoke.index("Health validation failed; no temporary privilege was requested."),
            smoke.index('$nhiUrl = "$FunctionAppUrl/api/nhi-access"'),
        )
        self.assertIn("Exact lifecycle-owned role assignment", smoke)
        self.assertIn("Normalize-ResourceId ([string]$_.id)", smoke)
        self.assertNotIn("[string]$_.name, [string]$assignmentId", smoke)
        self.assertIn("customStatus.status -ne 'revoked'", smoke)

    def test_function_remote_build_and_ci_enforce_hash_lock(self) -> None:
        entrypoint = REQUIREMENTS.read_text(encoding="utf-8").splitlines()
        self.assertIn("--require-hashes", entrypoint)
        self.assertIn("-r pins.txt", entrypoint)
        self.assertEqual(PYTHON_VERSION.read_text(encoding="utf-8").strip(), "3.11")
        lock = PINS.read_text(encoding="utf-8")
        for package in (
            "azure-functions==",
            "azure-functions-durable==",
            "azure-identity==",
            "msgraph-sdk==",
            "azure-mgmt-authorization==",
            "azure-monitor-ingestion==",
            "python-dateutil==",
        ):
            self.assertIn(package, lock)
        self.assertGreaterEqual(lock.count("--hash=sha256:"), 100)

        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("--require-hashes -r function/requirements.txt", workflow)
        self.assertIn("permissions:\n  contents: read", workflow)
        action_refs = re.findall(r"^\s*uses:\s*\S+@([^\s#]+)", workflow, re.MULTILINE)
        self.assertTrue(action_refs)
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in action_refs))

    def test_function_publish_cannot_package_local_secrets_or_environments(self) -> None:
        deploy = DEPLOY_LAB.read_text(encoding="utf-8-sig")
        self.assertNotIn('Compress-Archive -Path "$functionDir/*"', deploy)
        self.assertIn("$deploymentFiles = @(", deploy)
        self.assertIn("Copy-Item -LiteralPath $sourcePath -Destination $packageRoot", deploy)
        for runtime_file in (
            "access_safety.py",
            "admin_access.py",
            "audit.py",
            "function_app.py",
            "nhi_access.py",
            "host.json",
            "requirements.txt",
            "pins.txt",
        ):
            self.assertIn(f"'{runtime_file}'", deploy)

        ignored = set(FUNCIGNORE.read_text(encoding="utf-8").splitlines())
        for sensitive_path in ("local.settings.json", ".venv/", "venv/", "tests/", "*.pem", "*.key"):
            self.assertIn(sensitive_path, ignored)


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 is required")
class ZspPowerShellRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir()
        self.state_path = self.root / "azure-state.json"
        self.log_path = self.root / "az-calls.jsonl"
        self.manifest_path = self.root / ".zsp-deployment.json"
        self._write_state(rg_exists=False)
        self._write_fake_az()
        self.env = os.environ.copy()
        self.env.update(
            {
                "PATH": f"{self.bin_dir}{os.pathsep}{self.env.get('PATH', '')}",
                "MOCK_AZ_STATE": str(self.state_path),
                "MOCK_AZ_LOG": str(self.log_path),
                "MOCK_SUBSCRIPTION_ID": SUBSCRIPTION_ID,
                "MOCK_TENANT_ID": TENANT_ID,
            }
        )

    def _write_state(
        self,
        *,
        rg_exists: bool,
        owner: str | None = None,
        deployment: str | None = None,
        failed_once: bool = False,
    ) -> None:
        self.state_path.write_text(
            json.dumps(
                {
                    "rg_exists": rg_exists,
                    "rg_owner": owner,
                    "rg_deployment": deployment,
                    "failed_once": failed_once,
                }
            ),
            encoding="utf-8",
        )

    def _state(self) -> dict:
        return json.loads(self.state_path.read_text(encoding="utf-8"))

    def _calls(self) -> list[list[str]]:
        if not self.log_path.exists():
            return []
        return [
            json.loads(line)
            for line in self.log_path.read_text(encoding="utf-8").splitlines()
            if line
        ]

    def _write_fake_az(self) -> None:
        implementation = self.bin_dir / "az_impl.py"
        implementation.write_text(
            textwrap.dedent(
                r'''
                import json
                import os
                import sys
                from pathlib import Path

                args = sys.argv[1:]
                state_path = Path(os.environ["MOCK_AZ_STATE"])
                log_path = Path(os.environ["MOCK_AZ_LOG"])
                subscription = os.environ["MOCK_SUBSCRIPTION_ID"]
                tenant = os.environ["MOCK_TENANT_ID"]
                state = json.loads(state_path.read_text(encoding="utf-8"))

                with log_path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(args) + "\n")

                def save():
                    state_path.write_text(json.dumps(state), encoding="utf-8")

                def option(name, default=None):
                    if name not in args:
                        return default
                    index = args.index(name)
                    return args[index + 1] if index + 1 < len(args) else default

                def parameter(name, default=None):
                    prefix = name + "="
                    for value in args:
                        if value.startswith(prefix):
                            return value[len(prefix):]
                    return default

                def value(item):
                    return {"value": item}

                if args[:1] == ["version"]:
                    print(json.dumps({"azure-cli": "mock"}))
                elif args[:2] == ["account", "show"]:
                    print(json.dumps({"id": subscription, "tenantId": tenant, "name": "Mock Subscription"}))
                elif args[:3] == ["ad", "signed-in-user", "show"]:
                    print("33333333-3333-4333-8333-333333333333")
                elif args[:2] == ["group", "exists"]:
                    print("true" if state["rg_exists"] else "false")
                elif args[:2] == ["group", "show"]:
                    if not state["rg_exists"]:
                        sys.exit(3)
                    project = option("--name", "zsp-lab-rg")[:-3]
                    resource_group = option("--name", f"{project}-rg")
                    print(json.dumps({
                        "id": f"/subscriptions/{subscription}/resourceGroups/{resource_group}",
                        "name": resource_group,
                        "tags": {
                            "nlzt-owner": state.get("rg_owner"),
                            "nlzt-deployment": state.get("rg_deployment"),
                        },
                    }))
                elif args[:2] == ["group", "delete"]:
                    if os.environ.get("MOCK_FAIL_GROUP_DELETE") == "true":
                        sys.exit(44)
                    state["rg_exists"] = False
                    save()
                elif args[:3] == ["deployment", "sub", "create"]:
                    project = parameter("projectName", "zsp-lab")
                    resource_group = f"{project}-rg"
                    deployment_id = parameter("deploymentId")
                    owner = parameter("ownerMarker")
                    state["rg_exists"] = True
                    state["rg_owner"] = owner
                    state["rg_deployment"] = deployment_id
                    if os.environ.get("MOCK_FAIL_DEPLOYMENT_ONCE") == "true" and not state.get("failed_once"):
                        state["failed_once"] = True
                        save()
                        sys.exit(41)
                    save()
                    rg_id = f"/subscriptions/{subscription}/resourceGroups/{resource_group}"
                    unique = "abc123"
                    outputs = {
                        "resourceGroupName": value(resource_group),
                        "resourceGroupId": value(rg_id),
                        "functionAppName": value(f"{project}-gw-{unique}"),
                        "functionAppUrl": value(f"https://{project}-gw-{unique}.azurewebsites.net"),
                        "functionAppPrincipalId": value("44444444-4444-4444-8444-444444444444"),
                        "keyVaultId": value(f"{rg_id}/providers/Microsoft.KeyVault/vaults/{project}-kv"),
                        "keyVaultName": value(f"{project}-kv"),
                        "storageAccountId": value(f"{rg_id}/providers/Microsoft.Storage/storageAccounts/zsptest"),
                        "storageAccountName": value("zsptest"),
                        "logAnalyticsWorkspaceId": value(f"{rg_id}/providers/Microsoft.OperationalInsights/workspaces/{project}-logs"),
                        "logAnalyticsWorkspaceCustomerId": value("55555555-5555-4555-8555-555555555555"),
                        "dataCollectionEndpointUrl": value(f"https://{project}-dce.example"),
                        "tenantId": value(tenant),
                        "subscriptionId": value(subscription),
                        "maxAccessDurationMinutes": value(480),
                    }
                    print(json.dumps({"properties": {"provisioningState": "Succeeded", "outputs": outputs}}))
                elif args and args[0] == "rest":
                    method = (option("--method", "GET") or "GET").upper()
                    url = option("--url", option("--uri", ""))
                    if method == "PUT" and "dataCollectionRules" in url:
                        print(json.dumps({"properties": {"immutableId": "dcr-mock"}}))
                    elif method == "PUT":
                        pass
                    elif method == "GET":
                        print(json.dumps({"value": []}))
                    elif method == "DELETE":
                        pass
                    else:
                        sys.exit(98)
                elif args[:3] == ["role", "assignment", "list"]:
                    assignment_id = os.environ.get("MOCK_ASSIGNMENT_ID")
                    if not assignment_id:
                        sys.exit(97)
                    print(json.dumps([{
                        "id": assignment_id,
                        "name": assignment_id.rstrip("/").rsplit("/", 1)[-1],
                        "principalId": option("--assignee"),
                        "roleDefinitionName": "Key Vault Secrets User",
                        "scope": option("--scope"),
                    }]))
                elif args[:3] == ["functionapp", "keys", "list"]:
                    key = os.environ.get("MOCK_FUNCTION_KEY", "mock-function-key")
                    if key:
                        print(key)
                else:
                    print(f"Unexpected mocked az call: {args}", file=sys.stderr)
                    sys.exit(99)
                '''
            ).lstrip(),
            encoding="utf-8",
        )

        if os.name == "nt":
            wrapper = self.bin_dir / "az.cmd"
            wrapper.write_text(
                f'@echo off\r\n"{sys.executable}" "%~dp0az_impl.py" %*\r\n',
                encoding="utf-8",
            )
        else:
            wrapper = self.bin_dir / "az"
            wrapper.write_text(
                f"#!{sys.executable}\n"
                "import runpy\n"
                f"runpy.run_path({str(implementation)!r}, run_name='__main__')\n",
                encoding="utf-8",
            )
            wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)

    def _run_pwsh(self, script: Path, *arguments: str, **extra_env: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                "pwsh",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(script),
                *arguments,
            ],
            env={**self.env, **extra_env},
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    def _deploy_azure(self, **extra_env: str) -> subprocess.CompletedProcess:
        return self._run_pwsh(
            DEPLOY_AZURE,
            "-ProjectName",
            PROJECT,
            "-Location",
            "eastus",
            "-MaxAccessDurationMinutes",
            "480",
            "-DeployerPrincipalId",
            DEPLOYER_ID,
            "-ManifestPath",
            str(self.manifest_path),
            **extra_env,
        )

    def test_existing_unowned_resource_group_is_refused_before_mutation(self) -> None:
        self._write_state(rg_exists=True, owner="foreign", deployment="foreign")
        result = self._deploy_azure()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing to adopt", plain_process_output(result))
        self.assertFalse(self.manifest_path.exists())
        self.assertFalse(any(call[:3] == ["deployment", "sub", "create"] for call in self._calls()))

    def test_new_deploy_rerun_and_tag_collision_use_one_manifest_identity(self) -> None:
        first = self._deploy_azure()
        self.assertEqual(first.returncode, 0, first.stderr + first.stdout)
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema_version"], 2)
        self.assertEqual(manifest["status"], "azure_deployed")
        self.assertEqual(manifest["resource_group_id"].lower(), RESOURCE_GROUP_ID.lower())
        deployment_id = manifest["deployment_id"]
        self.assertEqual(self._state()["rg_owner"], OWNER_MARKER)
        self.assertEqual(self._state()["rg_deployment"], deployment_id)

        rerun = self._deploy_azure()
        self.assertEqual(rerun.returncode, 0, rerun.stderr + rerun.stdout)
        self.assertIn("Verified owned resource-group rerun", rerun.stdout)
        self.assertEqual(
            json.loads(self.manifest_path.read_text(encoding="utf-8"))["deployment_id"],
            deployment_id,
        )

        calls_before_collision = len(self._calls())
        state = self._state()
        state["rg_owner"] = "foreign"
        self.state_path.write_text(json.dumps(state), encoding="utf-8")
        collision = self._deploy_azure()
        self.assertNotEqual(collision.returncode, 0)
        self.assertIn("ownership tag", collision.stderr + collision.stdout)
        self.assertFalse(
            any(
                call[:3] == ["deployment", "sub", "create"]
                for call in self._calls()[calls_before_collision:]
            )
        )

    def test_partial_azure_failure_retains_planned_manifest_for_exact_retry(self) -> None:
        failed = self._deploy_azure(MOCK_FAIL_DEPLOYMENT_ONCE="true")
        self.assertNotEqual(failed.returncode, 0)
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "planned")
        deployment_id = manifest["deployment_id"]
        self.assertEqual(self._state()["rg_deployment"], deployment_id)

        retry = self._deploy_azure(MOCK_FAIL_DEPLOYMENT_ONCE="true")
        self.assertEqual(retry.returncode, 0, retry.stderr + retry.stdout)
        retried_manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(retried_manifest["deployment_id"], deployment_id)
        self.assertEqual(retried_manifest["status"], "azure_deployed")

    def test_cleanup_requires_live_tags_and_retains_state_until_absence(self) -> None:
        deployed = self._deploy_azure()
        self.assertEqual(deployed.returncode, 0, deployed.stderr + deployed.stdout)

        state = self._state()
        state["rg_owner"] = "foreign"
        self.state_path.write_text(json.dumps(state), encoding="utf-8")
        calls_before_collision = len(self._calls())
        collision = self._run_pwsh(
            CLEANUP,
            "-ConfirmProject",
            PROJECT,
            "-ManifestPath",
            str(self.manifest_path),
            "-DestroyAzureResources",
            "-Confirm:$false",
        )
        self.assertNotEqual(collision.returncode, 0)
        self.assertIn("No resources were deleted", plain_process_output(collision))
        self.assertFalse(
            any(call[:2] == ["group", "delete"] for call in self._calls()[calls_before_collision:])
        )

        state["rg_owner"] = OWNER_MARKER
        self.state_path.write_text(json.dumps(state), encoding="utf-8")
        cleanup = self._run_pwsh(
            CLEANUP,
            "-ConfirmProject",
            PROJECT,
            "-ManifestPath",
            str(self.manifest_path),
            "-DestroyAzureResources",
            "-Confirm:$false",
        )
        self.assertEqual(cleanup.returncode, 0, cleanup.stderr + cleanup.stdout)
        self.assertTrue(self.manifest_path.exists())
        self.assertFalse(self._state()["rg_exists"])

        verify = self._run_pwsh(
            CLEANUP,
            "-ConfirmProject",
            PROJECT,
            "-ManifestPath",
            str(self.manifest_path),
            "-DestroyAzureResources",
            "-Confirm:$false",
        )
        self.assertEqual(verify.returncode, 0, verify.stderr + verify.stdout)
        self.assertFalse(self.manifest_path.exists())

    def test_smoke_matches_the_full_role_assignment_resource_id(self) -> None:
        assignment_name = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        key_vault_id = f"{RESOURCE_GROUP_ID}/providers/Microsoft.KeyVault/vaults/zsp-lab-kv"
        assignment_id = (
            f"{key_vault_id}/providers/Microsoft.Authorization/"
            f"roleAssignments/{assignment_name}"
        )
        harness = self.root / "run-test-lab.ps1"
        harness.write_text(
            textwrap.dedent(
                f'''
                function global:Invoke-RestMethod {{
                    param($Uri, $Method = 'GET', $Headers, $Body, $ContentType, $TimeoutSec)
                    if ($Uri -like '*/api/health') {{
                        return [pscustomobject]@{{ status = 'healthy' }}
                    }}
                    if ($Method -eq 'POST') {{
                        return [pscustomobject]@{{
                            id = 'mock-instance'
                            statusQueryGetUri = 'https://status.example/mock-instance'
                        }}
                    }}
                    if ($Uri -eq 'https://status.example/mock-instance') {{
                        return [pscustomobject]@{{
                            runtimeStatus = 'Running'
                            customStatus = [pscustomobject]@{{
                                status = 'active'
                                expires_at = '2026-07-25T23:59:59Z'
                                grants = @([pscustomobject]@{{ assignment_id = $env:MOCK_ASSIGNMENT_ID }})
                            }}
                        }}
                    }}
                    throw "Unexpected Invoke-RestMethod call: $Method $Uri"
                }}

                & '{TEST_LAB}' `
                    -FunctionAppUrl 'https://zsp-lab.example' `
                    -FunctionKey 'test-key' `
                    -BackupSpObjectId '{DEPLOYER_ID}' `
                    -KeyVaultResourceId '{key_vault_id}' `
                    -TestDurationMinutes 1
                '''
            ).lstrip(),
            encoding="utf-8",
        )

        result = self._run_pwsh(
            harness,
            MOCK_ASSIGNMENT_ID=assignment_id,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("PASSED: Exact lifecycle-owned role assignment found", result.stdout)
        self.assertIn("Failed: 0", result.stdout)

    def test_smoke_failure_never_emits_or_records_validated_completion(self) -> None:
        lab = self.root / "smoke-lab"
        scripts = lab / "scripts"
        scripts.mkdir(parents=True)
        shutil.copy2(DEPLOY_LAB, scripts / "Deploy-Lab.ps1")

        deployment_id = "66666666-6666-4666-8666-666666666666"
        intune_group = "77777777-7777-4777-8777-777777777777"
        security_group = "88888888-8888-4888-8888-888888888888"
        backup_app = "99999999-9999-4999-8999-999999999999"
        backup_sp = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        backup_client = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        rg_id = RESOURCE_GROUP_ID

        (scripts / "Deploy-Azure.ps1").write_text(
            textwrap.dedent(
                f'''
                param($ProjectName,$Location,$MaxAccessDurationMinutes,$DeployerPrincipalId,$ManifestPath)
                $manifest = [ordered]@{{
                    schema_version = 2
                    status = 'azure_deployed'
                    project_name = $ProjectName
                    location = $Location
                    provenance_marker = 'nine-lives-zsp:v1;tenant={TENANT_ID};project=' + $ProjectName
                    azure_owner_marker = '{OWNER_MARKER}'
                    deployment_id = '{deployment_id}'
                    tenant_id = '{TENANT_ID}'
                    subscription_id = '{SUBSCRIPTION_ID}'
                    resource_group_name = '{RESOURCE_GROUP}'
                    resource_group_id = '{rg_id}'
                }}
                [IO.File]::WriteAllText($ManifestPath, ($manifest | ConvertTo-Json))
                @(
                  'RESOURCE_GROUP_NAME={RESOURCE_GROUP}'
                  'RESOURCE_GROUP_ID={rg_id}'
                  'FUNCTION_APP_NAME=zsp-lab-gw-mock'
                  'FUNCTION_APP_URL=https://zsp-lab-gw-mock.azurewebsites.net'
                  'FUNCTION_APP_PRINCIPAL_ID=44444444-4444-4444-8444-444444444444'
                  'KEYVAULT_ID={rg_id}/providers/Microsoft.KeyVault/vaults/zsp-lab-kv'
                  'KEYVAULT_NAME=zsp-lab-kv'
                  'STORAGE_ACCOUNT_ID={rg_id}/providers/Microsoft.Storage/storageAccounts/zsptest'
                  'STORAGE_ACCOUNT_NAME=zsptest'
                  'LOG_ANALYTICS_WORKSPACE_ID={rg_id}/providers/Microsoft.OperationalInsights/workspaces/zsp-lab-logs'
                  'LOG_ANALYTICS_WORKSPACE_CUSTOMER_ID=55555555-5555-4555-8555-555555555555'
                  'DCR_ENDPOINT_URL=https://zsp-lab-dce.example'
                  'TENANT_ID={TENANT_ID}'
                  'SUBSCRIPTION_ID={SUBSCRIPTION_ID}'
                  'DEPLOYMENT_ID={deployment_id}'
                  'AZURE_OWNER_MARKER={OWNER_MARKER}'
                  "DEPLOYMENT_MANIFEST_PATH=$ManifestPath"
                )
                exit 0
                '''
            ).lstrip(),
            encoding="utf-8",
        )
        (scripts / "Setup-EntraID.ps1").write_text(
            textwrap.dedent(
                f'''
                param($ProjectName,$ExpectedIntuneAdminGroupId,$ExpectedSecurityReaderGroupId,$ExpectedBackupAppObjectId,$ExpectedBackupSpObjectId)
                @(
                  'ENTRA_TENANT_ID={TENANT_ID}'
                  'INTUNE_ADMIN_GROUP_ID={intune_group}'
                  'SECURITY_READER_GROUP_ID={security_group}'
                  'BACKUP_APP_OBJECT_ID={backup_app}'
                  'BACKUP_SP_OBJECT_ID={backup_sp}'
                  'BACKUP_SP_CLIENT_ID={backup_client}'
                )
                exit 0
                '''
            ).lstrip(),
            encoding="utf-8",
        )
        (scripts / "Grant-Permissions.ps1").write_text(
            "param($FunctionAppPrincipalId,$ResourceGroupId,$DcrScope)\nexit 0\n",
            encoding="utf-8",
        )
        (scripts / "Configure-Function.ps1").write_text(
            "param($FunctionAppName,$ResourceGroupName,$IntuneAdminGroupId,$SecurityReaderGroupId,$BackupSpObjectId,$AllowedAdminUserIds,$KeyVaultResourceId,$StorageResourceId,$LogAnalyticsWorkspaceId,$DcrEndpoint,$DcrRuleId,$MaxAccessDurationMinutes)\nexit 0\n",
            encoding="utf-8",
        )
        (scripts / "Test-Lab.ps1").write_text(
            "param($FunctionAppUrl,$FunctionKey,$BackupSpObjectId,$KeyVaultResourceId,[switch]$WaitForRevocation)\nWrite-Host 'SMOKE FAILED'\nexit 9\n",
            encoding="utf-8",
        )

        smoke_manifest = lab / ".zsp-deployment.json"
        result = self._run_pwsh(
            scripts / "Deploy-Lab.ps1",
            "-ProjectName",
            PROJECT,
            "-Location",
            "eastus",
            "-SkipFunctionDeploy",
            "-ManifestPath",
            str(smoke_manifest),
        )
        self.assertNotEqual(result.returncode, 0)
        combined = result.stdout + result.stderr
        self.assertIn("SMOKE FAILED", combined)
        self.assertNotIn("Deployment Complete", combined)
        manifest = json.loads(smoke_manifest.read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "identities_configured")


if __name__ == "__main__":
    unittest.main()
