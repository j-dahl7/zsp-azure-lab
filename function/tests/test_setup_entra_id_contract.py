"""Regression tests for fail-closed Entra object discovery in Setup-EntraID.ps1."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import textwrap
import unittest


LAB_ROOT = Path(__file__).resolve().parents[2]
SETUP_SCRIPT = LAB_ROOT / "scripts" / "Setup-EntraID.ps1"
DEPLOY_SCRIPT = LAB_ROOT / "scripts" / "Deploy-Lab.ps1"
GRANT_PERMISSIONS_SCRIPT = LAB_ROOT / "scripts" / "Grant-Permissions.ps1"
TEST_SCRIPT = LAB_ROOT / "scripts" / "Test-Lab.ps1"


class SetupEntraIdStaticContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.setup_source = SETUP_SCRIPT.read_text(encoding="utf-8")
        cls.deploy_source = DEPLOY_SCRIPT.read_text(encoding="utf-8")
        cls.test_source = TEST_SCRIPT.read_text(encoding="utf-8")

    def test_legacy_first_match_adoption_is_gone(self) -> None:
        self.assertNotIn("$existingIntuneGroup[0]", self.setup_source)
        self.assertNotIn("$existingSecurityGroup[0]", self.setup_source)
        self.assertNotIn("$existingBackupApp[0]", self.setup_source)
        self.assertIn("Resolve-ExistingDirectoryObject", self.setup_source)
        self.assertIn("Refusing to auto-adopt", self.setup_source)

    def test_rerun_ids_are_complete_and_forwarded(self) -> None:
        parameter_names = (
            "ExpectedIntuneAdminGroupId",
            "ExpectedSecurityReaderGroupId",
            "ExpectedBackupAppObjectId",
            "ExpectedBackupSpObjectId",
        )
        for parameter_name in parameter_names:
            with self.subTest(parameter=parameter_name):
                self.assertIn(f"[string]${parameter_name}", self.setup_source)
                self.assertIn(
                    f"@{{ Parameter = '{parameter_name}'",
                    self.deploy_source,
                )
        self.assertIn("$entraParameters[$mapping.Parameter]", self.deploy_source)
        self.assertIn("partial Entra identity set", self.deploy_source)
        self.assertIn("supply all four Expected*ObjectId parameters", self.setup_source)

    def test_provenance_and_app_sp_linkage_are_verified(self) -> None:
        self.assertIn("$provenanceTag = 'nine-lives-zsp:v1'", self.setup_source)
        self.assertIn(
            '$provenanceMarker = "$provenanceTag;tenant=$tenantId;project=$ProjectName"',
            self.setup_source,
        )
        self.assertIn("Assert-ZspGroupIdentity", self.setup_source)
        self.assertIn("Assert-ZspApplicationIdentity", self.setup_source)
        self.assertIn("Assert-ZspServicePrincipalIdentity", self.setup_source)
        self.assertIn("servicePrincipal.appId", self.setup_source)
        self.assertIn("BACKUP_APP_OBJECT_ID=$backupAppObjectId", self.setup_source)

    def test_membership_guards_target_both_groups_before_role_work(self) -> None:
        intune_guard = (
            "Assert-ZspGroupHasNoDirectMembers -ObjectId $intuneGroupId "
            "-DisplayName $intuneGroupName"
        )
        security_guard = (
            "Assert-ZspGroupHasNoDirectMembers -ObjectId $securityGroupId "
            "-DisplayName $securityGroupName"
        )
        intune_role_work = "# Activate and assign Intune Administrator role"
        security_role_work = "# Activate and assign Security Reader role"

        self.assertEqual(self.setup_source.count(intune_guard), 1)
        self.assertEqual(self.setup_source.count(security_guard), 1)
        self.assertLess(self.setup_source.index(intune_guard), self.setup_source.index(security_guard))
        self.assertLess(self.setup_source.index(security_guard), self.setup_source.index(intune_role_work))
        self.assertLess(self.setup_source.index(intune_role_work), self.setup_source.index(security_role_work))

    def test_role_member_lookups_and_writes_check_native_exit_codes(self) -> None:
        operations = (
            (
                "$existingIntuneMember = az rest --method GET",
                "$intuneMemberLookupExitCode = $LASTEXITCODE",
                "$intuneMemberAssignmentExitCode = $LASTEXITCODE",
                'Write-Host "    Assignment created" -ForegroundColor Green',
            ),
            (
                "$existingSecurityMember = az rest --method GET",
                "$securityMemberLookupExitCode = $LASTEXITCODE",
                "$securityMemberAssignmentExitCode = $LASTEXITCODE",
                'Write-Host "    Assignment created" -ForegroundColor Green',
            ),
        )

        search_from = 0
        for lookup, lookup_check, assignment_check, success_message in operations:
            with self.subTest(lookup=lookup):
                lookup_index = self.setup_source.index(lookup, search_from)
                lookup_check_index = self.setup_source.index(lookup_check, lookup_index)
                assignment_check_index = self.setup_source.index(assignment_check, lookup_check_index)
                success_index = self.setup_source.index(success_message, assignment_check_index)
                self.assertLess(lookup_index, lookup_check_index)
                self.assertLess(lookup_check_index, assignment_check_index)
                self.assertLess(assignment_check_index, success_index)
                search_from = success_index + len(success_message)

        for exit_code_variable in (
            "$intuneMemberLookupExitCode",
            "$intuneMemberAssignmentExitCode",
            "$securityMemberLookupExitCode",
            "$securityMemberAssignmentExitCode",
        ):
            with self.subTest(exit_code_variable=exit_code_variable):
                self.assertIn(f"{exit_code_variable} -ne 0", self.setup_source)

    def test_role_membership_lookup_uses_supported_select_then_client_filter(self) -> None:
        self.assertNotIn("members?`$filter", self.setup_source)
        self.assertIn(
            "directoryRoles/$intuneRoleId/members?`$select=id",
            self.setup_source,
        )
        self.assertIn(
            "directoryRoles/$securityRoleId/members?`$select=id",
            self.setup_source,
        )
        self.assertGreaterEqual(self.setup_source.count("Where-Object"), 3)

    def test_temp_json_files_are_cleaned_in_finally(self) -> None:
        cleanup = "$script:_jsonTempFiles | ForEach-Object"
        self.assertEqual(self.setup_source.count(cleanup), 1)
        self.assertLess(self.setup_source.rindex("finally {"), self.setup_source.index(cleanup))

    def test_smoke_test_keeps_function_key_out_of_urls(self) -> None:
        self.assertNotIn("?code=$FunctionKey", self.test_source)
        self.assertIn("@{ 'x-functions-key' = $FunctionKey }", self.test_source)
        self.assertEqual(self.test_source.count("-Headers $functionHeaders"), 4)


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 is not available")
class SetupEntraIdResolverBehaviorTests(unittest.TestCase):
    def run_function_case(
        self,
        function_names: tuple[str, ...],
        case_script: str,
    ) -> None:
        function_name_literals = ", ".join(f"'{name}'" for name in function_names)
        harness = textwrap.dedent(
            f"""
            $ErrorActionPreference = 'Stop'
            $tokens = $null
            $parseErrors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile(
                $env:ZSP_SETUP_ENTRA_SCRIPT,
                [ref]$tokens,
                [ref]$parseErrors
            )
            if ($parseErrors.Count -ne 0) {{
                throw ($parseErrors | ForEach-Object Message | Out-String)
            }}
            $functionNames = @({function_name_literals})
            foreach ($functionName in $functionNames) {{
                $functionAst = $ast.Find(
                    {{
                        param($node)
                        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                            $node.Name -eq $functionName
                    }},
                    $true
                )
                if (-not $functionAst) {{ throw "Function '$functionName' was not found." }}
                Invoke-Expression $functionAst.Extent.Text
            }}

            {case_script}
            """
        )
        env = os.environ.copy()
        env["ZSP_SETUP_ENTRA_SCRIPT"] = str(SETUP_SCRIPT)
        completed = subprocess.run(
            ["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-"],
            input=harness,
            text=True,
            capture_output=True,
            env=env,
            timeout=30,
            check=False,
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
        )

    def run_resolver_case(self, case_script: str) -> None:
        self.run_function_case(("Resolve-ExistingDirectoryObject",), case_script)

    def test_same_name_group_without_expected_id_is_rejected(self) -> None:
        self.run_resolver_case(
            textwrap.dedent(
                """
                $candidate = [pscustomobject]@{
                    id = '11111111-1111-1111-1111-111111111111'
                    displayName = 'SG-Intune-Admins-ZSP'
                }
                $caught = $false
                try {
                    Resolve-ExistingDirectoryObject `
                        -Candidates @($candidate) `
                        -DisplayName 'SG-Intune-Admins-ZSP' `
                        -ObjectKind 'group' | Out-Null
                }
                catch {
                    $caught = $true
                    if ($_.Exception.Message -notmatch 'Refusing to auto-adopt') { throw }
                }
                if (-not $caught) { throw 'An untrusted same-name group was accepted.' }
                """
            )
        )

    def test_duplicate_name_is_rejected_even_with_expected_id(self) -> None:
        self.run_resolver_case(
            textwrap.dedent(
                """
                $candidates = @(
                    [pscustomobject]@{ id = '11111111-1111-1111-1111-111111111111'; displayName = 'SG-Intune-Admins-ZSP' },
                    [pscustomobject]@{ id = '22222222-2222-2222-2222-222222222222'; displayName = 'sg-intune-admins-zsp' }
                )
                $caught = $false
                try {
                    Resolve-ExistingDirectoryObject `
                        -Candidates $candidates `
                        -DisplayName 'SG-Intune-Admins-ZSP' `
                        -ExpectedObjectId '11111111-1111-1111-1111-111111111111' `
                        -ObjectKind 'group' | Out-Null
                }
                catch {
                    $caught = $true
                    if ($_.Exception.Message -notmatch 'multiple') { throw }
                }
                if (-not $caught) { throw 'Ambiguous duplicate groups were accepted.' }
                """
            )
        )

    def test_exact_expected_object_id_is_the_only_accepted_match(self) -> None:
        self.run_resolver_case(
            textwrap.dedent(
                """
                $expectedId = '11111111-1111-1111-1111-111111111111'
                $candidate = [pscustomobject]@{
                    id = $expectedId
                    displayName = 'SG-Intune-Admins-ZSP'
                }
                $result = Resolve-ExistingDirectoryObject `
                    -Candidates @($candidate) `
                    -DisplayName 'SG-Intune-Admins-ZSP' `
                    -ExpectedObjectId $expectedId `
                    -ObjectKind 'group'
                if ($result.id -ne $expectedId) { throw 'The expected object was not returned.' }
                """
            )
        )

    def test_wrong_group_provenance_is_rejected(self) -> None:
        self.run_function_case(
            ("Assert-ZspGroupIdentity",),
            textwrap.dedent(
                """
                function Get-GraphDirectoryObject {
                    return [pscustomobject]@{
                        id = '11111111-1111-1111-1111-111111111111'
                        displayName = 'SG-Intune-Admins-ZSP'
                        description = 'Looks plausible, but has no ownership marker.'
                        mailEnabled = $false
                        mailNickname = 'SG-Intune-Admins-ZSP'
                        securityEnabled = $true
                        isAssignableToRole = $true
                    }
                }
                $caught = $false
                try {
                    Assert-ZspGroupIdentity `
                        -ObjectId '11111111-1111-1111-1111-111111111111' `
                        -DisplayName 'SG-Intune-Admins-ZSP' `
                        -MailNickname 'SG-Intune-Admins-ZSP' `
                        -ProvenanceMarker 'nine-lives-zsp:v1;tenant=tenant;project=zsp-lab' | Out-Null
                }
                catch {
                    $caught = $true
                    if ($_.Exception.Message -notmatch 'provenance marker') { throw }
                }
                if (-not $caught) { throw 'A group with wrong provenance was accepted.' }
                """
            ),
        )

    def test_nonempty_privileged_group_is_rejected(self) -> None:
        self.run_function_case(
            ("Assert-NoDirectGroupMembers",),
            textwrap.dedent(
                """
                $membershipResponse = [pscustomobject]@{
                    value = @(
                        [pscustomobject]@{ id = '22222222-2222-2222-2222-222222222222' }
                    )
                }
                $caught = $false
                try {
                    Assert-NoDirectGroupMembers `
                        -MembershipResponse $membershipResponse `
                        -ObjectId '11111111-1111-1111-1111-111111111111' `
                        -DisplayName 'SG-Intune-Admins-ZSP'
                }
                catch {
                    $caught = $true
                    if ($_.Exception.Message -notmatch 'contains direct member') { throw }
                }
                if (-not $caught) { throw 'A non-empty privileged group was accepted.' }

                Assert-NoDirectGroupMembers `
                    -MembershipResponse ([pscustomobject]@{ value = @() }) `
                    -ObjectId '11111111-1111-1111-1111-111111111111' `
                    -DisplayName 'SG-Intune-Admins-ZSP'
                """
            ),
        )


class GrantPermissionsStaticContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.grant_source = GRANT_PERMISSIONS_SCRIPT.read_text(encoding="utf-8")

    def test_every_permission_retry_loop_checks_the_native_exit_code(self) -> None:
        operations = (
            "grant GroupMember.ReadWrite.All",
            "grant Directory.Read.All",
            "grant RoleManagement.ReadWrite.Directory",
            "grant User Access Administrator",
            "grant Monitoring Metrics Publisher",
        )

        self.assertIn("function Assert-AzCommandSucceeded", self.grant_source)
        self.assertIn("$exitCode = $LASTEXITCODE", self.grant_source)
        self.assertEqual(
            self.grant_source.count("Assert-AzCommandSucceeded -Operation"),
            len(operations),
        )
        for operation in operations:
            with self.subTest(operation=operation):
                self.assertEqual(
                    self.grant_source.count(
                        f"Assert-AzCommandSucceeded -Operation '{operation}'"
                    ),
                    1,
                )


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 is not available")
class GrantPermissionsBehaviorTests(unittest.TestCase):
    def test_native_exit_guard_rejects_nonzero_status(self) -> None:
        harness = textwrap.dedent(
            """
            $ErrorActionPreference = 'Stop'
            $tokens = $null
            $parseErrors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile(
                $env:ZSP_GRANT_PERMISSIONS_SCRIPT,
                [ref]$tokens,
                [ref]$parseErrors
            )
            if ($parseErrors.Count -ne 0) {
                throw ($parseErrors | ForEach-Object Message | Out-String)
            }
            $functionAst = $ast.Find(
                {
                    param($node)
                    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                        $node.Name -eq 'Assert-AzCommandSucceeded'
                },
                $true
            )
            if (-not $functionAst) { throw 'Exit-code guard was not found.' }
            Invoke-Expression $functionAst.Extent.Text

            $global:LASTEXITCODE = 0
            Assert-AzCommandSucceeded -Operation 'test success'

            $global:LASTEXITCODE = 7
            $caught = $false
            try {
                Assert-AzCommandSucceeded -Operation 'test failure'
            }
            catch {
                $caught = $true
                if ($_.Exception.Message -notmatch 'exit code 7') { throw }
            }
            if (-not $caught) { throw 'A nonzero Azure CLI exit code was accepted.' }
            """
        )
        env = os.environ.copy()
        env["ZSP_GRANT_PERMISSIONS_SCRIPT"] = str(GRANT_PERMISSIONS_SCRIPT)
        completed = subprocess.run(
            ["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-"],
            input=harness,
            text=True,
            capture_output=True,
            env=env,
            timeout=30,
            check=False,
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
        )


if __name__ == "__main__":
    unittest.main()
