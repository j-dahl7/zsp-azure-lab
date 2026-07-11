"""Tests for preexisting-entitlement rejection and revoke classification."""

from __future__ import annotations

import sys
import types
import unittest
from pathlib import Path


FUNCTION_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FUNCTION_DIR))


def _stub_module(name: str) -> types.ModuleType:
    module = sys.modules.get(name)
    if module is None:
        module = types.ModuleType(name)
        sys.modules[name] = module
    return module


# The tests inject clients, so lightweight import stubs are sufficient and keep
# this suite runnable without downloading the Azure deployment dependencies.
_stub_module("azure")
identity_module = _stub_module("azure.identity")
identity_module.DefaultAzureCredential = object
_stub_module("azure.mgmt")
authorization_module = _stub_module("azure.mgmt.authorization")
authorization_module.AuthorizationManagementClient = object
authorization_models_module = _stub_module("azure.mgmt.authorization.models")


class RoleAssignmentCreateParameters:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


authorization_models_module.RoleAssignmentCreateParameters = RoleAssignmentCreateParameters

msgraph_module = _stub_module("msgraph")
msgraph_module.GraphServiceClient = object
_stub_module("msgraph.generated")
_stub_module("msgraph.generated.models")
reference_module = _stub_module("msgraph.generated.models.reference_create")


class ReferenceCreate:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


reference_module.ReferenceCreate = ReferenceCreate

from access_safety import PreexistingEntitlementError  # noqa: E402
from admin_access import (  # noqa: E402
    ensure_admin_entitlement_absent,
    grant_admin_access,
    revoke_admin_access,
)
from nhi_access import (  # noqa: E402
    ROLE_DEFINITIONS,
    ensure_nhi_entitlement_absent,
    grant_nhi_access,
    revoke_nhi_access,
)


USER_ID = "11111111-1111-4111-8111-111111111111"
GROUP_ID = "22222222-2222-4222-8222-222222222222"
SP_ID = "33333333-3333-4333-8333-333333333333"
SUBSCRIPTION_ID = "44444444-4444-4444-8444-444444444444"
SCOPE = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-zsp/"
    "providers/Microsoft.KeyVault/vaults/example"
)
ASSIGNMENT_ID = (
    f"{SCOPE}/providers/Microsoft.Authorization/roleAssignments/"
    "55555555-5555-4555-8555-555555555555"
)


class SdkError(Exception):
    def __init__(self, status_code=None, *, code=None):
        super().__init__("SDK operation failed")
        self.status_code = status_code
        self.error = type("AzureError", (), {"code": code})() if code else None


class FakeMemberReference:
    def __init__(self, graph):
        self.graph = graph

    async def delete(self):
        self.graph.delete_calls += 1
        if self.graph.delete_error:
            raise self.graph.delete_error


class FakeSpecificMember:
    def __init__(self, graph):
        self.ref = FakeMemberReference(graph)


class FakeMembersReference:
    def __init__(self, graph):
        self.graph = graph

    async def post(self, request_body):
        self.graph.post_calls += 1
        self.graph.post_body = request_body
        if self.graph.post_error:
            raise self.graph.post_error


class FakeMembers:
    def __init__(self, graph, page_index=0):
        self.graph = graph
        self.page_index = page_index
        self.ref = FakeMembersReference(graph)

    async def get(self):
        self.graph.lookup_calls += 1
        if self.graph.lookup_error:
            raise self.graph.lookup_error
        member_ids = self.graph.member_pages[self.page_index]
        members = [type("Member", (), {"id": member_id})() for member_id in member_ids]
        next_link = (
            f"page:{self.page_index + 1}"
            if self.page_index + 1 < len(self.graph.member_pages)
            else None
        )
        return type(
            "MemberPage",
            (),
            {"value": members, "odata_next_link": next_link},
        )()

    def with_url(self, raw_url):
        return FakeMembers(self.graph, int(raw_url.split(":", 1)[1]))

    def by_directory_object_id(self, object_id):
        self.graph.last_object_id = object_id
        return FakeSpecificMember(self.graph)


class FakeGroup:
    def __init__(self, graph):
        self.members = FakeMembers(graph)


class FakeGroups:
    def __init__(self, graph):
        self.graph = graph

    def by_group_id(self, group_id):
        self.graph.last_group_id = group_id
        return FakeGroup(self.graph)


class FakeGraphClient:
    def __init__(
        self,
        *,
        member_pages=None,
        lookup_error=None,
        post_error=None,
        delete_error=None,
    ):
        self.member_pages = [[USER_ID]] if member_pages is None else member_pages
        self.lookup_error = lookup_error
        self.post_error = post_error
        self.delete_error = delete_error
        self.lookup_calls = 0
        self.post_calls = 0
        self.delete_calls = 0
        self.groups = FakeGroups(self)


class AdminEntitlementTests(unittest.IsolatedAsyncioTestCase):
    async def test_preexisting_direct_membership_is_rejected(self):
        graph = FakeGraphClient()

        with self.assertRaises(PreexistingEntitlementError):
            await grant_admin_access(
                USER_ID,
                GROUP_ID,
                60,
                "Incident response investigation",
                graph_client=graph,
            )

        self.assertEqual(graph.lookup_calls, 1)
        self.assertEqual(graph.post_calls, 0)

    async def test_membership_lookup_failure_fails_closed(self):
        graph = FakeGraphClient(lookup_error=SdkError(403))

        with self.assertRaises(SdkError):
            await grant_admin_access(
                USER_ID,
                GROUP_ID,
                60,
                "Incident response investigation",
                graph_client=graph,
            )

        self.assertEqual(graph.post_calls, 0)

    async def test_absent_user_allows_new_membership(self):
        graph = FakeGraphClient(member_pages=[[]])

        result = await grant_admin_access(
            USER_ID,
            GROUP_ID,
            60,
            "Incident response investigation",
            graph_client=graph,
        )

        self.assertEqual(result["status"], "granted")
        self.assertEqual(graph.post_calls, 1)

    async def test_recorded_preflight_makes_activity_retry_idempotent(self):
        graph = FakeGraphClient(member_pages=[[USER_ID]])

        result = await grant_admin_access(
            USER_ID,
            GROUP_ID,
            60,
            "Incident response investigation",
            graph_client=graph,
            preflight_recorded=True,
            expires_at="2026-07-10T19:00:00+00:00",
        )

        self.assertEqual(result["status"], "granted")
        self.assertFalse(result["created"])
        self.assertEqual(result["expires_at"], "2026-07-10T19:00:00+00:00")
        self.assertEqual(graph.post_calls, 0)

    async def test_admin_absence_preflight_has_no_side_effect(self):
        graph = FakeGraphClient(member_pages=[[]])
        await ensure_admin_entitlement_absent(
            USER_ID, GROUP_ID, graph_client=graph
        )
        self.assertEqual(graph.post_calls, 0)

    async def test_all_membership_pages_are_checked(self):
        graph = FakeGraphClient(member_pages=[[GROUP_ID], [USER_ID]])

        with self.assertRaises(PreexistingEntitlementError):
            await grant_admin_access(
                USER_ID,
                GROUP_ID,
                60,
                "Incident response investigation",
                graph_client=graph,
            )

        self.assertEqual(graph.lookup_calls, 2)
        self.assertEqual(graph.post_calls, 0)

    async def test_admin_revoke_only_normalizes_404(self):
        absent_graph = FakeGraphClient(delete_error=SdkError(404))
        result = await revoke_admin_access(
            USER_ID, GROUP_ID, graph_client=absent_graph
        )
        self.assertEqual(result["status"], "already_revoked")

        denied_graph = FakeGraphClient(delete_error=SdkError(403))
        with self.assertRaises(SdkError):
            await revoke_admin_access(
                USER_ID, GROUP_ID, graph_client=denied_graph
            )


class FakeRoleAssignments:
    def __init__(self, *, existing=None, create_error=None, delete_error=None):
        self.existing = [] if existing is None else existing
        self.create_error = create_error
        self.delete_error = delete_error
        self.create_calls = 0
        self.delete_calls = 0

    def list_for_scope(self, *, scope, filter):
        self.list_scope = scope
        self.list_filter = filter
        return self.existing

    def create(self, *, scope, role_assignment_name, parameters):
        self.create_calls += 1
        if self.create_error:
            raise self.create_error
        return type(
            "Assignment",
            (),
            {
                "id": (
                    f"{scope}/providers/Microsoft.Authorization/roleAssignments/"
                    f"{role_assignment_name}"
                ),
                "name": role_assignment_name,
            },
        )()

    def delete_by_id(self, assignment_id):
        self.delete_calls += 1
        if self.delete_error:
            raise self.delete_error


class FakeAuthorizationClient:
    def __init__(self, role_assignments):
        self.role_assignments = role_assignments


class NhiEntitlementTests(unittest.IsolatedAsyncioTestCase):
    async def test_preexisting_matching_role_assignment_is_rejected(self):
        role_definition_id = (
            f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
            "Microsoft.Authorization/roleDefinitions/"
            f"{ROLE_DEFINITIONS['Key Vault Secrets User']}"
        )
        existing = type(
            "Assignment",
            (),
            {"role_definition_id": role_definition_id, "scope": SCOPE},
        )()
        assignments = FakeRoleAssignments(existing=[existing])

        with self.assertRaises(PreexistingEntitlementError):
            await grant_nhi_access(
                SP_ID,
                SCOPE,
                "Key Vault Secrets User",
                30,
                "nightly-backup",
                auth_client=FakeAuthorizationClient(assignments),
            )

        self.assertEqual(assignments.create_calls, 0)

    async def test_recorded_preflight_resumes_only_owned_assignment(self):
        role_definition_id = (
            f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
            "Microsoft.Authorization/roleDefinitions/"
            f"{ROLE_DEFINITIONS['Reader']}"
        )
        assignment_name = "55555555-5555-4555-8555-555555555555"
        existing = type(
            "Assignment",
            (),
            {
                "role_definition_id": role_definition_id,
                "scope": SCOPE,
                "name": assignment_name,
                "id": (
                    f"{SCOPE}/providers/Microsoft.Authorization/roleAssignments/"
                    f"{assignment_name}"
                ),
            },
        )()
        assignments = FakeRoleAssignments(existing=[existing])

        result = await grant_nhi_access(
            SP_ID,
            SCOPE,
            "Reader",
            30,
            "manual-test",
            auth_client=FakeAuthorizationClient(assignments),
            assignment_name=assignment_name,
            preflight_recorded=True,
            expires_at="2026-07-10T18:30:00+00:00",
        )

        self.assertFalse(result["created"])
        self.assertEqual(result["assignment_id"], existing.id)
        self.assertEqual(assignments.create_calls, 0)

    async def test_nhi_absence_preflight_has_no_side_effect(self):
        assignments = FakeRoleAssignments(existing=[])
        await ensure_nhi_entitlement_absent(
            SP_ID,
            SCOPE,
            "Reader",
            auth_client=FakeAuthorizationClient(assignments),
        )
        self.assertEqual(assignments.create_calls, 0)

    async def test_create_race_does_not_adopt_existing_assignment(self):
        assignments = FakeRoleAssignments(
            create_error=SdkError(409, code="RoleAssignmentExists")
        )

        with self.assertRaises(PreexistingEntitlementError):
            await grant_nhi_access(
                SP_ID,
                SCOPE,
                "Reader",
                30,
                "manual-test",
                auth_client=FakeAuthorizationClient(assignments),
            )

        self.assertEqual(assignments.create_calls, 1)

    async def test_nhi_revoke_only_normalizes_404(self):
        absent_assignments = FakeRoleAssignments(delete_error=SdkError(404))
        result = await revoke_nhi_access(
            ASSIGNMENT_ID,
            auth_client=FakeAuthorizationClient(absent_assignments),
        )
        self.assertEqual(result["status"], "already_revoked")

        denied_assignments = FakeRoleAssignments(delete_error=SdkError(403))
        with self.assertRaises(SdkError):
            await revoke_nhi_access(
                ASSIGNMENT_ID,
                auth_client=FakeAuthorizationClient(denied_assignments),
            )


if __name__ == "__main__":
    unittest.main()
