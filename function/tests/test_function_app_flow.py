"""Endpoint and orchestration tests for the Durable access lifecycle saga."""

from __future__ import annotations

import json
import os
import sys
import types
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch


FUNCTION_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FUNCTION_DIR))


def _module(name: str) -> types.ModuleType:
    module = types.ModuleType(name)
    sys.modules[name] = module
    return module


azure_module = sys.modules.setdefault("azure", types.ModuleType("azure"))
functions_module = _module("azure.functions")
durable_module = _module("azure.durable_functions")
azure_module.functions = functions_module
azure_module.durable_functions = durable_module


class HttpResponse:
    def __init__(self, body, *, status_code=200, mimetype=None):
        self.body = body
        self.status_code = status_code
        self.mimetype = mimetype

    def get_body(self):
        return self.body.encode("utf-8")


class AuthLevel:
    FUNCTION = "function"


class DFApp:
    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def __getattr__(self, name):
        def decorator_factory(**kwargs):
            def decorator(function):
                return function

            return decorator

        return decorator_factory


class RetryOptions:
    def __init__(self, first_interval, max_attempts):
        self.first_interval = first_interval
        self.max_attempts = max_attempts


class EntityId:
    def __init__(self, name, key):
        self.name = name
        self.key = key


functions_module.HttpResponse = HttpResponse
functions_module.HttpRequest = object
functions_module.TimerRequest = object
functions_module.AuthLevel = AuthLevel
durable_module.DFApp = DFApp
durable_module.DurableOrchestrationContext = object
durable_module.DurableEntityContext = object
durable_module.RetryOptions = RetryOptions
durable_module.EntityId = EntityId


async def _placeholder(*args, **kwargs):
    raise AssertionError("test did not patch deployment dependency")


admin_module = _module("admin_access")
admin_module.ensure_admin_entitlement_absent = _placeholder
admin_module.grant_admin_access = _placeholder
admin_module.revoke_admin_access = _placeholder
nhi_module = _module("nhi_access")
nhi_module.ensure_nhi_entitlement_absent = _placeholder
nhi_module.grant_nhi_access = _placeholder
nhi_module.revoke_nhi_access = _placeholder
audit_module = _module("audit")
audit_module.log_access_event = _placeholder

from access_safety import (  # noqa: E402
    PreexistingEntitlementError,
    build_nhi_assignment_id,
    build_nhi_assignment_name,
)
import function_app  # noqa: E402


USER_ID = "11111111-1111-4111-8111-111111111111"
GROUP_ID = "22222222-2222-4222-8222-222222222222"
SP_ID = "33333333-3333-4333-8333-333333333333"
SUBSCRIPTION_ID = "44444444-4444-4444-8444-444444444444"
SCOPE = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-zsp/"
    "providers/Microsoft.KeyVault/vaults/example"
)


class FakeRequest:
    def __init__(self, body):
        self.body = body

    def get_json(self):
        return self.body


class FakeDurableClient:
    def __init__(self, error=None, instance_id="instance-123"):
        self.error = error
        self.instance_id = instance_id
        self.calls = []

    async def start_new(self, name, *, client_input):
        self.calls.append((name, client_input))
        if self.error:
            raise self.error
        return self.instance_id

    def create_check_status_response(self, _request, instance_id):
        return HttpResponse(
            json.dumps(
                {
                    "id": instance_id,
                    "statusQueryGetUri": f"https://status.example/{instance_id}",
                }
            ),
            status_code=202,
            mimetype="application/json",
        )


class EndpointSafetyTests(unittest.IsolatedAsyncioTestCase):
    async def test_admin_endpoint_starts_history_before_any_grant(self):
        grant = AsyncMock()
        client = FakeDurableClient()
        with (
            patch.dict(
                os.environ,
                {
                    "ALLOWED_ADMIN_USER_IDS": USER_ID,
                    "ALLOWED_ADMIN_GROUP_IDS": GROUP_ID,
                    "MAX_ACCESS_DURATION_MINUTES": "480",
                },
                clear=False,
            ),
            patch.object(function_app, "grant_admin_access", grant),
        ):
            response = await function_app.admin_access_request(
                FakeRequest(
                    {
                        "user_id": USER_ID,
                        "group_id": GROUP_ID,
                        "duration_minutes": 60,
                        "justification": "Incident response investigation",
                    }
                ),
                client,
            )

        self.assertEqual(response.status_code, 202)
        self.assertEqual(client.calls[0][0], "access_lifecycle_orchestrator")
        self.assertEqual(client.calls[0][1]["access_type"], "admin")
        grant.assert_not_awaited()

    async def test_durable_start_failure_cannot_leave_nhi_privilege(self):
        grant = AsyncMock()
        client = FakeDurableClient(error=RuntimeError("durable storage unavailable"))
        with (
            patch.dict(
                os.environ,
                {
                    "ALLOWED_NHI_SP_OBJECT_IDS": SP_ID,
                    "ALLOWED_SCOPE_IDS": SCOPE,
                    "MAX_ACCESS_DURATION_MINUTES": "480",
                },
                clear=False,
            ),
            patch.object(function_app, "grant_nhi_access", grant),
        ):
            response = await function_app.nhi_access_request(
                FakeRequest(
                    {
                        "sp_object_id": SP_ID,
                        "scope": SCOPE,
                        "role": "Key Vault Secrets User",
                        "duration_minutes": 30,
                        "workflow_id": "nightly-backup",
                    }
                ),
                client,
            )

        self.assertEqual(response.status_code, 503)
        self.assertIn("no access was granted", json.loads(response.body)["error"])
        grant.assert_not_awaited()

    async def test_boolean_duration_is_rejected_before_orchestration(self):
        client = FakeDurableClient()
        response = await function_app.admin_access_request(
            FakeRequest(
                {
                    "user_id": USER_ID,
                    "group_id": GROUP_ID,
                    "duration_minutes": True,
                    "justification": "Incident response investigation",
                }
            ),
            client,
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(client.calls, [])

    async def test_backup_timer_only_starts_one_bundle_orchestration(self):
        grant = AsyncMock()
        storage_scope = SCOPE.replace("Microsoft.KeyVault/vaults/example", "Microsoft.Storage/storageAccounts/example")
        client = FakeDurableClient()
        with (
            patch.dict(
                os.environ,
                {
                    "BACKUP_SP_OBJECT_ID": SP_ID,
                    "KEYVAULT_RESOURCE_ID": SCOPE,
                    "STORAGE_RESOURCE_ID": storage_scope,
                    "BACKUP_JOB_DURATION_MINUTES": "35",
                    "MAX_ACCESS_DURATION_MINUTES": "480",
                },
                clear=False,
            ),
            patch.object(function_app, "grant_nhi_access", grant),
        ):
            await function_app.backup_job_access_grant(object(), client)

        self.assertEqual(len(client.calls), 1)
        name, payload = client.calls[0]
        self.assertEqual(name, "access_lifecycle_orchestrator")
        self.assertEqual(payload["access_type"], "nhi_bundle")
        self.assertEqual(len(payload["grants"]), 2)
        grant.assert_not_awaited()


class FakeOrchestrationContext:
    def __init__(self, input_data, *, instance_id="instance-123"):
        self.input_data = input_data
        self.instance_id = instance_id
        self.current_utc_datetime = datetime(2026, 7, 10, 18, 0, tzinfo=timezone.utc)
        self.activity_calls = []
        self.entity_calls = []
        self.task_all_calls = []
        self.custom_statuses = []
        self.timer_expiry = None

    def get_input(self):
        return self.input_data

    def create_timer(self, expiry_time):
        self.timer_expiry = expiry_time
        return ("timer", expiry_time)

    def call_activity_with_retry(self, name, retry_options, input_data):
        task = ("activity", name, input_data)
        self.activity_calls.append((name, retry_options, input_data))
        return task

    def call_entity(self, entity_id, operation_name, operation_input):
        task = ("entity", operation_name, operation_input, entity_id)
        self.entity_calls.append((entity_id, operation_name, operation_input))
        return task

    def task_all(self, tasks):
        task = ("all", tasks)
        self.task_all_calls.append(tasks)
        return task

    def set_custom_status(self, value):
        self.custom_statuses.append(value)


class FakeEntityContext:
    def __init__(self, holder, operation_name, payload):
        self.holder = holder
        self.operation_name = operation_name
        self.payload = payload
        self.result = None

    def get_input(self):
        return self.payload

    def get_state(self, initializer=None):
        if "state" not in self.holder and initializer is not None:
            self.holder["state"] = initializer()
        return self.holder.get("state")

    def set_state(self, value):
        self.holder["state"] = value

    def set_result(self, value):
        self.result = value

    def destruct_on_exit(self):
        self.holder.pop("state", None)


class AdminOwnershipEntityTests(unittest.TestCase):
    def _payload(self, owner):
        return {
            "orchestration_instance_id": owner,
            "user_id": USER_ID,
            "group_id": GROUP_ID,
        }

    def _operate(self, holder, operation, owner):
        context = FakeEntityContext(holder, operation, self._payload(owner))
        function_app.admin_entitlement_owner(context)
        return context.result

    def test_concurrent_owner_cannot_claim_or_release_membership(self):
        holder = {}

        first = self._operate(holder, "claim", "instance-one")
        second = self._operate(holder, "claim", "instance-two")
        foreign_release = self._operate(holder, "release", "instance-two")
        owner_verify = self._operate(holder, "verify", "instance-one")

        self.assertTrue(first["claimed"])
        self.assertFalse(second["claimed"])
        self.assertEqual(second["owner"], "instance-one")
        self.assertFalse(foreign_release["released"])
        self.assertTrue(owner_verify["owned"])

        owner_release = self._operate(holder, "release", "instance-one")
        self.assertTrue(owner_release["released"])
        self.assertNotIn("state", holder)

    def test_same_lifecycle_claim_replay_is_idempotent(self):
        holder = {}
        self._operate(holder, "claim", "instance-one")
        replay = self._operate(holder, "claim", "instance-one")

        self.assertTrue(replay["claimed"])
        self.assertTrue(replay["replayed"])


class ActivityFailureAuditTests(unittest.IsolatedAsyncioTestCase):
    async def test_grant_and_revoke_failures_are_audited_and_reraised(self):
        expires_at = "2026-07-10T19:00:00+00:00"
        assignment_id = (
            f"{SCOPE}/providers/Microsoft.Authorization/roleAssignments/"
            "55555555-5555-4555-8555-555555555555"
        )
        cases = (
            (
                "admin grant",
                function_app.grant_admin_access_activity,
                "grant_admin_access",
                {
                    "user_id": USER_ID,
                    "group_id": GROUP_ID,
                    "duration_minutes": 60,
                    "justification": "Incident response",
                    "ticket_id": "INC-1234",
                    "expires_at": expires_at,
                },
                "AccessGrant",
                "human",
                USER_ID,
                GROUP_ID,
            ),
            (
                "nhi grant",
                function_app.grant_nhi_access_activity,
                "grant_nhi_access",
                {
                    "sp_object_id": SP_ID,
                    "scope": SCOPE,
                    "role": "Key Vault Secrets User",
                    "duration_minutes": 30,
                    "workflow_id": "nightly-backup",
                    "assignment_name": "55555555-5555-4555-8555-555555555555",
                    "expires_at": expires_at,
                },
                "AccessGrant",
                "nhi",
                SP_ID,
                SCOPE,
            ),
            (
                "admin revoke",
                function_app.revoke_group_membership_activity,
                "revoke_admin_access",
                {"user_id": USER_ID, "group_id": GROUP_ID},
                "AccessRevoke",
                "human",
                USER_ID,
                GROUP_ID,
            ),
            (
                "nhi revoke",
                function_app.revoke_role_assignment_activity,
                "revoke_nhi_access",
                {
                    "assignment_id": assignment_id,
                    "sp_object_id": SP_ID,
                    "scope": SCOPE,
                    "role": "Key Vault Secrets User",
                },
                "AccessRevoke",
                "nhi",
                SP_ID,
                SCOPE,
            ),
        )

        for (
            label,
            activity,
            dependency_name,
            payload,
            event_type,
            identity_type,
            principal_id,
            target,
        ) in cases:
            with self.subTest(activity=label):
                operation_error = RuntimeError(f"{label} failed")
                audit = AsyncMock()
                with (
                    patch.object(
                        function_app,
                        dependency_name,
                        new=AsyncMock(side_effect=operation_error),
                    ),
                    patch.object(function_app, "log_access_event", new=audit),
                ):
                    with self.assertRaises(RuntimeError) as caught:
                        await activity(payload)

                self.assertIs(caught.exception, operation_error)
                audit.assert_awaited_once()
                audit_fields = audit.await_args.kwargs
                self.assertEqual(audit_fields["event_type"], event_type)
                self.assertEqual(audit_fields["identity_type"], identity_type)
                self.assertEqual(audit_fields["principal_id"], principal_id)
                self.assertEqual(audit_fields["target"], target)
                self.assertEqual(audit_fields["result"], "Failed")
                self.assertEqual(audit_fields["error_message"], str(operation_error))

    async def test_audit_transport_failure_does_not_mask_activity_failure(self):
        operation_error = RuntimeError("revocation failed")
        with (
            patch.object(
                function_app,
                "revoke_admin_access",
                new=AsyncMock(side_effect=operation_error),
            ),
            patch.object(
                function_app,
                "log_access_event",
                new=AsyncMock(side_effect=RuntimeError("audit unavailable")),
            ),
            patch.object(function_app.logging, "exception"),
        ):
            with self.assertRaises(RuntimeError) as caught:
                await function_app.revoke_group_membership_activity(
                    {"user_id": USER_ID, "group_id": GROUP_ID}
                )

        self.assertIs(caught.exception, operation_error)


class OrchestratorTests(unittest.TestCase):
    def _admin_input(self):
        return {
            "access_type": "admin",
            "user_id": USER_ID,
            "group_id": GROUP_ID,
            "duration_minutes": 60,
            "justification": "Incident response investigation",
        }

    def _nhi_input(self):
        return {
            "access_type": "nhi",
            "sp_object_id": SP_ID,
            "scope": SCOPE,
            "role": "Key Vault Secrets User",
            "duration_minutes": 30,
            "workflow_id": "nightly-backup",
        }

    def test_lifecycle_preflights_then_grants_then_revokes(self):
        context = FakeOrchestrationContext(self._nhi_input())
        generator = function_app.access_lifecycle_orchestrator(context)

        preflight_task = next(generator)
        self.assertEqual(preflight_task[1], "check_nhi_entitlement_activity")
        grant_task = generator.send({"status": "absent"})
        self.assertEqual(grant_task[1], "grant_nhi_access_activity")

        grant_payload = grant_task[2]
        expected_name = build_nhi_assignment_name(
            context.instance_id, 0, SP_ID, SCOPE, "Key Vault Secrets User"
        )
        self.assertEqual(grant_payload["assignment_name"], expected_name)
        self.assertEqual(
            grant_payload["assignment_id"],
            build_nhi_assignment_id(SCOPE, expected_name),
        )

        grant_result = {
            "status": "granted",
            "assignment_id": grant_payload["assignment_id"],
            "expires_at": grant_payload["expires_at"],
        }
        timer_task = generator.send(grant_result)
        self.assertEqual(timer_task[0], "timer")
        self.assertEqual(context.timer_expiry.hour, 18)
        self.assertEqual(context.timer_expiry.minute, 30)

        revoke_all = generator.send(None)
        self.assertEqual(revoke_all[0], "all")
        self.assertEqual(revoke_all[1][0][1], "revoke_role_assignment_activity")
        with self.assertRaises(StopIteration) as completed:
            generator.send([{"status": "revoked"}])

        self.assertEqual(completed.exception.value["status"], "revoked")
        self.assertEqual(context.custom_statuses[0]["status"], "granting")
        self.assertEqual(context.custom_statuses[1]["status"], "active")
        retry_options = context.activity_calls[0][1]
        self.assertEqual(retry_options.first_interval, 5000)
        self.assertEqual(retry_options.max_attempts, 5)

    def test_grant_failure_compensates_deterministic_entitlement(self):
        context = FakeOrchestrationContext(self._nhi_input())
        generator = function_app.access_lifecycle_orchestrator(context)

        next(generator)
        grant_task = generator.send({"status": "absent"})
        cleanup_all = generator.throw(RuntimeError("activity completion was lost"))
        self.assertEqual(cleanup_all[0], "all")
        cleanup_task = cleanup_all[1][0]
        self.assertEqual(cleanup_task[1], "revoke_role_assignment_activity")
        self.assertEqual(cleanup_task[2]["assignment_id"], grant_task[2]["assignment_id"])
        with self.assertRaisesRegex(RuntimeError, "completion was lost"):
            generator.send([{"status": "already_revoked"}])

    def test_preexisting_entitlement_is_never_compensated(self):
        context = FakeOrchestrationContext(self._nhi_input())
        generator = function_app.access_lifecycle_orchestrator(context)

        next(generator)
        with self.assertRaises(PreexistingEntitlementError):
            generator.throw(PreexistingEntitlementError("already exists"))
        self.assertEqual(context.task_all_calls, [])

    def test_admin_lifecycle_claims_verifies_and_releases_serialized_owner(self):
        context = FakeOrchestrationContext(self._admin_input())
        generator = function_app.access_lifecycle_orchestrator(context)

        claim = next(generator)
        self.assertEqual(claim[0:2], ("entity", "claim"))
        self.assertEqual(claim[2]["orchestration_instance_id"], context.instance_id)

        preflight = generator.send({"claimed": True, "owner": context.instance_id})
        self.assertEqual(preflight[1], "check_admin_entitlement_activity")
        grant = generator.send({"status": "absent"})
        self.assertEqual(grant[1], "grant_admin_access_activity")

        timer = generator.send({"status": "granted", "created": True})
        self.assertEqual(timer[0], "timer")
        verify = generator.send(None)
        self.assertEqual(verify[0:2], ("entity", "verify"))
        revoke_all = generator.send({"owned": True, "owner": context.instance_id})
        self.assertEqual(revoke_all[0], "all")
        self.assertEqual(revoke_all[1][0][1], "revoke_group_membership_activity")
        release = generator.send([{"status": "revoked"}])
        self.assertEqual(release[0:2], ("entity", "release"))

        with self.assertRaises(StopIteration) as completed:
            generator.send({"released": True, "owner": context.instance_id})
        self.assertEqual(completed.exception.value["status"], "revoked")

    def test_concurrent_admin_claim_is_rejected_before_preflight(self):
        context = FakeOrchestrationContext(self._admin_input())
        generator = function_app.access_lifecycle_orchestrator(context)

        next(generator)
        with self.assertRaises(PreexistingEntitlementError):
            generator.send({"claimed": False, "owner": "other-instance"})
        self.assertEqual(context.activity_calls, [])
        self.assertEqual(context.task_all_calls, [])

    def test_admin_preflight_failure_releases_claim_without_revoking(self):
        context = FakeOrchestrationContext(self._admin_input())
        generator = function_app.access_lifecycle_orchestrator(context)

        next(generator)
        generator.send({"claimed": True, "owner": context.instance_id})
        failure = PreexistingEntitlementError("membership already exists")
        release = generator.throw(failure)
        self.assertEqual(release[0:2], ("entity", "release"))
        self.assertEqual(context.task_all_calls, [])

        with self.assertRaises(PreexistingEntitlementError):
            generator.send({"released": True, "owner": context.instance_id})

    def test_admin_grant_failure_verifies_compensates_then_releases(self):
        context = FakeOrchestrationContext(self._admin_input())
        generator = function_app.access_lifecycle_orchestrator(context)

        next(generator)
        generator.send({"claimed": True, "owner": context.instance_id})
        generator.send({"status": "absent"})
        failure = RuntimeError("activity completion was lost")
        verify = generator.throw(failure)
        self.assertEqual(verify[0:2], ("entity", "verify"))
        cleanup = generator.send({"owned": True, "owner": context.instance_id})
        self.assertEqual(cleanup[0], "all")
        self.assertEqual(cleanup[1][0][1], "revoke_group_membership_activity")
        release = generator.send([{"status": "already_revoked"}])
        self.assertEqual(release[0:2], ("entity", "release"))

        with self.assertRaisesRegex(RuntimeError, "completion was lost"):
            generator.send({"released": True, "owner": context.instance_id})

    def test_admin_cleanup_failure_retains_owner_lock(self):
        context = FakeOrchestrationContext(self._admin_input())
        generator = function_app.access_lifecycle_orchestrator(context)

        next(generator)
        generator.send({"claimed": True, "owner": context.instance_id})
        generator.send({"status": "absent"})
        generator.throw(RuntimeError("grant result lost"))
        generator.send({"owned": True, "owner": context.instance_id})
        with self.assertRaisesRegex(RuntimeError, "cleanup failed"):
            generator.throw(RuntimeError("cleanup failed"))

        operations = [operation for _, operation, _ in context.entity_calls]
        self.assertNotIn("release", operations)

    def test_legacy_revocation_still_services_pending_instances(self):
        context = FakeOrchestrationContext(
            {
                "revocation_type": "role_assignment",
                "expiry_time": "2026-07-10T13:00:00-05:00",
            }
        )
        generator = function_app.revocation_orchestrator(context)

        self.assertEqual(next(generator)[0], "timer")
        self.assertEqual(
            generator.send(None)[1],
            "revoke_role_assignment_activity",
        )
        with self.assertRaises(StopIteration):
            generator.send(None)


if __name__ == "__main__":
    unittest.main()
