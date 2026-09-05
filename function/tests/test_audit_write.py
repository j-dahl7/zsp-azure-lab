"""Tests for the ZSPAudit_CL write that every access event depends on."""

from __future__ import annotations

import os
import sys
import types
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch


FUNCTION_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FUNCTION_DIR))


_MISSING = object()
_created_modules: list[str] = []
_replaced_attributes: list[tuple[types.ModuleType, str, object, object]] = []


def _stub_module(name: str) -> types.ModuleType:
    module = sys.modules.get(name)
    if module is None:
        module = types.ModuleType(name)
        sys.modules[name] = module
        _created_modules.append(name)
    return module


def _stub_attribute(module: types.ModuleType, name: str, value: object) -> None:
    """Replace an attribute, remembering what it held and what replaced it."""

    _replaced_attributes.append((module, name, getattr(module, name, _MISSING), value))
    setattr(module, name, value)


def tearDownModule():
    """Undo the import stubs once this suite has finished.

    Every suite in this directory is loaded into a single interpreter, so a stub
    that only this one wants has to be taken back off the real Azure packages.
    """

    for module, name, original, applied in reversed(_replaced_attributes):
        # A suite that stubbed the same name later in collection now owns the
        # value, and its own teardown restores what was there before all of this.
        if getattr(module, name, _MISSING) is not applied:
            continue
        if original is _MISSING:
            delattr(module, name)
        else:
            setattr(module, name, original)
    _replaced_attributes.clear()

    for name in reversed(_created_modules):
        sys.modules.pop(name, None)
    _created_modules.clear()


# audit.py binds both SDK names at import time and the tests inject their own
# client, so the names only have to exist for the import to succeed.
_stub_module("azure")
identity_module = _stub_module("azure.identity")
_stub_attribute(identity_module, "DefaultAzureCredential", object)
_stub_module("azure.monitor")
ingestion_module = _stub_module("azure.monitor.ingestion")
_stub_attribute(ingestion_module, "LogsIngestionClient", object)

import audit  # noqa: E402


DCR_ENVIRONMENT = {
    "DCR_ENDPOINT": "https://zsp-dce.eastus-1.ingest.monitor.azure.com",
    "DCR_RULE_ID": "dcr-0123456789abcdef0123456789abcdef",
}

GRANT_EVENT = {
    "event_type": "AccessGrant",
    "identity_type": "human",
    "principal_id": "11111111-1111-4111-8111-111111111111",
    "target": "22222222-2222-4222-8222-222222222222",
    "target_type": "EntraGroup",
    "result": "Success",
}


class FakeIngestionClient:
    """Stand in for LogsIngestionClient and record what would have been sent."""

    def __init__(self, upload_error=None):
        self.upload_error = upload_error
        self.uploads = []

    def __call__(self, *, endpoint, credential, **kwargs):
        self.endpoint = endpoint
        self.credential = credential
        self.options = kwargs
        return self

    def upload(self, *, rule_id, stream_name, logs):
        self.uploads.append((rule_id, stream_name, logs))
        if self.upload_error:
            raise self.upload_error


class AuditWriteTests(unittest.IsolatedAsyncioTestCase):
    async def _log_event(self, client, **overrides):
        fields = dict(GRANT_EVENT)
        fields.update(overrides)
        with (
            patch.dict(os.environ, DCR_ENVIRONMENT, clear=True),
            patch.object(audit, "DefaultAzureCredential", object),
            patch.object(audit, "LogsIngestionClient", client),
        ):
            await audit.log_access_event(**fields)

    async def test_transport_failure_reaches_the_caller(self):
        transport_error = RuntimeError("ingestion endpoint unreachable")
        client = FakeIngestionClient(upload_error=transport_error)

        with self.assertRaises(audit.AuditWriteError) as caught:
            await self._log_event(client)

        self.assertIs(caught.exception.__cause__, transport_error)
        self.assertEqual(len(client.uploads), 1)
        self.assertEqual(client.options['redirect_total'], 0)

    async def test_requested_by_is_written_to_the_custom_table(self):
        client = FakeIngestionClient()

        await self._log_event(
            client,
            requested_by="api/admin-access",
            justification="Incident response investigation",
        )

        rule_id, stream_name, logs = client.uploads[0]
        self.assertEqual(rule_id, DCR_ENVIRONMENT["DCR_RULE_ID"])
        self.assertEqual(stream_name, "Custom-ZSPAudit_CL")
        self.assertEqual(logs[0]["RequestedBy"], "api/admin-access")
        self.assertEqual(logs[0]["Justification"], "Incident response investigation")
        self.assertTrue(logs[0]["TimeGenerated"].endswith("+00:00"))

    async def test_exact_lifecycle_and_entitlement_ids_are_written(self):
        client = FakeIngestionClient()

        await self._log_event(
            client,
            lifecycle_id="orchestration-123",
            entitlement_id="membership-456",
        )

        event = client.uploads[0][2][0]
        self.assertEqual(event["LifecycleId"], "orchestration-123")
        self.assertEqual(event["EntitlementId"], "membership-456")

    def test_unrevoked_grant_hunt_is_wellformed_and_validates_input(self):
        """The hunt that finds privilege the ownership guard leaves standing."""

        query = audit.build_kql_query_unrevoked_expired_grants()
        self.assertIn("let grace = 15m;", query)
        self.assertIn('EventType == "AccessGrant"', query)
        self.assertIn('EventType == "AccessRevoke"', query)
        self.assertIn(
            "join kind=leftanti exact_revokes on LifecycleId, EntitlementId",
            query,
        )
        self.assertNotIn("on PrincipalId, Target", query)
        self.assertIn('CorrelationStatus = "LegacyUncorrelated"', query)
        self.assertIn(
            "let grace = 30m;", audit.build_kql_query_unrevoked_expired_grants(30)
        )
        for bad in (0, -5, True, "15"):
            with self.subTest(grace=bad):
                with self.assertRaises(ValueError):
                    audit.build_kql_query_unrevoked_expired_grants(bad)

    async def test_unconfigured_dcr_fails_closed(self):
        client = FakeIngestionClient()

        with (
            patch.dict(os.environ, {}, clear=True),
            patch.object(audit, "LogsIngestionClient", client),
        ):
            with self.assertRaises(audit.AuditConfigurationError):
                await audit.log_access_event(**GRANT_EVENT)

        self.assertEqual(client.uploads, [])

    async def test_untrusted_endpoint_fails_before_credential_acquisition(self):
        for endpoint in ('https://attacker.example', DCR_ENVIRONMENT['DCR_ENDPOINT'] + '?token=secret',
                         DCR_ENVIRONMENT['DCR_ENDPOINT'] + '/redirect'):
            with patch.dict(os.environ, {**DCR_ENVIRONMENT, 'DCR_ENDPOINT': endpoint}, clear=True), \
                    patch.object(audit, 'DefaultAzureCredential') as credential, \
                    patch.object(audit, 'LogsIngestionClient') as client:
                with self.assertRaises(audit.AuditConfigurationError):
                    await audit.log_access_event(**GRANT_EVENT)
                credential.assert_not_called()
                client.assert_not_called()

    def test_audit_configuration_rejects_non_https_or_mutable_rule_ids(self):
        with patch.dict(
            os.environ,
            {"DCR_ENDPOINT": "http://example.test", "DCR_RULE_ID": "resource-id"},
            clear=True,
        ):
            status = audit.audit_configuration_status()
            self.assertFalse(status["ready"])
            self.assertEqual(len(status["issues"]), 2)
            with self.assertRaises(audit.AuditConfigurationError):
                audit.require_audit_configuration()

    def test_repeated_healthy_admin_lifecycles_do_not_alert(self):
        expires_at = "2026-07-10T18:00:00+00:00"
        events = []
        for lifecycle_id in ("admin-one", "admin-two"):
            common = {
                "IdentityType": "human",
                "PrincipalId": GRANT_EVENT["principal_id"],
                "Target": GRANT_EVENT["target"],
                "LifecycleId": lifecycle_id,
                "EntitlementId": "same-membership",
                "ExpiresAt": expires_at,
                "Result": "Success",
            }
            events.append({**common, "EventType": "AccessGrant"})
            events.append({**common, "EventType": "AccessRevoke"})

        findings = audit.evaluate_unrevoked_expired_grants(
            events,
            now=datetime(2026, 7, 10, 20, 0, tzinfo=timezone.utc),
        )

        self.assertEqual(findings, [])

    def test_different_nhi_roles_on_one_scope_correlate_independently(self):
        expires_at = "2026-07-10T18:00:00+00:00"
        common = {
            "IdentityType": "nhi",
            "PrincipalId": "service-principal",
            "Target": "/subscriptions/example/resourceGroups/rg",
            "ExpiresAt": expires_at,
            "Result": "Success",
        }
        events = [
            {
                **common,
                "EventType": "AccessGrant",
                "Role": "Reader",
                "LifecycleId": "reader-lifecycle",
                "EntitlementId": "reader-assignment",
            },
            {
                **common,
                "EventType": "AccessRevoke",
                "Role": "Reader",
                "LifecycleId": "reader-lifecycle",
                "EntitlementId": "reader-assignment",
            },
            {
                **common,
                "EventType": "AccessGrant",
                "Role": "Contributor",
                "LifecycleId": "contributor-lifecycle",
                "EntitlementId": "contributor-assignment",
            },
        ]

        findings = audit.evaluate_unrevoked_expired_grants(
            events,
            now=datetime(2026, 7, 10, 20, 0, tzinfo=timezone.utc),
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Role"], "Contributor")
        self.assertEqual(findings[0]["CorrelationStatus"], "Exact")

    def test_legacy_rows_are_review_items_not_heuristically_correlated(self):
        events = [
            {
                "EventType": "AccessGrant",
                "Result": "Success",
                "PrincipalId": "legacy-principal",
                "Target": "legacy-target",
                "ExpiresAt": "2026-07-10T18:00:00+00:00",
            },
            {
                "EventType": "AccessRevoke",
                "Result": "Success",
                "PrincipalId": "legacy-principal",
                "Target": "legacy-target",
            },
        ]

        findings = audit.evaluate_unrevoked_expired_grants(
            events,
            now=datetime(2026, 7, 10, 20, 0, tzinfo=timezone.utc),
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["CorrelationStatus"], "LegacyUncorrelated")


if __name__ == "__main__":
    unittest.main()
