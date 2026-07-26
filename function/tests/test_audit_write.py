"""Tests for the ZSPAudit_CL write that every access event depends on."""

from __future__ import annotations

import os
import sys
import types
import unittest
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

    def __call__(self, *, endpoint, credential):
        self.endpoint = endpoint
        self.credential = credential
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

    async def test_unconfigured_dcr_skips_the_write(self):
        client = FakeIngestionClient()

        with (
            patch.dict(os.environ, {}, clear=True),
            patch.object(audit, "LogsIngestionClient", client),
        ):
            await audit.log_access_event(**GRANT_EVENT)

        self.assertEqual(client.uploads, [])


if __name__ == "__main__":
    unittest.main()
