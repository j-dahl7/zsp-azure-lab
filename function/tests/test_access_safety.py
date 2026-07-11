"""Focused safety tests for ZSP validation and deterministic ownership."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


FUNCTION_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FUNCTION_DIR))

from access_safety import (  # noqa: E402
    RequestValidationError,
    build_admin_ownership_key,
    build_nhi_assignment_id,
    build_nhi_assignment_name,
    exception_error_code,
    exception_status_code,
    is_explicit_not_found,
    validate_admin_request,
    validate_duration,
    validate_nhi_request,
)


USER_ID = "11111111-1111-4111-8111-111111111111"
GROUP_ID = "22222222-2222-4222-8222-222222222222"
SP_ID = "33333333-3333-4333-8333-333333333333"
SUBSCRIPTION_ID = "44444444-4444-4444-8444-444444444444"
SCOPE = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-zsp/"
    "providers/Microsoft.KeyVault/vaults/example"
)


class StructuredError(Exception):
    def __init__(self, *, status_code=None, response_status_code=None, code=None):
        super().__init__("untrusted text that might contain 404")
        self.status_code = status_code
        self.response_status_code = response_status_code
        self.error = type("AzureError", (), {"code": code})() if code else None


class RequestValidationTests(unittest.TestCase):
    def test_admin_request_is_normalized(self):
        result = validate_admin_request(
            {
                "user_id": USER_ID.upper(),
                "group_id": GROUP_ID,
                "duration_minutes": 60,
                "justification": "  Incident response investigation  ",
                "ticket_id": "  INC-1234  ",
            },
            480,
        )

        self.assertEqual(result["user_id"], USER_ID)
        self.assertEqual(result["group_id"], GROUP_ID)
        self.assertEqual(result["justification"], "Incident response investigation")
        self.assertEqual(result["ticket_id"], "INC-1234")

    def test_nhi_request_is_normalized(self):
        result = validate_nhi_request(
            {
                "sp_object_id": SP_ID,
                "scope": SCOPE,
                "role": "Key Vault Secrets User",
                "duration_minutes": 30,
                "workflow_id": "nightly-backup",
            },
            60,
        )

        self.assertEqual(result["scope"], SCOPE)
        self.assertEqual(result["duration_minutes"], 30)

    def test_body_must_be_an_object(self):
        with self.assertRaisesRegex(RequestValidationError, "must be an object"):
            validate_admin_request(None, 480)

    def test_unexpected_fields_are_rejected(self):
        with self.assertRaisesRegex(RequestValidationError, "Unexpected fields"):
            validate_admin_request(
                {
                    "user_id": USER_ID,
                    "group_id": GROUP_ID,
                    "duration_minutes": 60,
                    "justification": "Incident response investigation",
                    "admin": True,
                },
                480,
            )

    def test_object_ids_must_be_uuids(self):
        with self.assertRaisesRegex(RequestValidationError, "valid UUID"):
            validate_nhi_request(
                {
                    "sp_object_id": "not-an-object-id",
                    "scope": SCOPE,
                    "role": "Reader",
                    "duration_minutes": 30,
                    "workflow_id": "manual-test",
                },
                60,
            )

    def test_scope_rejects_query_fragment_and_non_subscription_paths(self):
        bodies = [
            SCOPE + "?api-version=1",
            "/providers/Microsoft.Management/managementGroups/example",
        ]
        for invalid_scope in bodies:
            with self.subTest(scope=invalid_scope):
                with self.assertRaises(RequestValidationError):
                    validate_nhi_request(
                        {
                            "sp_object_id": SP_ID,
                            "scope": invalid_scope,
                            "role": "Reader",
                            "duration_minutes": 30,
                            "workflow_id": "manual-test",
                        },
                        60,
                    )

    def test_duration_rejects_bool_non_integer_and_out_of_range(self):
        for value in (True, "30", 30.0, 0, -1, 481):
            with self.subTest(value=value):
                with self.assertRaises(RequestValidationError):
                    validate_duration(value, 480)

    def test_duration_accepts_policy_boundaries(self):
        self.assertEqual(validate_duration(1, 480), 1)
        self.assertEqual(validate_duration(480, 480), 480)


class ErrorClassificationTests(unittest.TestCase):
    def test_only_structured_404_is_not_found(self):
        self.assertTrue(is_explicit_not_found(StructuredError(status_code=404)))
        self.assertTrue(
            is_explicit_not_found(StructuredError(response_status_code="404"))
        )
        self.assertFalse(is_explicit_not_found(Exception("request returned 404")))
        self.assertFalse(is_explicit_not_found(StructuredError(status_code=403)))

    def test_structured_error_code_is_extracted(self):
        error = StructuredError(code="RoleAssignmentExists")
        self.assertEqual(exception_error_code(error), "RoleAssignmentExists")
        self.assertIsNone(exception_error_code(Exception("RoleAssignmentExists")))

    def test_nested_response_status_is_extracted(self):
        error = Exception("failed")
        error.response = type("Response", (), {"status_code": 429})()
        self.assertEqual(exception_status_code(error), 429)


class DurableOwnershipTests(unittest.TestCase):
    def test_admin_ownership_key_is_stable_per_user_and_group(self):
        first = build_admin_ownership_key(USER_ID, GROUP_ID)
        same_pair = build_admin_ownership_key(USER_ID.upper(), GROUP_ID.upper())
        other_group = build_admin_ownership_key(
            USER_ID, "55555555-5555-4555-8555-555555555555"
        )

        self.assertEqual(first, same_pair)
        self.assertNotEqual(first, other_group)

    def test_assignment_name_is_stable_and_saga_specific(self):
        first = build_nhi_assignment_name(
            "instance-123", 0, SP_ID, SCOPE, "Reader"
        )
        replay = build_nhi_assignment_name(
            "instance-123", 0, SP_ID, SCOPE, "Reader"
        )
        other_instance = build_nhi_assignment_name(
            "instance-456", 0, SP_ID, SCOPE, "Reader"
        )

        self.assertEqual(first, replay)
        self.assertNotEqual(first, other_instance)
        self.assertEqual(
            build_nhi_assignment_id(SCOPE, first),
            f"{SCOPE}/providers/Microsoft.Authorization/roleAssignments/{first}",
        )

    def test_assignment_name_rejects_invalid_owner_inputs(self):
        with self.assertRaises(ValueError):
            build_nhi_assignment_name("", 0, SP_ID, SCOPE, "Reader")
        with self.assertRaises(ValueError):
            build_nhi_assignment_name("instance-123", -1, SP_ID, SCOPE, "Reader")


if __name__ == "__main__":
    unittest.main()
