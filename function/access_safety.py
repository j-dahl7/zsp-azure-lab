"""Safety primitives shared by the Zero Standing Privilege grant paths.

The gateway must never turn an entitlement that predates a request into an
entitlement it later revokes.  It must also roll back a newly-created grant if
Durable Functions cannot accept the corresponding revocation schedule.
"""

from __future__ import annotations

import re
import uuid
from typing import Any


class RequestValidationError(ValueError):
    """The caller supplied a malformed or unsupported access request."""


class PreexistingEntitlementError(RuntimeError):
    """The requested principal already has the requested entitlement."""


_WORKFLOW_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def build_admin_ownership_key(user_id: str, group_id: str) -> str:
    """Return the stable Durable Entity key that serializes one membership.

    All gateway lifecycles for the same user and privileged group address the
    same entity. Durable Entity operations execute serially, so only one
    orchestration instance can own that membership at a time.
    """

    if not isinstance(user_id, str) or not user_id:
        raise ValueError("user_id is required")
    if not isinstance(group_id, str) or not group_id:
        raise ValueError("group_id is required")
    ownership_key = "|".join(
        ("nlzt-zsp-admin", user_id.casefold(), group_id.casefold())
    )
    return str(uuid.uuid5(uuid.NAMESPACE_URL, ownership_key))


def build_nhi_assignment_name(
    orchestration_instance_id: str,
    grant_index: int,
    sp_object_id: str,
    scope: str,
    role: str,
) -> str:
    """Return the stable RBAC assignment name owned by one Durable saga.

    Durable activities are at-least-once.  A deterministic assignment ID lets
    a replay recognize the side effect created by an earlier activity attempt
    without adopting an assignment that predates the orchestration.
    """

    if not isinstance(orchestration_instance_id, str) or not orchestration_instance_id:
        raise ValueError("orchestration_instance_id is required")
    if not isinstance(grant_index, int) or isinstance(grant_index, bool) or grant_index < 0:
        raise ValueError("grant_index must be a non-negative integer")

    ownership_key = "|".join(
        (
            "nlzt-zsp",
            orchestration_instance_id,
            str(grant_index),
            sp_object_id.casefold(),
            scope.rstrip("/").casefold(),
            role.casefold(),
        )
    )
    return str(uuid.uuid5(uuid.NAMESPACE_URL, ownership_key))


def build_nhi_assignment_id(scope: str, assignment_name: str) -> str:
    """Build the full Azure RBAC assignment resource ID."""

    return (
        f"{scope.rstrip('/')}/providers/Microsoft.Authorization/"
        f"roleAssignments/{assignment_name}"
    )


def exception_status_code(exc: Exception) -> int | None:
    """Return a structured HTTP status code without parsing exception text."""

    candidates = (exc, getattr(exc, "response", None))
    for candidate in candidates:
        if candidate is None:
            continue
        for attribute in ("status_code", "response_status_code"):
            value = getattr(candidate, attribute, None)
            if isinstance(value, int) and not isinstance(value, bool):
                return value
            if isinstance(value, str) and value.isdigit():
                return int(value)
    return None


def exception_error_code(exc: Exception) -> str | None:
    """Return a structured Azure error code, if the SDK supplied one."""

    candidates = (exc, getattr(exc, "error", None))
    for candidate in candidates:
        if candidate is None:
            continue
        value = getattr(candidate, "code", None)
        if isinstance(value, str) and value:
            return value
    return None


def is_explicit_not_found(exc: Exception) -> bool:
    """Only an explicit SDK/HTTP 404 is safe to treat as already absent."""

    return exception_status_code(exc) == 404


def validate_duration(value: Any, maximum: int) -> int:
    """Validate a positive, bounded whole-minute duration."""

    if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum < 1:
        raise RuntimeError("MAX_ACCESS_DURATION_MINUTES must be a positive integer")
    if not isinstance(value, int) or isinstance(value, bool):
        raise RequestValidationError("duration_minutes must be a whole number")
    if value < 1:
        raise RequestValidationError("duration_minutes must be at least 1")
    if value > maximum:
        raise RequestValidationError(
            f"duration_minutes exceeds the maximum of {maximum}"
        )
    return value


def parse_positive_int_setting(value: str | None, *, name: str, default: int) -> int:
    """Parse a positive integer setting and fail closed on bad configuration."""

    raw_value = str(default) if value is None else value
    try:
        parsed = int(raw_value)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"{name} must be a positive integer") from exc
    if parsed < 1:
        raise RuntimeError(f"{name} must be a positive integer")
    return parsed


def validate_object_id(value: Any, field: str) -> str:
    """Validate and canonicalize an Entra object ID."""

    if not isinstance(value, str) or not value:
        raise RequestValidationError(f"{field} must be an Entra object ID")
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError) as exc:
        raise RequestValidationError(f"{field} must be a valid UUID") from exc
    return str(parsed)


def validate_scope(value: Any) -> str:
    """Validate the shape of an Azure resource ID used as an RBAC scope."""

    if not isinstance(value, str) or not value or len(value) > 1024:
        raise RequestValidationError("scope must be an Azure resource ID")
    if value != value.strip() or "\\" in value or "?" in value or "#" in value:
        raise RequestValidationError("scope must be a canonical Azure resource ID")

    segments = value.split("/")
    # A canonical Azure resource ID begins with /subscriptions/{UUID}/ and has
    # no empty path segments after the leading slash.
    if (
        len(segments) < 5
        or segments[0] != ""
        or segments[1].casefold() != "subscriptions"
        or any(not segment for segment in segments[1:])
    ):
        raise RequestValidationError("scope must be a canonical Azure resource ID")
    validate_object_id(segments[2], "scope subscription ID")
    return value


def _validate_text(
    value: Any,
    field: str,
    *,
    minimum: int = 1,
    maximum: int,
) -> str:
    if not isinstance(value, str):
        raise RequestValidationError(f"{field} must be a string")
    normalized = value.strip()
    if len(normalized) < minimum or len(normalized) > maximum:
        raise RequestValidationError(
            f"{field} must be between {minimum} and {maximum} characters"
        )
    if any(ord(character) < 32 and character not in "\t\n\r" for character in normalized):
        raise RequestValidationError(f"{field} contains unsupported control characters")
    return normalized


def _validate_body_shape(body: Any, required: set[str], optional: set[str]) -> dict:
    if not isinstance(body, dict):
        raise RequestValidationError("JSON body must be an object")

    missing = sorted(required - body.keys())
    if missing:
        raise RequestValidationError(f"Missing required fields: {missing}")

    unexpected = sorted(body.keys() - required - optional)
    if unexpected:
        raise RequestValidationError(f"Unexpected fields: {unexpected}")
    return body


def validate_admin_request(body: Any, maximum_duration: int) -> dict:
    """Validate and normalize a human-administrator request body."""

    body = _validate_body_shape(
        body,
        {"user_id", "group_id", "duration_minutes", "justification"},
        {"ticket_id"},
    )
    result = {
        "user_id": validate_object_id(body["user_id"], "user_id"),
        "group_id": validate_object_id(body["group_id"], "group_id"),
        "duration_minutes": validate_duration(body["duration_minutes"], maximum_duration),
        "justification": _validate_text(
            body["justification"], "justification", minimum=10, maximum=1000
        ),
        "ticket_id": None,
    }
    if body.get("ticket_id") is not None:
        result["ticket_id"] = _validate_text(
            body["ticket_id"], "ticket_id", maximum=128
        )
    return result


def validate_nhi_request(body: Any, maximum_duration: int) -> dict:
    """Validate and normalize a non-human-identity request body."""

    body = _validate_body_shape(
        body,
        {"sp_object_id", "scope", "role", "duration_minutes", "workflow_id"},
        set(),
    )
    workflow_id = _validate_text(body["workflow_id"], "workflow_id", maximum=64)
    if not _WORKFLOW_ID_RE.fullmatch(workflow_id):
        raise RequestValidationError(
            "workflow_id may contain only letters, numbers, dots, underscores, and hyphens"
        )
    return {
        "sp_object_id": validate_object_id(body["sp_object_id"], "sp_object_id"),
        "scope": validate_scope(body["scope"]),
        "role": _validate_text(body["role"], "role", maximum=128),
        "duration_minutes": validate_duration(body["duration_minutes"], maximum_duration),
        "workflow_id": workflow_id,
    }
