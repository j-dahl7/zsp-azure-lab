"""
Non-Human Identity Access Management

Handles granting/revoking Azure RBAC role assignments for service principals.
"""

import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.authorization.models import RoleAssignmentCreateParameters

from access_safety import (
    PreexistingEntitlementError,
    exception_error_code,
    is_explicit_not_found,
)


# Common role definition IDs (built-in roles)
ROLE_DEFINITIONS = {
    "Key Vault Secrets User": "4633458b-17de-408a-b874-0445c86b69e6",
    "Key Vault Reader": "21090545-7ca7-4776-b22c-e363652d74d2",
    "Storage Blob Data Reader": "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1",
    "Storage Blob Data Contributor": "ba92f5b4-2d11-453d-a403-e96b0029c9fe",
    "Reader": "acdd72a7-3385-48ef-bd42-f606fba81ae7",
}


def get_subscription_id_from_scope(scope: str) -> str:
    """Extract subscription ID from a resource scope."""
    parts = scope.split("/")
    normalized_parts = [part.casefold() for part in parts]
    if "subscriptions" in normalized_parts:
        idx = normalized_parts.index("subscriptions")
        return parts[idx + 1]
    raise ValueError(f"Could not extract subscription ID from scope: {scope}")


def get_role_definition_id(role_name: str, subscription_id: str) -> str:
    """Get the full role definition ID for a role name."""
    if role_name in ROLE_DEFINITIONS:
        role_guid = ROLE_DEFINITIONS[role_name]
        return f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/{role_guid}"
    raise ValueError(f"Unknown role: {role_name}. Add it to ROLE_DEFINITIONS.")


def _assignment_name(assignment) -> str:
    name = getattr(assignment, "name", None)
    if isinstance(name, str) and name:
        return name
    assignment_id = getattr(assignment, "id", None)
    if isinstance(assignment_id, str) and assignment_id:
        return assignment_id.rstrip("/").rsplit("/", 1)[-1]
    return ""


def _matching_role_assignments(
    auth_client,
    *,
    sp_object_id: str,
    scope: str,
    role_name: str,
) -> list:
    """Return exact principal/role/scope matches, failing closed on SDK errors."""

    expected_role_guid = ROLE_DEFINITIONS[role_name].casefold()
    existing_assignments = auth_client.role_assignments.list_for_scope(
        scope=scope,
        filter=f"principalId eq '{sp_object_id}'",
    )
    matches = []
    for existing_assignment in existing_assignments:
        existing_role_id = str(
            getattr(existing_assignment, "role_definition_id", "") or ""
        ).casefold()
        existing_scope = getattr(existing_assignment, "scope", None)
        if existing_scope and str(existing_scope).rstrip("/").casefold() != scope.rstrip("/").casefold():
            continue
        if existing_role_id.rstrip("/").endswith(f"/{expected_role_guid}"):
            matches.append(existing_assignment)
    return matches


async def ensure_nhi_entitlement_absent(
    sp_object_id: str,
    scope: str,
    role_name: str,
    *,
    auth_client=None,
) -> None:
    """Fail closed if the requested exact RBAC entitlement already exists."""

    subscription_id = get_subscription_id_from_scope(scope)
    if auth_client is None:
        credential = DefaultAzureCredential()
        auth_client = AuthorizationManagementClient(credential, subscription_id)

    if _matching_role_assignments(
        auth_client,
        sp_object_id=sp_object_id,
        scope=scope,
        role_name=role_name,
    ):
        raise PreexistingEntitlementError(
            f"Service principal {sp_object_id} already has {role_name} on {scope}"
        )


async def grant_nhi_access(
    sp_object_id: str,
    scope: str,
    role_name: str,
    duration_minutes: int,
    workflow_id: str,
    *,
    auth_client=None,
    assignment_name: str | None = None,
    preflight_recorded: bool = False,
    expires_at: str | None = None,
) -> dict:
    """
    Grant temporary role assignment to a service principal.

    Args:
        sp_object_id: Object ID of the service principal
        scope: Resource scope (e.g., Key Vault resource ID)
        role_name: The role to assign (e.g., "Key Vault Secrets User")
        duration_minutes: How long access should last
        workflow_id: Identifier for the triggering workflow

    Returns:
        dict with assignment details
    """
    logging.info(f"Granting NHI access: sp={sp_object_id}, scope={scope}, role={role_name}, duration={duration_minutes}m")

    subscription_id = get_subscription_id_from_scope(scope)
    if auth_client is None:
        credential = DefaultAzureCredential()
        auth_client = AuthorizationManagementClient(credential, subscription_id)

    # A Durable lifecycle passes a deterministic name so an at-least-once
    # activity retry can recognize only its own prior side effect. Direct calls
    # retain a random name and the strict preexisting-entitlement guard.
    assignment_name = assignment_name or str(uuid.uuid4())

    # Get role definition ID
    role_definition_id = get_role_definition_id(role_name, subscription_id)

    matches = _matching_role_assignments(
        auth_client,
        sp_object_id=sp_object_id,
        scope=scope,
        role_name=role_name,
    )
    owned_assignment = next(
        (
            existing
            for existing in matches
            if preflight_recorded
            and _assignment_name(existing).casefold() == assignment_name.casefold()
        ),
        None,
    )
    foreign_matches = [existing for existing in matches if existing is not owned_assignment]
    if foreign_matches or (matches and owned_assignment is None):
        raise PreexistingEntitlementError(
            f"Service principal {sp_object_id} already has {role_name} on {scope}"
        )

    # Create role assignment
    assignment_params = RoleAssignmentCreateParameters(
        role_definition_id=role_definition_id,
        principal_id=sp_object_id,
        principal_type="ServicePrincipal"
    )

    created = owned_assignment is None
    assignment = owned_assignment
    if assignment is None:
        try:
            assignment = auth_client.role_assignments.create(
                scope=scope,
                role_assignment_name=assignment_name,
                parameters=assignment_params
            )
        except Exception as exc:
            if exception_error_code(exc) == "RoleAssignmentExists":
                # A prior activity attempt may have committed the deterministic
                # assignment before its completion event reached Durable storage.
                # Re-read and adopt only that exact saga-owned assignment name.
                retry_matches = _matching_role_assignments(
                    auth_client,
                    sp_object_id=sp_object_id,
                    scope=scope,
                    role_name=role_name,
                )
                assignment = next(
                    (
                        existing
                        for existing in retry_matches
                        if preflight_recorded
                        and _assignment_name(existing).casefold() == assignment_name.casefold()
                    ),
                    None,
                )
                if assignment is None or any(
                    existing is not assignment for existing in retry_matches
                ):
                    raise PreexistingEntitlementError(
                        f"Service principal {sp_object_id} already has {role_name} on {scope}"
                    ) from exc
                created = False
            else:
                raise

    expiry_value = expires_at or (
        datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)
    ).isoformat()
    assignment_id = getattr(assignment, "id", None) or (
        f"{scope.rstrip('/')}/providers/Microsoft.Authorization/"
        f"roleAssignments/{assignment_name}"
    )

    logging.info(
        "Role assignment %s: %s, expires at %s",
        "created" if created else "resumed",
        assignment_id,
        expiry_value,
    )

    return {
        "status": "granted",
        "assignment_id": assignment_id,
        "assignment_name": getattr(assignment, "name", None) or assignment_name,
        "sp_object_id": sp_object_id,
        "scope": scope,
        "role": role_name,
        "expires_at": expiry_value,
        "duration_minutes": duration_minutes,
        "workflow_id": workflow_id,
        "created": created,
    }


async def revoke_nhi_access(
    assignment_id: str,
    *,
    auth_client=None,
) -> dict:
    """
    Revoke NHI access by deleting the role assignment.

    Args:
        assignment_id: The full resource ID of the role assignment

    Returns:
        dict with revocation status
    """
    logging.info(f"Revoking NHI access: assignment={assignment_id}")

    # Extract subscription ID from assignment ID
    # Format: /subscriptions/{sub}/providers/.../roleAssignments/{name}
    # or: /subscriptions/{sub}/resourceGroups/{rg}/providers/.../roleAssignments/{name}
    parts = assignment_id.split("/")
    normalized_parts = [part.casefold() for part in parts]
    subscription_id = parts[normalized_parts.index("subscriptions") + 1]

    if auth_client is None:
        credential = DefaultAzureCredential()
        auth_client = AuthorizationManagementClient(credential, subscription_id)

    try:
        # Delete by ID
        auth_client.role_assignments.delete_by_id(assignment_id)
        logging.info(f"Role assignment deleted: {assignment_id}")

        return {
            "status": "revoked",
            "assignment_id": assignment_id,
            "revoked_at": datetime.now(timezone.utc).isoformat()
        }

    except Exception as exc:
        if is_explicit_not_found(exc):
            logging.info("Role assignment was already absent: %s", assignment_id)
            return {
                "status": "already_revoked",
                "assignment_id": assignment_id,
            }

        # Authentication, authorization, throttling, and service failures are
        # genuine revoke failures and must be retried/alerted, not normalized.
        logging.error("Failed to delete role assignment: %s", exc)
        raise


async def list_sp_role_assignments(sp_object_id: str, subscription_id: str) -> list:
    """
    List all role assignments for a service principal.
    Useful for auditing/verification.
    """
    credential = DefaultAzureCredential()
    auth_client = AuthorizationManagementClient(credential, subscription_id)

    assignments = auth_client.role_assignments.list_for_subscription(
        filter=f"principalId eq '{sp_object_id}'"
    )

    return [
        {
            "id": a.id,
            "scope": a.scope,
            "role_definition_id": a.role_definition_id,
            "created": a.created_on.isoformat() if a.created_on else None
        }
        for a in assignments
    ]
