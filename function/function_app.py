"""
Zero Standing Privilege Gateway - Azure Function App

Handles access requests for both human administrators and non-human identities.
All access is time-bounded and automatically revoked.
"""

import azure.functions as func
import azure.durable_functions as df
import logging
import json
import os
from datetime import datetime, timedelta, timezone

from admin_access import (
    ensure_admin_entitlement_absent,
    grant_admin_access,
    revoke_admin_access,
)
from nhi_access import (
    ROLE_DEFINITIONS,
    ensure_nhi_entitlement_absent,
    grant_nhi_access,
    revoke_nhi_access,
)
from audit import log_access_event
from access_safety import (
    PreexistingEntitlementError,
    RequestValidationError,
    build_admin_ownership_key,
    build_nhi_assignment_id,
    build_nhi_assignment_name,
    parse_positive_int_setting,
    validate_admin_request,
    validate_duration,
    validate_nhi_request,
)

app = df.DFApp(http_auth_level=func.AuthLevel.FUNCTION)
ADMIN_OWNER_ENTITY_NAME = "admin_entitlement_owner"


def _same_admin_owner(state: object, requested: dict) -> bool:
    """Return whether an entity state belongs to this exact lifecycle."""

    if not isinstance(state, dict):
        return False
    return (
        isinstance(state.get("orchestration_instance_id"), str)
        and state["orchestration_instance_id"] == requested["orchestration_instance_id"]
        and all(
            isinstance(state.get(field), str)
            and state[field].casefold() == requested[field].casefold()
            for field in ("user_id", "group_id")
        )
    )


@app.entity_trigger(
    context_name="context",
    entity_name=ADMIN_OWNER_ENTITY_NAME,
)
def admin_entitlement_owner(context: df.DurableEntityContext):
    """Serialize and record lifecycle ownership of one admin membership.

    A Durable Entity is addressed by the stable user/group ownership key. Its
    operations are serialized by Durable Functions, preventing two gateway
    orchestrations from both adopting and later revoking the same membership.
    """

    operation = context.operation_name
    requested = context.get_input()
    if not isinstance(requested, dict) or any(
        not isinstance(requested.get(field), str) or not requested[field]
        for field in ("orchestration_instance_id", "user_id", "group_id")
    ):
        raise ValueError("Admin ownership operation requires lifecycle, user, and group IDs")

    state = context.get_state(lambda: None)
    same_owner = _same_admin_owner(state, requested)

    if operation == "claim":
        if state is None:
            context.set_state(dict(requested))
            context.set_result({
                "claimed": True,
                "owner": requested["orchestration_instance_id"],
                "replayed": False,
            })
        elif same_owner:
            context.set_result({
                "claimed": True,
                "owner": requested["orchestration_instance_id"],
                "replayed": True,
            })
        else:
            current_owner = state.get("orchestration_instance_id") if isinstance(state, dict) else None
            context.set_result({
                "claimed": False,
                "owner": current_owner,
            })
    elif operation == "verify":
        context.set_result({
            "owned": same_owner,
            "owner": state.get("orchestration_instance_id") if isinstance(state, dict) else None,
        })
    elif operation == "release":
        if same_owner:
            context.destruct_on_exit()
            context.set_result({
                "released": True,
                "owner": requested["orchestration_instance_id"],
            })
        else:
            context.set_result({
                "released": False,
                "owner": state.get("orchestration_instance_id") if isinstance(state, dict) else None,
            })
    else:
        raise ValueError(f"Unsupported admin ownership operation: {operation}")

# Both HTTP triggers authenticate with a function key rather than with a user, so
# the only requester the gateway can vouch for is the entry point that started the
# lifecycle. Recording that keeps ZSPAudit_CL's RequestedBy column honest and out
# of the caller's control.
ADMIN_REQUEST_SOURCE = "api/admin-access"
NHI_REQUEST_SOURCE = "api/nhi-access"
BACKUP_TIMER_REQUEST_SOURCE = "backup-job-timer"


def _csv_env(name: str) -> set[str]:
    return {item.strip() for item in os.environ.get(name, "").split(",") if item.strip()}


def _json_response(payload: dict, status_code: int) -> func.HttpResponse:
    return func.HttpResponse(
        json.dumps(payload),
        status_code=status_code,
        mimetype="application/json"
    )


def _scope_is_allowed(scope: str) -> bool:
    allowed_scopes = _csv_env("ALLOWED_SCOPE_IDS")
    for env_name in ("KEYVAULT_RESOURCE_ID", "STORAGE_RESOURCE_ID"):
        value = os.environ.get(env_name)
        if value:
            allowed_scopes.add(value)

    if not allowed_scopes:
        return False

    return any(scope == allowed or scope.startswith(f"{allowed}/") for allowed in allowed_scopes)


def _nhi_roles_allowed() -> set[str]:
    configured = _csv_env("ALLOWED_NHI_ROLES")
    if configured:
        return configured

    return {
        "Key Vault Secrets User",
        "Key Vault Reader",
        "Storage Blob Data Reader",
        "Storage Blob Data Contributor",
        "Reader",
    }


def _workflow_ids_allowed() -> set[str]:
    configured = _csv_env("ALLOWED_WORKFLOW_IDS")
    if configured:
        return configured

    return {"manual-test", "nightly-backup"}


def _sp_ids_allowed() -> set[str]:
    configured = _csv_env("ALLOWED_NHI_SP_OBJECT_IDS")
    if configured:
        return configured

    backup_sp = os.environ.get("BACKUP_SP_OBJECT_ID")
    return {backup_sp} if backup_sp else set()


def _admin_groups_allowed() -> set[str]:
    configured = _csv_env("ALLOWED_ADMIN_GROUP_IDS")
    if configured:
        return configured

    groups = set()
    for env_name in ("INTUNE_ADMIN_GROUP_ID", "SECURITY_READER_GROUP_ID", "PIM_GROUP_ID"):
        value = os.environ.get(env_name)
        if value:
            groups.add(value)
    return groups


def _admin_users_allowed() -> set[str]:
    return _csv_env("ALLOWED_ADMIN_USER_IDS")


def _object_id_is_allowed(object_id: str, allowlist: set[str]) -> bool:
    """Compare UUID identifiers case-insensitively."""

    normalized = object_id.casefold()
    return any(candidate.casefold() == normalized for candidate in allowlist)


def _maximum_access_duration() -> int:
    return parse_positive_int_setting(
        os.environ.get("MAX_ACCESS_DURATION_MINUTES"),
        name="MAX_ACCESS_DURATION_MINUTES",
        default=480,
    )


def _activity_payload(value) -> dict:
    """Normalize an activity input supplied as decoded JSON or a JSON string."""

    payload = json.loads(value) if isinstance(value, str) else value
    if not isinstance(payload, dict):
        raise ValueError("Activity payload must be an object")
    return payload


async def _log_failed_access_event(error: Exception, **event_fields) -> None:
    """Best-effort custom audit row without masking the activity failure."""

    try:
        await log_access_event(
            **event_fields,
            result="Failed",
            error_message=str(error),
        )
    except Exception:
        logging.exception("Failed to record the custom audit failure row")


async def _start_access_lifecycle(req, client, client_input: dict) -> func.HttpResponse:
    """Persist orchestration history before any grant activity can execute."""

    try:
        instance_id = await client.start_new(
            "access_lifecycle_orchestrator",
            client_input=client_input,
        )
    except Exception as exc:
        logging.error("Unable to start access lifecycle orchestration: %s", exc)
        return _json_response(
            {"error": "Durable access scheduling is unavailable; no access was granted"},
            503,
        )

    if not isinstance(instance_id, str) or not instance_id.strip():
        logging.error("Durable Functions returned an empty lifecycle instance ID")
        return _json_response(
            {"error": "Durable access scheduling is unavailable; no access was granted"},
            503,
        )

    # The Durable management response is deliberately asynchronous. Clients can
    # inspect customStatus for `active` and later `revoked`; the HTTP trigger
    # itself never creates privilege before this instance is durably recorded.
    try:
        return client.create_check_status_response(req, instance_id)
    except Exception as exc:
        # History is already committed at this point. Preserve the accepted
        # response so a response-construction edge case cannot prompt a client
        # retry and create a second lifecycle.
        logging.error("Unable to build Durable management response for %s: %s", instance_id, exc)
        return _json_response(
            {
                "status": "accepted",
                "orchestrator_instance_id": instance_id,
            },
            202,
        )

# =============================================================================
# HTTP TRIGGERS - Access Request Endpoints
# =============================================================================

@app.route(route="api/admin-access", methods=["POST"])
@app.durable_client_input(client_name="client")
async def admin_access_request(req: func.HttpRequest, client) -> func.HttpResponse:
    """
    Handle human admin access requests.

    Request body:
    {
        "user_id": "entra-user-object-id",
        "group_id": "zsp-group-object-id",
        "duration_minutes": 60,
        "justification": "Reason for access",
        "ticket_id": "INC0012345" (optional)
    }
    """
    logging.info("Admin access request received")

    try:
        raw_body = req.get_json()
    except (TypeError, ValueError):
        return _json_response({"error": "Invalid JSON body"}, 400)

    try:
        body = validate_admin_request(raw_body, _maximum_access_duration())
    except RequestValidationError as exc:
        return _json_response({"error": str(exc)}, 400)
    except RuntimeError as exc:
        logging.error("Invalid ZSP duration configuration: %s", exc)
        return _json_response({"error": "Access duration policy is not configured correctly"}, 503)

    allowed_groups = _admin_groups_allowed()
    if not allowed_groups:
        return _json_response({"error": "Admin group allowlist is not configured"}, 503)
    if not _object_id_is_allowed(body["group_id"], allowed_groups):
        return _json_response({"error": "Group is not allowed for this lab deployment"}, 403)

    allowed_users = _admin_users_allowed()
    if not allowed_users:
        return _json_response({"error": "Admin user allowlist is not configured"}, 503)
    if not _object_id_is_allowed(body["user_id"], allowed_users):
        return _json_response({"error": "User is not allowed for this lab deployment"}, 403)

    return await _start_access_lifecycle(
        req,
        client,
        {
            "access_type": "admin",
            **body,
            "requested_by": ADMIN_REQUEST_SOURCE,
        },
    )


@app.route(route="api/nhi-access", methods=["POST"])
@app.durable_client_input(client_name="client")
async def nhi_access_request(req: func.HttpRequest, client) -> func.HttpResponse:
    """
    Handle non-human identity access requests.

    Request body:
    {
        "sp_object_id": "service-principal-object-id",
        "scope": "/subscriptions/.../resourceGroups/.../providers/...",
        "role": "Key Vault Secrets User",
        "duration_minutes": 30,
        "workflow_id": "nightly-backup"
    }
    """
    logging.info("NHI access request received")

    try:
        raw_body = req.get_json()
    except (TypeError, ValueError):
        return _json_response({"error": "Invalid JSON body"}, 400)

    try:
        body = validate_nhi_request(raw_body, _maximum_access_duration())
    except RequestValidationError as exc:
        return _json_response({"error": str(exc)}, 400)
    except RuntimeError as exc:
        logging.error("Invalid ZSP duration configuration: %s", exc)
        return _json_response({"error": "Access duration policy is not configured correctly"}, 503)

    # Fail closed: if no service-principal allowlist is configured, refuse the
    # request rather than accepting any caller-supplied sp_object_id. This mirrors
    # the admin-access path (503 when allowlists are unset) so the NHI grant path
    # cannot fail open on an empty allowlist.
    allowed_sp_ids = _sp_ids_allowed()
    if not allowed_sp_ids:
        return _json_response(
            {"error": "Service principal allowlist is not configured for this lab deployment"},
            503,
        )
    if not _object_id_is_allowed(body["sp_object_id"], allowed_sp_ids):
        return _json_response({"error": "Service principal is not allowed for this lab deployment"}, 403)

    if body["workflow_id"] not in _workflow_ids_allowed():
        return _json_response({"error": "Workflow ID is not allowed for this lab deployment"}, 403)

    if body["role"] not in _nhi_roles_allowed():
        return _json_response({"error": "Role is not allowed for this lab deployment"}, 403)

    # ALLOWED_NHI_ROLES can name a role the gateway holds no definition ID for.
    # Rejecting it during admission keeps that configuration mistake from turning
    # into a KeyError inside the preflight, long after the caller saw a 202.
    if body["role"] not in ROLE_DEFINITIONS:
        return _json_response({"error": "Role is not supported by this gateway"}, 400)

    if not _scope_is_allowed(body["scope"]):
        return _json_response({"error": "Requested scope is not allowed for this lab deployment"}, 403)

    return await _start_access_lifecycle(
        req,
        client,
        {
            "access_type": "nhi",
            **body,
            "requested_by": NHI_REQUEST_SOURCE,
        },
    )


# =============================================================================
# TIMER TRIGGERS - Scheduled NHI Access
# =============================================================================

@app.timer_trigger(schedule="%BACKUP_JOB_SCHEDULE%", arg_name="timer", run_on_startup=False)
@app.durable_client_input(client_name="client")
async def backup_job_access_grant(timer: func.TimerRequest, client):
    """
    Grant backup service principal access before the nightly job runs.
    Triggered by schedule (default: 1:55 AM daily).
    """
    logging.info("Backup job access grant triggered")

    sp_object_id = os.environ.get("BACKUP_SP_OBJECT_ID")
    keyvault_id = os.environ.get("KEYVAULT_RESOURCE_ID")
    storage_id = os.environ.get("STORAGE_RESOURCE_ID")

    if not all([sp_object_id, keyvault_id, storage_id]):
        logging.error("Missing environment variables for backup job")
        return

    try:
        duration = parse_positive_int_setting(
            os.environ.get("BACKUP_JOB_DURATION_MINUTES"),
            name="BACKUP_JOB_DURATION_MINUTES",
            default=35,
        )
        validate_duration(duration, _maximum_access_duration())
    except (RequestValidationError, RuntimeError) as exc:
        logging.error("Invalid backup access duration configuration: %s", exc)
        return

    try:
        grants = []
        for scope, role in (
            (keyvault_id, "Key Vault Secrets User"),
            (storage_id, "Storage Blob Data Contributor"),
        ):
            request = validate_nhi_request(
                {
                    "sp_object_id": sp_object_id,
                    "scope": scope,
                    "role": role,
                    "duration_minutes": duration,
                    "workflow_id": "nightly-backup",
                },
                _maximum_access_duration(),
            )
            grants.append(request)

        instance_id = await client.start_new(
            "access_lifecycle_orchestrator",
            client_input={
                "access_type": "nhi_bundle",
                "duration_minutes": duration,
                "workflow_id": "nightly-backup",
                "requested_by": BACKUP_TIMER_REQUEST_SOURCE,
                "grants": grants,
            },
        )
        if not isinstance(instance_id, str) or not instance_id.strip():
            raise RuntimeError("Durable Functions returned an empty lifecycle instance ID")
        logging.info(
            "Backup access lifecycle %s accepted for %s minutes; no grant was created by the timer trigger",
            instance_id,
            duration,
        )
    except Exception as exc:
        # No grant API is called in this trigger. A scheduling failure therefore
        # cannot leave partial backup privilege behind.
        logging.error("Backup access lifecycle could not be started: %s", exc)
        raise


# =============================================================================
# DURABLE FUNCTIONS - Grant, Wait, and Revoke Saga
# =============================================================================

@app.orchestration_trigger(context_name="context")
def access_lifecycle_orchestrator(context: df.DurableOrchestrationContext):
    """Own the complete entitlement lifecycle inside Durable history.

    The HTTP and timer triggers only start this orchestration.  Preflight, grant,
    expiry timer, and revoke are all Durable tasks, so a host crash can replay
    from recorded history instead of stranding an out-of-band grant.
    """

    input_data = context.get_input()
    if not isinstance(input_data, dict):
        raise ValueError("Access lifecycle input must be an object")

    access_type = input_data.get("access_type")
    duration = input_data.get("duration_minutes")
    if not isinstance(duration, int) or isinstance(duration, bool) or duration < 1:
        raise ValueError("duration_minutes must be a positive integer")

    if access_type in {"admin", "nhi"}:
        grants = [input_data]
    elif access_type == "nhi_bundle":
        grants = input_data.get("grants")
        if not isinstance(grants, list) or not grants:
            raise ValueError("nhi_bundle requires at least one grant")
    else:
        raise ValueError("Unsupported access_type")

    # Validate the full bundle before scheduling the first side effect. A bad
    # later entry must not be able to fail after an earlier entry was granted.
    expected_type = "admin" if access_type == "admin" else "nhi"
    required_fields = (
        {"user_id", "group_id", "justification"}
        if expected_type == "admin"
        else {"sp_object_id", "scope", "role", "workflow_id"}
    )
    for grant in grants:
        if not isinstance(grant, dict) or not required_fields.issubset(grant):
            raise ValueError(f"{expected_type.upper()} lifecycle input is incomplete")
        if any(not isinstance(grant[field], str) or not grant[field] for field in required_fields):
            raise ValueError(f"{expected_type.upper()} lifecycle fields must be non-empty strings")

    # An instance created before this field existed replays without it, so every
    # read of the requester has to tolerate its absence.
    requested_by = input_data.get("requested_by")

    expiry_time = context.current_utc_datetime + timedelta(minutes=duration)
    expiry_value = expiry_time.isoformat()
    retry_options = df.RetryOptions(5000, 5)
    instance_id = context.instance_id
    grant_results = []
    owned_revocations = []
    admin_owner_entity = None
    admin_owner_payload = None
    admin_owner_claimed = False

    context.set_custom_status({
        "status": "granting",
        "expires_at": expiry_value,
        "grant_count": len(grants),
    })

    for grant_index, grant in enumerate(grants):
        if access_type == "admin":
            admin_owner_payload = {
                "orchestration_instance_id": instance_id,
                "user_id": grant["user_id"],
                "group_id": grant["group_id"],
            }
            admin_owner_entity = df.EntityId(
                ADMIN_OWNER_ENTITY_NAME,
                build_admin_ownership_key(grant["user_id"], grant["group_id"]),
            )
            activity_payload = {
                "user_id": grant["user_id"],
                "group_id": grant["group_id"],
                "duration_minutes": duration,
                "justification": grant["justification"],
                "ticket_id": grant.get("ticket_id"),
                "expires_at": expiry_value,
                "requested_by": requested_by,
                "orchestration_instance_id": instance_id,
            }
            preflight_activity = "check_admin_entitlement_activity"
            grant_activity = "grant_admin_access_activity"
            revoke_activity = "revoke_group_membership_activity"
            revoke_payload = {
                "revocation_type": "group_membership",
                "user_id": grant["user_id"],
                "group_id": grant["group_id"],
                "requested_by": requested_by,
            }
        else:
            assignment_name = build_nhi_assignment_name(
                instance_id,
                grant_index,
                grant["sp_object_id"],
                grant["scope"],
                grant["role"],
            )
            assignment_id = build_nhi_assignment_id(grant["scope"], assignment_name)
            activity_payload = {
                "sp_object_id": grant["sp_object_id"],
                "scope": grant["scope"],
                "role": grant["role"],
                "duration_minutes": duration,
                "workflow_id": grant["workflow_id"],
                "assignment_name": assignment_name,
                "assignment_id": assignment_id,
                "expires_at": expiry_value,
                "requested_by": requested_by,
                "orchestration_instance_id": instance_id,
            }
            preflight_activity = "check_nhi_entitlement_activity"
            grant_activity = "grant_nhi_access_activity"
            revoke_activity = "revoke_role_assignment_activity"
            revoke_payload = {
                "revocation_type": "role_assignment",
                "assignment_id": assignment_id,
                "sp_object_id": grant["sp_object_id"],
                "scope": grant["scope"],
                "role": grant["role"],
                "requested_by": requested_by,
            }

        preflight_succeeded = False
        try:
            if admin_owner_entity is not None:
                claim_result = yield context.call_entity(
                    admin_owner_entity,
                    "claim",
                    admin_owner_payload,
                )
                if not isinstance(claim_result, dict):
                    raise RuntimeError("Admin ownership entity returned an invalid claim response")
                if not claim_result.get("claimed"):
                    raise PreexistingEntitlementError(
                        "Another active lifecycle already owns this user/group membership"
                    )
                if claim_result.get("owner") != instance_id:
                    raise RuntimeError("Admin ownership entity returned the wrong lifecycle owner")
                admin_owner_claimed = True

            # This successful absence check is committed to Durable history
            # before the at-least-once grant activity is scheduled.
            yield context.call_activity_with_retry(
                preflight_activity,
                retry_options,
                activity_payload,
            )
            preflight_succeeded = True
            result = yield context.call_activity_with_retry(
                grant_activity,
                retry_options,
                activity_payload,
            )
            grant_results.append(result)
            owned_revocations.append((revoke_activity, revoke_payload))
        except Exception as grant_error:
            # If the grant activity died after committing its side effect but
            # before recording completion, include its deterministic entitlement
            # in compensation. Previously completed bundle grants are also
            # revoked. task_all ensures every cleanup is attempted.
            cleanup = list(reversed(owned_revocations))
            if preflight_succeeded:
                cleanup.insert(0, (revoke_activity, revoke_payload))
            context.set_custom_status({
                "status": "compensating",
                "expires_at": expiry_value,
                "cleanup_count": len(cleanup),
            })

            # Never remove a group membership unless the serialized ownership
            # entity still proves that this exact lifecycle owns it.
            if cleanup and admin_owner_claimed:
                verify_result = yield context.call_entity(
                    admin_owner_entity,
                    "verify",
                    admin_owner_payload,
                )
                if (
                    not isinstance(verify_result, dict)
                    or not verify_result.get("owned")
                    or verify_result.get("owner") != instance_id
                ):
                    context.set_custom_status({
                        "status": "ownership_lost",
                        "expires_at": expiry_value,
                    })
                    # The refusal to delete is deliberate, but it can leave a live
                    # entitlement behind. Record that in ZSPAudit_CL before failing
                    # so the stranded grant is discoverable from the audit table
                    # rather than only from Durable instance history.
                    try:
                        yield context.call_activity_with_retry(
                            "record_ownership_lost_activity",
                            retry_options,
                            {
                                "user_id": admin_owner_payload["user_id"],
                                "group_id": admin_owner_payload["group_id"],
                                "requested_by": requested_by,
                                "expires_at": expiry_value,
                                "phase": "compensation",
                            },
                        )
                    except Exception:
                        # An audit transport failure must not mask the ownership
                        # error and must never turn into a deletion.
                        pass
                    raise RuntimeError(
                        "Admin ownership could not be proven during compensation; membership was not revoked"
                    ) from grant_error
            if cleanup:
                cleanup_tasks = [
                    context.call_activity_with_retry(name, retry_options, payload)
                    for name, payload in cleanup
                ]
                yield context.task_all(cleanup_tasks)
            if admin_owner_claimed:
                release_result = yield context.call_entity(
                    admin_owner_entity,
                    "release",
                    admin_owner_payload,
                )
                if (
                    not isinstance(release_result, dict)
                    or not release_result.get("released")
                    or release_result.get("owner") != instance_id
                ):
                    raise RuntimeError(
                        "Admin ownership could not be released after compensation"
                    ) from grant_error
                admin_owner_claimed = False
            raise grant_error

    context.set_custom_status({
        "status": "active",
        "expires_at": expiry_value,
        "grants": grant_results,
    })
    yield context.create_timer(expiry_time)

    context.set_custom_status({
        "status": "revoking",
        "expires_at": expiry_value,
        "grant_count": len(owned_revocations),
    })
    if admin_owner_claimed:
        verify_result = yield context.call_entity(
            admin_owner_entity,
            "verify",
            admin_owner_payload,
        )
        if (
            not isinstance(verify_result, dict)
            or not verify_result.get("owned")
            or verify_result.get("owner") != instance_id
        ):
            context.set_custom_status({
                "status": "ownership_lost",
                "expires_at": expiry_value,
            })
            # Expiry is the failure that matters most: the grant is past its
            # deadline and is deliberately not being revoked, so it must appear
            # in ZSPAudit_CL for the unmatched-expired-grant hunt to find it.
            try:
                yield context.call_activity_with_retry(
                    "record_ownership_lost_activity",
                    retry_options,
                    {
                        "user_id": admin_owner_payload["user_id"],
                        "group_id": admin_owner_payload["group_id"],
                        "requested_by": requested_by,
                        "expires_at": expiry_value,
                        "phase": "expiry",
                    },
                )
            except Exception:
                # An audit transport failure must not mask the ownership error
                # and must never turn into a deletion.
                pass
            raise RuntimeError(
                "Admin ownership could not be proven at expiry; membership was not revoked"
            )
    revoke_tasks = [
        context.call_activity_with_retry(name, retry_options, payload)
        for name, payload in reversed(owned_revocations)
    ]
    revoke_results = yield context.task_all(revoke_tasks)
    if admin_owner_claimed:
        release_result = yield context.call_entity(
            admin_owner_entity,
            "release",
            admin_owner_payload,
        )
        if (
            not isinstance(release_result, dict)
            or not release_result.get("released")
            or release_result.get("owner") != instance_id
        ):
            raise RuntimeError("Admin ownership could not be released after revocation")
        admin_owner_claimed = False
    completed_at = context.current_utc_datetime.isoformat()
    context.set_custom_status({
        "status": "revoked",
        "completed_at": completed_at,
    })

    return {
        "status": "revoked",
        "expires_at": expiry_value,
        "completed_at": completed_at,
        "grants": grant_results,
        "revocations": revoke_results,
    }


# Backward compatibility for already-scheduled lab instances created by older
# deployments. New requests never use this revoke-only orchestration.

@app.orchestration_trigger(context_name="context")
def revocation_orchestrator(context: df.DurableOrchestrationContext):
    """
    Orchestrator that waits until expiry time, then revokes access.
    """
    input_data = context.get_input()
    if not isinstance(input_data, dict):
        raise ValueError("Revocation input must be an object")

    revocation_type = input_data.get("revocation_type")
    if revocation_type not in {"group_membership", "role_assignment"}:
        raise ValueError("Unsupported revocation_type")

    # Wait until the specified expiry time
    # Require an explicit offset and normalize it instead of relabeling a local
    # time as UTC. Durable context time is deterministic during replay.
    expiry_time = datetime.fromisoformat(input_data["expiry_time"])
    if expiry_time.tzinfo is None:
        raise ValueError("expiry_time must include a timezone offset")
    expiry_time = expiry_time.astimezone(timezone.utc)
    yield context.create_timer(expiry_time)

    # Transient Graph/ARM failures must not silently strand access. The revoke
    # helpers only normalize an explicit 404; every other failure reaches this
    # bounded Durable retry policy and remains a failed orchestration if all
    # attempts are exhausted.
    retry_options = df.RetryOptions(5000, 5)
    activity_name = (
        "revoke_group_membership_activity"
        if revocation_type == "group_membership"
        else "revoke_role_assignment_activity"
    )
    yield context.call_activity_with_retry(activity_name, retry_options, input_data)

    return {
        "status": "revoked",
        "completed_at": context.current_utc_datetime.isoformat(),
    }


@app.activity_trigger(input_name="activityPayload")
async def check_admin_entitlement_activity(activityPayload):
    """Record absence in Durable history before a group membership is added."""

    input_data = _activity_payload(activityPayload)
    await ensure_admin_entitlement_absent(
        user_id=input_data["user_id"],
        group_id=input_data["group_id"],
    )
    return {"status": "absent"}


@app.activity_trigger(input_name="activityPayload")
async def grant_admin_access_activity(activityPayload):
    """Idempotently add a member after the recorded absence preflight."""

    input_data = _activity_payload(activityPayload)
    try:
        result = await grant_admin_access(
            user_id=input_data["user_id"],
            group_id=input_data["group_id"],
            duration_minutes=input_data["duration_minutes"],
            justification=input_data["justification"],
            ticket_id=input_data.get("ticket_id"),
            preflight_recorded=True,
            expires_at=input_data["expires_at"],
        )
    except Exception as exc:
        await _log_failed_access_event(
            exc,
            event_type="AccessGrant",
            identity_type="human",
            principal_id=input_data["user_id"],
            target=input_data["group_id"],
            target_type="EntraGroup",
            duration_minutes=input_data["duration_minutes"],
            justification=input_data["justification"],
            ticket_id=input_data.get("ticket_id"),
            expires_at=input_data["expires_at"],
            requested_by=input_data.get("requested_by"),
        )
        raise
    await log_access_event(
        event_type="AccessGrant",
        identity_type="human",
        principal_id=input_data["user_id"],
        target=input_data["group_id"],
        target_type="EntraGroup",
        duration_minutes=input_data["duration_minutes"],
        justification=input_data["justification"],
        ticket_id=input_data.get("ticket_id"),
        expires_at=input_data["expires_at"],
        requested_by=input_data.get("requested_by"),
        result="Success",
    )
    return result


@app.activity_trigger(input_name="activityPayload")
async def check_nhi_entitlement_activity(activityPayload):
    """Record exact RBAC absence before the deterministic assignment is made."""

    input_data = _activity_payload(activityPayload)
    await ensure_nhi_entitlement_absent(
        sp_object_id=input_data["sp_object_id"],
        scope=input_data["scope"],
        role_name=input_data["role"],
    )
    return {"status": "absent"}


@app.activity_trigger(input_name="activityPayload")
async def grant_nhi_access_activity(activityPayload):
    """Create or resume only this saga's deterministic RBAC assignment."""

    input_data = _activity_payload(activityPayload)
    try:
        result = await grant_nhi_access(
            sp_object_id=input_data["sp_object_id"],
            scope=input_data["scope"],
            role_name=input_data["role"],
            duration_minutes=input_data["duration_minutes"],
            workflow_id=input_data["workflow_id"],
            assignment_name=input_data["assignment_name"],
            preflight_recorded=True,
            expires_at=input_data["expires_at"],
        )
    except Exception as exc:
        await _log_failed_access_event(
            exc,
            event_type="AccessGrant",
            identity_type="nhi",
            principal_id=input_data["sp_object_id"],
            target=input_data["scope"],
            target_type="AzureResource",
            role=input_data["role"],
            duration_minutes=input_data["duration_minutes"],
            workflow_id=input_data["workflow_id"],
            expires_at=input_data["expires_at"],
            requested_by=input_data.get("requested_by"),
        )
        raise
    await log_access_event(
        event_type="AccessGrant",
        identity_type="nhi",
        principal_id=input_data["sp_object_id"],
        target=input_data["scope"],
        target_type="AzureResource",
        role=input_data["role"],
        duration_minutes=input_data["duration_minutes"],
        workflow_id=input_data["workflow_id"],
        expires_at=input_data["expires_at"],
        requested_by=input_data.get("requested_by"),
        result="Success",
    )
    return result


@app.activity_trigger(input_name="activityPayload")
async def revoke_group_membership_activity(activityPayload):
    """Idempotently remove a user from the dedicated ZSP group."""

    input_data = _activity_payload(activityPayload)
    try:
        result = await revoke_admin_access(
            user_id=input_data["user_id"],
            group_id=input_data["group_id"],
        )
    except Exception as exc:
        await _log_failed_access_event(
            exc,
            event_type="AccessRevoke",
            identity_type="human",
            principal_id=input_data["user_id"],
            target=input_data["group_id"],
            target_type="EntraGroup",
            requested_by=input_data.get("requested_by"),
        )
        raise
    await log_access_event(
        event_type="AccessRevoke",
        identity_type="human",
        principal_id=input_data["user_id"],
        target=input_data["group_id"],
        target_type="EntraGroup",
        requested_by=input_data.get("requested_by"),
        result="Success",
    )
    return result


@app.activity_trigger(input_name="activityPayload")
async def revoke_role_assignment_activity(activityPayload):
    """Idempotently delete the deterministic RBAC role assignment."""

    input_data = _activity_payload(activityPayload)
    try:
        result = await revoke_nhi_access(assignment_id=input_data["assignment_id"])
    except Exception as exc:
        await _log_failed_access_event(
            exc,
            event_type="AccessRevoke",
            identity_type="nhi",
            principal_id=input_data["sp_object_id"],
            target=input_data["scope"],
            target_type="AzureResource",
            role=input_data.get("role"),
            requested_by=input_data.get("requested_by"),
        )
        raise
    await log_access_event(
        event_type="AccessRevoke",
        identity_type="nhi",
        principal_id=input_data["sp_object_id"],
        target=input_data["scope"],
        target_type="AzureResource",
        role=input_data.get("role"),
        requested_by=input_data.get("requested_by"),
        result="Success",
    )
    return result


@app.activity_trigger(input_name="activityPayload")
async def record_ownership_lost_activity(activityPayload):
    """Record a deliberately un-revoked entitlement in ZSPAudit_CL.

    The orchestrator refuses to delete a group membership it cannot prove it
    owns, because Graph membership edges carry no owner token and a blind
    delete could remove a newer, independently managed entitlement. That is the
    right call, but it can leave temporary privilege in place. Without this row
    the only trace is Durable instance history, which no KQL hunt reads.
    """

    input_data = _activity_payload(activityPayload)
    phase = str(input_data.get("phase", "unknown"))
    await log_access_event(
        event_type="AccessRevoke",
        identity_type="human",
        principal_id=input_data["user_id"],
        target=input_data["group_id"],
        target_type="EntraGroup",
        expires_at=input_data.get("expires_at"),
        requested_by=input_data.get("requested_by"),
        result="Failed",
        error_message=(
            f"ownership_lost during {phase}: the lifecycle could not prove it owns "
            "this membership, so it was intentionally not revoked and may still be "
            "active. Follow the manual recovery runbook in README.md."
        ),
    )
    return {"status": "ownership_lost_recorded", "phase": phase}


# =============================================================================
# HEALTH CHECK
# =============================================================================

@app.route(route="api/health", methods=["GET"])
def health_check(req: func.HttpRequest) -> func.HttpResponse:
    """Simple health check endpoint."""
    return func.HttpResponse(
        json.dumps({
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "1.0.0"
        }),
        status_code=200,
        mimetype="application/json"
    )
