"""
Human Administrator Access Management

Handles adding/removing users to/from ZSP security groups.
"""

import logging
from datetime import datetime, timedelta, timezone
from azure.identity import DefaultAzureCredential
from msgraph import GraphServiceClient
from msgraph.generated.models.reference_create import ReferenceCreate

from access_safety import PreexistingEntitlementError, is_explicit_not_found


async def _is_direct_group_member(graph_client, group_id: str, user_id: str) -> bool:
    """Check every page of a group's direct members and fail closed on errors."""

    member_request = graph_client.groups.by_group_id(group_id).members
    page = await member_request.get()
    seen_next_links: set[str] = set()
    normalized_user_id = user_id.casefold()

    while page is not None:
        members = getattr(page, "value", None)
        if members is None:
            raise RuntimeError("Microsoft Graph returned a malformed membership page")
        for member in members:
            member_id = getattr(member, "id", None)
            if isinstance(member_id, str) and member_id.casefold() == normalized_user_id:
                return True

        next_link = getattr(page, "odata_next_link", None)
        if not next_link:
            return False
        if next_link in seen_next_links:
            raise RuntimeError("Microsoft Graph returned a membership pagination cycle")
        seen_next_links.add(next_link)
        page = await member_request.with_url(next_link).get()

    raise RuntimeError("Microsoft Graph returned an empty membership response")


async def ensure_admin_entitlement_absent(
    user_id: str,
    group_id: str,
    *,
    graph_client=None,
) -> None:
    """Fail closed unless the user is absent from the dedicated ZSP group."""

    if graph_client is None:
        credential = DefaultAzureCredential()
        graph_client = GraphServiceClient(credential)

    if await _is_direct_group_member(graph_client, group_id, user_id):
        raise PreexistingEntitlementError(
            f"User {user_id} is already a direct member of group {group_id}"
        )


async def grant_admin_access(
    user_id: str,
    group_id: str,
    duration_minutes: int,
    justification: str,
    ticket_id: str | None = None,
    *,
    graph_client=None,
    preflight_recorded: bool = False,
    expires_at: str | None = None,
) -> dict:
    """
    Grant temporary admin access by adding user to ZSP group.

    Args:
        user_id: Entra object ID of the requesting user
        group_id: Object ID of the ZSP security group
        duration_minutes: How long access should last
        justification: Required reason for access
        ticket_id: Optional ITSM ticket reference

    Returns:
        dict with grant details and expiry time
    """
    logging.info(f"Granting admin access: user={user_id}, group={group_id}, duration={duration_minutes}m")

    # Initialize Graph client with managed identity
    if graph_client is None:
        credential = DefaultAzureCredential()
        graph_client = GraphServiceClient(credential)

    already_present = await _is_direct_group_member(graph_client, group_id, user_id)
    if already_present and not preflight_recorded:
        raise PreexistingEntitlementError(
            f"User {user_id} is already a direct member of group {group_id}"
        )

    if not already_present:
        request_body = ReferenceCreate(
            odata_id=f"https://graph.microsoft.com/v1.0/directoryObjects/{user_id}"
        )
        await graph_client.groups.by_group_id(group_id).members.ref.post(request_body)
    else:
        # The orchestrator records a successful absence preflight before it
        # schedules this activity. Seeing the member here therefore means an
        # earlier at-least-once activity attempt already performed the add. ZSP
        # groups are gateway-owned; Setup-EntraID rejects adopted groups.
        logging.info(
            "Resuming Durable admin grant for user %s in dedicated group %s",
            user_id,
            group_id,
        )

    expiry_value = expires_at or (
        datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)
    ).isoformat()

    logging.info(
        "User %s %s group %s, expires at %s",
        user_id,
        "already present in" if already_present else "added to",
        group_id,
        expiry_value,
    )

    return {
        "status": "granted",
        "user_id": user_id,
        "group_id": group_id,
        "expires_at": expiry_value,
        "duration_minutes": duration_minutes,
        "justification": justification,
        "ticket_id": ticket_id,
        "created": not already_present,
    }


async def revoke_admin_access(
    user_id: str,
    group_id: str,
    *,
    graph_client=None,
) -> dict:
    """
    Revoke admin access by removing user from ZSP group.

    Args:
        user_id: Entra object ID of the user to remove
        group_id: Object ID of the ZSP security group

    Returns:
        dict with revocation status
    """
    logging.info(f"Revoking admin access: user={user_id}, group={group_id}")

    if graph_client is None:
        credential = DefaultAzureCredential()
        graph_client = GraphServiceClient(credential)

    try:
        await graph_client.groups.by_group_id(group_id).members.by_directory_object_id(user_id).ref.delete()
        logging.info(f"User {user_id} removed from group {group_id}")

        return {
            "status": "revoked",
            "user_id": user_id,
            "group_id": group_id,
            "revoked_at": datetime.now(timezone.utc).isoformat()
        }

    except Exception as exc:
        if is_explicit_not_found(exc):
            logging.info(
                "User %s was already absent from group %s",
                user_id,
                group_id,
            )
            return {
                "status": "already_revoked",
                "user_id": user_id,
                "group_id": group_id,
            }

        # Authentication, authorization, throttling, and service failures must
        # reach Durable Functions so its retry/failure handling can act on them.
        logging.error("Failed to remove user from group: %s", exc)
        raise


async def get_user_display_name(user_id: str) -> str | None:
    """Get the display name for a user ID (for logging)."""
    try:
        credential = DefaultAzureCredential()
        graph_client = GraphServiceClient(credential)
        user = await graph_client.users.by_user_id(user_id).get()
        return user.display_name if user else None
    except Exception:
        return None


async def get_group_display_name(group_id: str) -> str | None:
    """Get the display name for a group ID (for logging)."""
    try:
        credential = DefaultAzureCredential()
        graph_client = GraphServiceClient(credential)
        group = await graph_client.groups.by_group_id(group_id).get()
        return group.display_name if group else None
    except Exception:
        return None
