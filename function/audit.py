"""
ZSP Audit Logging

Sends all access grant/revoke events to Log Analytics custom table.
"""

import logging
import os
from datetime import datetime, timezone
from azure.identity import DefaultAzureCredential
from azure.monitor.ingestion import LogsIngestionClient


class AuditWriteError(RuntimeError):
    """The access event could not be written to ZSPAudit_CL."""


async def log_access_event(
    event_type: str,
    identity_type: str,
    principal_id: str,
    target: str,
    target_type: str,
    result: str,
    role: str | None = None,
    duration_minutes: int | None = None,
    justification: str | None = None,
    ticket_id: str | None = None,
    workflow_id: str | None = None,
    expires_at: str | None = None,
    requested_by: str | None = None,
    error_message: str | None = None
):
    """
    Log an access event to Log Analytics.

    Args:
        event_type: "AccessGrant" or "AccessRevoke"
        identity_type: "human" or "nhi"
        principal_id: Object ID of the identity
        target: Target resource (group ID or resource scope)
        target_type: "EntraGroup" or "AzureResource"
        result: "Success" or "Failed"
        role: Role name (for NHI)
        duration_minutes: Access duration
        justification: Reason for access (for human)
        ticket_id: ITSM ticket reference
        workflow_id: Workflow identifier (for NHI)
        expires_at: Expiry timestamp
        requested_by: Who requested the access
        error_message: Error details if failed
    """

    dcr_endpoint = os.environ.get("DCR_ENDPOINT")
    dcr_rule_id = os.environ.get("DCR_RULE_ID")

    if not dcr_endpoint or not dcr_rule_id:
        logging.warning("DCR not configured, skipping audit log")
        return

    try:
        credential = DefaultAzureCredential()
        client = LogsIngestionClient(
            endpoint=dcr_endpoint,
            credential=credential
        )

        log_entry = {
            "TimeGenerated": datetime.now(timezone.utc).isoformat(),
            "EventType": event_type,
            "IdentityType": identity_type,
            "PrincipalId": principal_id,
            "PrincipalName": "",  # Could be enriched with display name
            "Target": target,
            "TargetType": target_type,
            "Role": role or "",
            "DurationMinutes": duration_minutes or 0,
            "Justification": justification or "",
            "TicketId": ticket_id or "",
            "WorkflowId": workflow_id or "",
            "ExpiresAt": expires_at or "",
            "RequestedBy": requested_by or "",
            "Result": result,
            "ErrorMessage": error_message or ""
        }

        client.upload(
            rule_id=dcr_rule_id,
            stream_name="Custom-ZSPAudit_CL",
            logs=[log_entry]
        )

        logging.info(f"Audit log sent: {event_type} for {principal_id}")

    except Exception as e:
        # The custom table is the only record a grant leaves behind, so a
        # transport failure has to reach the caller. Completing an access grant
        # with nothing in ZSPAudit_CL is the failure this lab exists to prevent;
        # the activity wrappers decide whether to retry or compensate.
        logging.error(f"Failed to send audit log: {e}")
        raise AuditWriteError(f"Failed to send audit log: {e}") from e


def build_kql_query_all_grants(hours: int = 24) -> str:
    """Return KQL query for all access grants in the specified period."""
    return f"""
ZSPAudit_CL
| where TimeGenerated > ago({hours}h)
| where EventType == "AccessGrant"
| project TimeGenerated, IdentityType, PrincipalId, Target, Role, DurationMinutes, Justification, WorkflowId, Result
| order by TimeGenerated desc
"""


def build_kql_query_failures() -> str:
    """Return KQL query for all failed access attempts."""
    return """
ZSPAudit_CL
| where Result == "Failed"
| project TimeGenerated, EventType, IdentityType, PrincipalId, Target, ErrorMessage
| order by TimeGenerated desc
"""


def build_kql_query_nhi_anomalies() -> str:
    """Return KQL query for NHI access outside expected patterns."""
    return """
ZSPAudit_CL
| where IdentityType == "nhi"
| where EventType == "AccessGrant"
| where WorkflowId !in ("nightly-backup", "manual-test")
| project TimeGenerated, PrincipalId, Target, Role, WorkflowId
| order by TimeGenerated desc
"""


def build_kql_query_human_no_ticket() -> str:
    """Return KQL query for human access without ticket reference."""
    return """
ZSPAudit_CL
| where IdentityType == "human"
| where EventType == "AccessGrant"
| where isempty(TicketId)
| project TimeGenerated, PrincipalId, Target, Justification
| order by TimeGenerated desc
"""


def build_kql_query_unrevoked_expired_grants(grace_minutes: int = 15) -> str:
    """Return KQL for grants that are past expiry with no successful revoke.

    This is the hunt for standing privilege. A lifecycle that refuses to revoke
    a membership it cannot prove it owns fails closed against deleting someone
    else's entitlement, but the granted access can remain live. Those cases
    surface here as an expired grant with no matching successful AccessRevoke.

    The grace window absorbs the normal gap between the expiry timer firing and
    the revoke activity completing, so a healthy lifecycle does not alert.
    """
    if not isinstance(grace_minutes, int) or isinstance(grace_minutes, bool) or grace_minutes < 1:
        raise ValueError("grace_minutes must be a positive integer")

    return f"""
let grace = {grace_minutes}m;
let grants =
    ZSPAudit_CL
    | where EventType == "AccessGrant" and Result == "Success"
    | where isnotempty(ExpiresAt)
    | extend Expiry = todatetime(ExpiresAt)
    | project GrantTime = TimeGenerated, PrincipalId, Target, Role, IdentityType, Expiry;
let revokes =
    ZSPAudit_CL
    | where EventType == "AccessRevoke" and Result == "Success"
    | project RevokeTime = TimeGenerated, PrincipalId, Target;
grants
| where Expiry < ago(grace)
| join kind=leftouter revokes on PrincipalId, Target
| where isnull(RevokeTime) or RevokeTime < GrantTime
| summarize
    Grants = count(),
    LastGrant = max(GrantTime),
    LastExpiry = max(Expiry)
  by PrincipalId, Target, Role, IdentityType
| extend
    MinutesOverdue = datetime_diff('minute', now(), LastExpiry),
    Finding = "Expired grant with no successful revoke"
| order by MinutesOverdue desc
"""
