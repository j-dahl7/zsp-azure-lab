"""
ZSP Audit Logging

Sends all access grant/revoke events to Log Analytics custom table.
"""

import logging
import os
from datetime import datetime, timezone
from typing import Iterable, Mapping
from urllib.parse import urlparse

from azure.identity import DefaultAzureCredential
from azure.monitor.ingestion import LogsIngestionClient


class AuditWriteError(RuntimeError):
    """The access event could not be written to ZSPAudit_CL."""


class AuditConfigurationError(AuditWriteError):
    """Audit ingestion is not configured safely enough to permit a grant."""


def audit_configuration_status() -> dict:
    """Return a non-secret readiness assessment for the audit ingestion path."""

    endpoint = os.environ.get("DCR_ENDPOINT", "").strip()
    rule_id = os.environ.get("DCR_RULE_ID", "").strip()
    issues = []

    if not endpoint:
        issues.append("DCR_ENDPOINT is missing")
    else:
        parsed = urlparse(endpoint)
        if parsed.scheme.casefold() != "https" or not parsed.netloc:
            issues.append("DCR_ENDPOINT must be an HTTPS URL")

    if not rule_id:
        issues.append("DCR_RULE_ID is missing")
    elif not rule_id.casefold().startswith("dcr-"):
        issues.append("DCR_RULE_ID must be an immutable dcr- ID")

    return {
        "ready": not issues,
        "issues": issues,
        "endpoint": endpoint,
        "rule_id": rule_id,
    }


def require_audit_configuration() -> tuple[str, str]:
    """Return the DCR settings or fail closed before privilege is granted."""

    status = audit_configuration_status()
    if not status["ready"]:
        raise AuditConfigurationError("; ".join(status["issues"]))
    return status["endpoint"], status["rule_id"]


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
    lifecycle_id: str | None = None,
    entitlement_id: str | None = None,
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
        lifecycle_id: Durable orchestration instance that owns the event
        entitlement_id: Exact group-membership or role-assignment identifier
        expires_at: Expiry timestamp
        requested_by: Who requested the access
        error_message: Error details if failed
    """

    dcr_endpoint, dcr_rule_id = require_audit_configuration()

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
            "LifecycleId": lifecycle_id or "",
            "EntitlementId": entitlement_id or "",
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
| project TimeGenerated, IdentityType, PrincipalId, Target, Role, DurationMinutes, Justification, WorkflowId, LifecycleId, EntitlementId, Result
| order by TimeGenerated desc
"""


def build_kql_query_failures() -> str:
    """Return KQL query for all failed access attempts."""
    return """
ZSPAudit_CL
| where Result == "Failed"
| project TimeGenerated, EventType, IdentityType, PrincipalId, Target, LifecycleId, EntitlementId, ErrorMessage
| order by TimeGenerated desc
"""


def build_kql_query_nhi_anomalies() -> str:
    """Return KQL query for NHI access outside expected patterns."""
    return """
ZSPAudit_CL
| where IdentityType == "nhi"
| where EventType == "AccessGrant"
| where WorkflowId !in ("nightly-backup", "manual-test")
| project TimeGenerated, PrincipalId, Target, Role, WorkflowId, LifecycleId, EntitlementId
| order by TimeGenerated desc
"""


def build_kql_query_human_no_ticket() -> str:
    """Return KQL query for human access without ticket reference."""
    return """
ZSPAudit_CL
| where IdentityType == "human"
| where EventType == "AccessGrant"
| where isempty(TicketId)
| project TimeGenerated, PrincipalId, Target, Justification, LifecycleId, EntitlementId
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
let exact_grants =
    ZSPAudit_CL
    | where EventType == "AccessGrant" and Result == "Success"
    | where isnotempty(ExpiresAt)
    | extend Expiry = todatetime(ExpiresAt)
    | where Expiry < ago(grace)
    | where isnotempty(LifecycleId) and isnotempty(EntitlementId)
    | summarize
        GrantTime = min(TimeGenerated),
        LastExpiry = max(Expiry),
        PrincipalId = take_any(PrincipalId),
        Target = take_any(Target),
        Role = take_any(Role),
        IdentityType = take_any(IdentityType)
      by LifecycleId, EntitlementId;
let exact_revokes =
    ZSPAudit_CL
    | where EventType == "AccessRevoke" and Result == "Success"
    | where isnotempty(LifecycleId) and isnotempty(EntitlementId)
    | summarize RevokeTime = max(TimeGenerated) by LifecycleId, EntitlementId;
let exact_findings =
    exact_grants
    | join kind=leftanti exact_revokes on LifecycleId, EntitlementId
    | extend
        MinutesOverdue = datetime_diff('minute', now(), LastExpiry),
        CorrelationStatus = "Exact",
        Finding = "Expired lifecycle entitlement with no successful revoke";
let legacy_findings =
    ZSPAudit_CL
    | where EventType == "AccessGrant" and Result == "Success"
    | where isnotempty(ExpiresAt)
    | extend LastExpiry = todatetime(ExpiresAt)
    | where LastExpiry < ago(grace)
    | where isempty(LifecycleId) or isempty(EntitlementId)
    | project
        GrantTime = TimeGenerated,
        LastExpiry,
        PrincipalId,
        Target,
        Role,
        IdentityType,
        LifecycleId,
        EntitlementId
    | extend
        MinutesOverdue = datetime_diff('minute', now(), LastExpiry),
        CorrelationStatus = "LegacyUncorrelated",
        Finding = "Legacy expired grant lacks exact lifecycle correlation; review manually";
union exact_findings, legacy_findings
| project
    GrantTime,
    LastExpiry,
    PrincipalId,
    Target,
    Role,
    IdentityType,
    LifecycleId,
    EntitlementId,
    MinutesOverdue = datetime_diff('minute', now(), LastExpiry),
    CorrelationStatus,
    Finding
| order by MinutesOverdue desc
"""


def evaluate_unrevoked_expired_grants(
    events: Iterable[Mapping[str, object]],
    *,
    now: datetime,
    grace_minutes: int = 15,
) -> list[dict]:
    """Evaluate the hunt's exact-correlation semantics without a Kusto service.

    This reference implementation supports regression tests and offline incident
    tooling. Legacy events are surfaced as uncorrelated review items; they are
    never guessed against another lifecycle using principal and target fields.
    """

    if not isinstance(grace_minutes, int) or isinstance(grace_minutes, bool) or grace_minutes < 1:
        raise ValueError("grace_minutes must be a positive integer")
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")

    events = list(events)
    cutoff = now.timestamp() - (grace_minutes * 60)
    exact_revocations = {
        (str(event.get("LifecycleId", "")), str(event.get("EntitlementId", "")))
        for event in events
        if event.get("EventType") == "AccessRevoke"
        and event.get("Result") == "Success"
        and event.get("LifecycleId")
        and event.get("EntitlementId")
    }

    findings: dict[tuple[str, str], dict] = {}
    legacy_findings = []
    for event in events:
        if event.get("EventType") != "AccessGrant" or event.get("Result") != "Success":
            continue
        expires_at = event.get("ExpiresAt")
        if not isinstance(expires_at, str) or not expires_at:
            continue
        try:
            expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except ValueError:
            continue
        if expiry.tzinfo is None or expiry.timestamp() >= cutoff:
            continue

        lifecycle_id = str(event.get("LifecycleId", ""))
        entitlement_id = str(event.get("EntitlementId", ""))
        finding = dict(event)
        if not lifecycle_id or not entitlement_id:
            finding["CorrelationStatus"] = "LegacyUncorrelated"
            legacy_findings.append(finding)
            continue

        key = (lifecycle_id, entitlement_id)
        if key not in exact_revocations:
            finding["CorrelationStatus"] = "Exact"
            findings[key] = finding

    return [*findings.values(), *legacy_findings]
