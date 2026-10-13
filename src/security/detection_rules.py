"""Transparent, configurable rules for illustrative suspicious activity."""
from typing import Any

DEFAULT_FAILED_LOGIN_THRESHOLD = 3
SECURITY_SENSITIVE_EVENTS = {
    "DeleteTrail",
    "StopLogging",
    "PutBucketPolicy",
    "PutUserPolicy",
    "AttachUserPolicy",
    "CreateAccessKey",
    "AuthorizeSecurityGroupIngress",
}


def detect_rule_findings(
    events,
    failed_login_threshold: int = DEFAULT_FAILED_LOGIN_THRESHOLD,
) -> list[dict[str, Any]]:
    """Return explainable findings; this function does not prove malicious intent."""
    findings: list[dict[str, Any]] = []
    failed_by_identity: dict[str, list[dict[str, Any]]] = {}

    for _, row in events.iterrows():
        event_name = str(row.get("event_name", "Unknown"))
        error_code = str(row.get("error_code", "") or "")
        identity = str(row.get("identity_arn", "Unknown"))

        if event_name == "ConsoleLogin" and error_code:
            failed_by_identity.setdefault(identity, []).append(row.to_dict())

        if event_name in SECURITY_SENSITIVE_EVENTS:
            findings.append({
                "rule_id": "SECURITY_SENSITIVE_API",
                "severity": "review",
                "identity_arn": identity,
                "event_name": event_name,
                "event_time": str(row.get("event_time", "")),
                "reason": f"Sensitive security-related API event observed: {event_name}",
                "source_ip": str(row.get("source_ip", "Unknown")),
            })

        if "AccessDenied" in error_code or "Unauthorized" in error_code:
            findings.append({
                "rule_id": "ACCESS_DENIED_EVENT",
                "severity": "low",
                "identity_arn": identity,
                "event_name": event_name,
                "event_time": str(row.get("event_time", "")),
                "reason": f"Access-denied style error observed: {error_code}",
                "source_ip": str(row.get("source_ip", "Unknown")),
            })

    for identity, failed_events in failed_by_identity.items():
        if len(failed_events) >= failed_login_threshold:
            latest = failed_events[-1]
            findings.append({
                "rule_id": "REPEATED_FAILED_CONSOLE_LOGIN",
                "severity": "review",
                "identity_arn": identity,
                "event_name": "ConsoleLogin",
                "event_time": str(latest.get("event_time", "")),
                "reason": (
                    f"{len(failed_events)} failed ConsoleLogin events in the input "
                    f"file (threshold: {failed_login_threshold}); investigate context."
                ),
                "source_ip": str(latest.get("source_ip", "Unknown")),
            })

    return findings
