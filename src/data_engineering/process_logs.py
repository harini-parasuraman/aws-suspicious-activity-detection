"""Parse and transform CloudTrail-style JSON for the local project prototype."""
from pathlib import Path
from typing import Any

import pandas as pd


def load_cloudtrail(path: str | Path) -> list[dict[str, Any]]:
    """Load a CloudTrail JSON file with a top-level Records array."""
    with Path(path).open("r", encoding="utf-8") as handle:
        payload = __import__("json").load(handle)

    if isinstance(payload, dict) and isinstance(payload.get("Records"), list):
        records = payload["Records"]
    elif isinstance(payload, list):
        records = payload
    else:
        raise ValueError("Expected a CloudTrail object with a 'Records' list or a JSON list.")

    return [record for record in records if isinstance(record, dict)]


def normalize_events(records: list[dict[str, Any]]) -> pd.DataFrame:
    """Flatten the common fields needed by the detection prototype."""
    rows = []
    for event in records:
        identity = event.get("userIdentity") or {}
        if not isinstance(identity, dict):
            identity = {}
        session = identity.get("sessionContext") or {}
        if not isinstance(session, dict):
            session = {}

        rows.append({
            "event_time": event.get("eventTime"),
            "event_name": event.get("eventName", "Unknown"),
            "event_source": event.get("eventSource", "Unknown"),
            "aws_region": event.get("awsRegion", "Unknown"),
            "source_ip": event.get("sourceIPAddress", "Unknown"),
            "identity_type": identity.get("type", "Unknown"),
            "identity_arn": identity.get("arn") or identity.get("principalId") or "Unknown",
            "error_code": event.get("errorCode") or "",
            "user_agent": event.get("userAgent", "Unknown"),
        })

    columns = [
        "event_time", "event_name", "event_source", "aws_region", "source_ip",
        "identity_type", "identity_arn", "error_code", "user_agent"
    ]
    frame = pd.DataFrame(rows, columns=columns)
    if not frame.empty:
        frame["event_time"] = pd.to_datetime(frame["event_time"], errors="coerce", utc=True)
        frame["event_name"] = frame["event_name"].fillna("Unknown")
        frame["event_source"] = frame["event_source"].fillna("Unknown")
        frame["identity_arn"] = frame["identity_arn"].fillna("Unknown")
        frame["error_code"] = frame["error_code"].fillna("")
    return frame


def build_activity_features(events: pd.DataFrame) -> pd.DataFrame:
    """Aggregate events by identity and 15-minute UTC window."""
    feature_columns = [
        "failed_login_count", "api_call_count", "distinct_event_count",
        "access_denied_count", "security_change_count"
    ]
    if events.empty:
        return pd.DataFrame(columns=["identity_arn", "window_start", *feature_columns])

    frame = events.copy()
    frame["event_time"] = pd.to_datetime(frame["event_time"], errors="coerce", utc=True)
    frame = frame.dropna(subset=["event_time"])
    if frame.empty:
        return pd.DataFrame(columns=["identity_arn", "window_start", *feature_columns])

    frame["identity_arn"] = frame["identity_arn"].fillna("Unknown")
    frame["window_start"] = frame["event_time"].dt.floor("15min")
    frame["failed_login"] = (
        frame["event_name"].eq("ConsoleLogin")
        & frame["error_code"].ne("")
    ).astype(int)
    frame["access_denied"] = frame["error_code"].str.contains(
        "AccessDenied|Unauthorized", case=False, na=False
    ).astype(int)
    security_events = {
        "PutBucketPolicy", "DeleteTrail", "StopLogging", "AuthorizeSecurityGroupIngress",
        "PutUserPolicy", "AttachUserPolicy", "CreateAccessKey"
    }
    frame["security_change"] = frame["event_name"].isin(security_events).astype(int)

    grouped = frame.groupby(["identity_arn", "window_start"], dropna=False)
    result = grouped.agg(
        failed_login_count=("failed_login", "sum"),
        api_call_count=("event_name", "size"),
        distinct_event_count=("event_name", "nunique"),
        access_denied_count=("access_denied", "sum"),
        security_change_count=("security_change", "sum"),
    ).reset_index()

    return result[["identity_arn", "window_start", *feature_columns]]
