"""Approval workflow consent fatigue exploitation (MCTS-T-1046)."""

from __future__ import annotations

from typing import Any

_SENSITIVE_OPS = frozenset(
    {
        "credential_access",
        "system_execution",
        "file_deletion",
        "network_exfiltration",
        "privilege_escalation",
        "environment_variable_access",
        "secret_access",
    }
)
_HIGH_RISK = frozenset({"high", "critical"})


def detect_consent_fatigue(event: dict[str, Any]) -> bool:
    """Detect MFA-fatigue-style approval bombardment followed by sensitive grants."""
    rows = event.get("events") or event.get("approval_events")
    if isinstance(rows, list) and rows:
        return _detect_batch(rows)
    return _detect_single(event)


def _detect_single(event: dict[str, Any]) -> bool:
    event_type = str(event.get("event_type") or "")
    if event_type != "approval_granted":
        return False
    risk = str(event.get("risk_level") or "").lower()
    op = str(event.get("operation_type") or "").lower()
    if risk not in _HIGH_RISK and op not in _SENSITIVE_OPS:
        return False
    response_ms = int(event.get("response_time_ms") or 0)
    if response_ms and response_ms < 2000:
        return True
    hour = event.get("hour_of_day")
    if hour is not None and (int(hour) < 6 or int(hour) > 22):
        return True
    approval_rate = float(event.get("session_approval_rate") or 0)
    baseline_dev = float(event.get("baseline_deviation") or 0)
    if approval_rate > 90 and baseline_dev > 30:
        return True
    freq = int(event.get("approval_count_last_hour") or event.get("count") or 0)
    return freq >= 10


def _detect_batch(rows: list[Any]) -> bool:
    grants: list[dict[str, Any]] = []
    for row in rows:
        if isinstance(row, dict) and str(row.get("event_type") or "") == "approval_granted":
            grants.append(row)
    if len(grants) < 5:
        return False
    sensitive = [
        row
        for row in grants
        if str(row.get("risk_level") or "").lower() in _HIGH_RISK
        or str(row.get("operation_type") or "").lower() in _SENSITIVE_OPS
    ]
    if not sensitive:
        return False
    if len(grants) >= 10:
        return True
    rapid = [row for row in sensitive if int(row.get("response_time_ms") or 9999) < 2000]
    if rapid:
        return True
    times = [int(row.get("response_time_ms") or 0) for row in grants[-5:] if row.get("response_time_ms")]
    return bool(len(times) >= 3 and times[0] > 0 and times[-1] < times[0] * 0.7)
