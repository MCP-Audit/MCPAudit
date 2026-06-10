"""Cross-tool credential and data contamination (MCTS-T-1056)."""

from __future__ import annotations

from typing import Any

_SENSITIVE_DATA_MARKERS = ("token", "password", "secret", "api_key", "credential", "bearer", "session")
_CROSS_SERVICE_MARKERS = ("http", "fetch", "webhook", "email", "slack", "database", "sql")


def detect_cross_tool_contamination(event: dict[str, Any]) -> bool:
    """Detect compromised tool output flowing into a different privileged service tool."""
    source = str(event.get("source_tool") or event.get("compromised_tool") or "").lower()
    dest = str(
        event.get("destination_tool") or event.get("target_tool") or event.get("tool_name") or ""
    ).lower()
    if not source or not dest or source == dest:
        return False
    payload = str(
        event.get("transferred_data") or event.get("tool_output") or event.get("data") or ""
    ).lower()
    if not payload:
        return False
    has_secret = any(marker in payload for marker in _SENSITIVE_DATA_MARKERS)
    cross_service = any(marker in dest for marker in _CROSS_SERVICE_MARKERS)
    if has_secret and cross_service:
        return True
    if event.get("cross_service_data_flow") and event.get("unauthorized_transfer"):
        return True
    return bool(event.get("contamination_detected"))
