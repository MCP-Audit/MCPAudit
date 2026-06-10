"""Token theft via API response bodies (MCTS-T-1075)."""

from __future__ import annotations

from typing import Any

_TOKEN_TOOL_MARKERS = (
    "token",
    "access_token",
    "session.token",
    "session_token",
    "auth_token",
    "debug_token",
    "get_token",
)

_TOKEN_BODY_MARKERS = (
    "access_token",
    "refresh_token",
    "bearer ",
    "session_token",
    "id_token",
    "token_type",
)

_SENSITIVE_TOOL_DESC = ("debug", "introspect", "oauth", "session")


def detect_token_api_theft(event: dict[str, Any]) -> bool:
    """Detect OAuth/session tokens exposed in MCP API tool responses."""
    if event.get("token_theft") or event.get("sensitive_token_in_response"):
        return True

    tool = str(event.get("tool_name", "")).lower()
    if any(marker in tool for marker in _TOKEN_TOOL_MARKERS):
        return True

    body = str(
        event.get("response_body") or event.get("api_response") or event.get("tool_output") or ""
    ).lower()
    if not body or not any(marker in body for marker in _TOKEN_BODY_MARKERS):
        return False

    desc = str(event.get("tool_description") or "").lower()
    return any(marker in desc for marker in _SENSITIVE_TOOL_DESC) or "eyJ" in body
