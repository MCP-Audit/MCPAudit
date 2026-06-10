"""MCP agent external API flooding (MCTS-T-1078)."""

from __future__ import annotations

from typing import Any

_HTTP_TOOL_MARKERS = (
    "http.get",
    "http.post",
    "http.put",
    "http.delete",
    "api.call",
    "rest.request",
    "http_request",
    "api_call",
)

_FLOOD_THRESHOLD = 50


def detect_api_flooding(event: dict[str, Any]) -> bool:
    """Detect abusive outbound API request volume from MCP agents."""
    if event.get("api_flooding"):
        return True

    rows = event.get("events")
    if isinstance(rows, list) and rows:
        return _detect_batch(rows)

    tool = str(event.get("tool_name", "")).lower()
    if not _is_http_tool(tool):
        return False

    rate = int(event.get("requests_per_minute") or event.get("call_rate") or 0)
    if rate >= _FLOOD_THRESHOLD:
        return True
    return int(event.get("request_count") or 0) >= _FLOOD_THRESHOLD


def _detect_batch(rows: list[Any]) -> bool:
    session_counts: dict[str, int] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        tool = str(row.get("tool_name", "")).lower()
        if not _is_http_tool(tool):
            continue
        session = str(row.get("session_id") or "default")
        session_counts[session] = session_counts.get(session, 0) + 1
    return any(count >= _FLOOD_THRESHOLD for count in session_counts.values())


def _is_http_tool(name: str) -> bool:
    return any(marker in name for marker in _HTTP_TOOL_MARKERS) or name.startswith("http")
