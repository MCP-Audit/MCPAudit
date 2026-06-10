"""High-frequency automated data collection via MCP tools (MCTS-T-1044)."""

from __future__ import annotations

from typing import Any

_READ_TOOL_PREFIXES = ("get_", "read_", "query_", "fetch_", "list_", "search_")
_CREDENTIAL_MARKERS = ("password", "api_key", "secret", "token", ".env", "credential")
_BURST_THRESHOLD = 25
_WINDOW_SECONDS = 300


def detect_data_harvesting(event: dict[str, Any]) -> bool:
    """Detect burst read/query activity or coordinated multi-server harvesting."""
    rows = event.get("events")
    if isinstance(rows, list) and rows:
        return _detect_batch(rows)
    return _detect_single(event)


def _detect_single(event: dict[str, Any]) -> bool:
    tool = str(event.get("tool_name", "")).lower()
    if not _is_read_tool(tool):
        return False
    count = int(event.get("call_count") or event.get("count") or 0)
    if count >= _BURST_THRESHOLD:
        return True
    params = str(event.get("tool_parameters") or event.get("parameters") or "").lower()
    if count >= 10 and any(marker in params for marker in _CREDENTIAL_MARKERS):
        return True
    servers = int(event.get("distinct_servers") or 0)
    return count >= 8 and servers >= 2 and bool(event.get("coordination") == "sequential")


def _detect_batch(rows: list[Any]) -> bool:
    session_counts: dict[str, int] = {}
    session_servers: dict[str, set[str]] = {}
    session_has_cred_keywords: dict[str, bool] = {}

    for row in rows:
        if not isinstance(row, dict):
            continue
        tool = str(row.get("tool_name", "")).lower()
        if not _is_read_tool(tool):
            continue
        session = str(row.get("session_id") or row.get("credential_id") or "default")
        session_counts[session] = session_counts.get(session, 0) + 1
        server = str(row.get("server_id") or row.get("server_name") or "")
        if server:
            session_servers.setdefault(session, set()).add(server)
        params = str(row.get("tool_parameters") or row.get("parameters") or "").lower()
        if any(marker in params for marker in _CREDENTIAL_MARKERS):
            session_has_cred_keywords[session] = True

    for session, count in session_counts.items():
        if count >= _BURST_THRESHOLD:
            return True
        if count >= 10 and session_has_cred_keywords.get(session):
            return True
        if count >= 8 and len(session_servers.get(session, set())) >= 2:
            return True
    return False


def _is_read_tool(tool_name: str) -> bool:
    if not tool_name:
        return False
    if any(tool_name.startswith(prefix) for prefix in _READ_TOOL_PREFIXES):
        return True
    return any(token in tool_name for token in ("read", "fetch", "query", "list", "search", "export"))
