"""MCP tool manifest enumeration abuse (MCTS-T-1042)."""

from __future__ import annotations

from typing import Any

_LIST_METHOD = "tools/list"
_CALL_METHOD = "tools/call"
_UNKNOWN_TOOL_ERROR = -32602

_HIGH_VOLUME_THRESHOLD = 50
_CROSS_SERVER_THRESHOLD = 5
_FINGERPRINT_THRESHOLD = 10
_LIST_ONLY_SESSION_SECONDS = 60


def detect_tool_enumeration(event: dict[str, Any]) -> bool:
    """Detect abusive tools/list volume, cross-server sweeps, or fingerprinting."""
    rows = _event_rows(event)
    if rows:
        return _detect_batch(rows)
    return _detect_single(event)


def _event_rows(event: dict[str, Any]) -> list[dict[str, Any]]:
    rows = event.get("events")
    if isinstance(rows, list):
        return [row for row in rows if isinstance(row, dict)]
    if isinstance(event, list):
        return [row for row in event if isinstance(row, dict)]
    return []


def _detect_single(event: dict[str, Any]) -> bool:
    method = str(event.get("method", ""))
    if method == _LIST_METHOD:
        count = int(event.get("count_per_credential") or event.get("list_count") or 0)
        if count > _HIGH_VOLUME_THRESHOLD:
            return True
        servers = int(event.get("distinct_server_ids") or 0)
        if servers > _CROSS_SERVER_THRESHOLD:
            return True
        duration = float(event.get("session_duration") or 0)
        call_count = int(event.get("session_tools_call_count") or 0)
        if duration > _LIST_ONLY_SESSION_SECONDS and call_count == 0:
            return True
    if method == _CALL_METHOD:
        error_code = event.get("error_code")
        distinct = int(event.get("distinct_tool_names") or event.get("fingerprint_count") or 0)
        if error_code == _UNKNOWN_TOOL_ERROR and distinct > _FINGERPRINT_THRESHOLD:
            return True
    return False


def _detect_batch(rows: list[dict[str, Any]]) -> bool:
    list_counts: dict[str, int] = {}
    servers_by_cred: dict[str, set[str]] = {}
    unknown_tools: dict[str, set[str]] = {}
    session_lists: dict[str, int] = {}
    session_calls: dict[str, int] = {}

    for row in rows:
        method = str(row.get("method", ""))
        cred = str(row.get("credential_id") or row.get("session_id") or "default")
        server = str(row.get("server_id") or row.get("server_name") or "")
        session = str(row.get("session_id") or cred)

        if method == _LIST_METHOD:
            list_counts[cred] = list_counts.get(cred, 0) + 1
            if server:
                servers_by_cred.setdefault(cred, set()).add(server)
            session_lists[session] = session_lists.get(session, 0) + 1
        elif method == _CALL_METHOD:
            session_calls[session] = session_calls.get(session, 0) + 1
            if row.get("error_code") == _UNKNOWN_TOOL_ERROR:
                tool = str(row.get("tool_name") or "")
                if tool:
                    unknown_tools.setdefault(session, set()).add(tool)

    if any(count > _HIGH_VOLUME_THRESHOLD for count in list_counts.values()):
        return True
    if any(len(servers) > _CROSS_SERVER_THRESHOLD for servers in servers_by_cred.values()):
        return True
    if any(len(tools) > _FINGERPRINT_THRESHOLD for tools in unknown_tools.values()):
        return True
    return any(lists >= 3 and session_calls.get(session, 0) == 0 for session, lists in session_lists.items())
