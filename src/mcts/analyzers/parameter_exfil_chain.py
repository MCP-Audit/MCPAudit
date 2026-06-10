"""Collect-then-exfil multi-stage parameter smuggling (MCTS-T-1070)."""

from __future__ import annotations

from typing import Any

_COLLECT_TOOLS = (
    "read_file",
    "file_read",
    "get_env",
    "database_query",
    "fetch_secret",
    "query",
    "sql",
)

_EXFIL_TOOLS = (
    "send_",
    "post_",
    "create_",
    "upload_",
    "notify",
    "webhook",
    "email",
    "message",
    "http.post",
    "http_request",
)

_SENSITIVE_PATH_MARKERS = (".env", "credentials", ".aws", ".ssh", "config", "secret")
_EXFIL_PARAM_MARKERS = ("password", "api_key", "secret", "token", "credential", "bearer")


def detect_parameter_exfil_chain(event: dict[str, Any]) -> bool:
    """Detect sensitive collection followed by outbound exfil in the same session."""
    if event.get("collection_then_exfil") or event.get("parameter_exfil_chain"):
        return True

    rows = event.get("events") or event.get("tool_chain")
    if isinstance(rows, list):
        return _detect_session_chain(rows)

    collect_tool = str(event.get("prior_tool") or event.get("collect_tool") or "").lower()
    exfil_tool = str(event.get("tool_name") or event.get("exfil_tool") or "").lower()
    if _is_collect_tool(collect_tool) and _is_exfil_tool(exfil_tool):
        params = str(event.get("tool_parameters") or event.get("exfil_params") or "").lower()
        path = str(event.get("path") or event.get("file_path") or "").lower()
        if any(m in params for m in _EXFIL_PARAM_MARKERS):
            return True
        if any(m in path for m in _SENSITIVE_PATH_MARKERS):
            return True
    return False


def _detect_session_chain(rows: list[Any]) -> bool:
    session_collect: dict[str, bool] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        session = str(row.get("session_id") or "default")
        tool = str(row.get("tool_name") or "").lower()
        path = str(row.get("path") or row.get("file_path") or "").lower()
        params = str(row.get("tool_parameters") or "").lower()

        if _is_collect_tool(tool) or any(m in path for m in _SENSITIVE_PATH_MARKERS):
            session_collect[session] = True

        if session_collect.get(session) and _is_exfil_tool(tool):
            if any(m in params for m in _EXFIL_PARAM_MARKERS):
                return True
            if any(m in tool for m in ("http", "webhook", "post", "upload")):
                return True
    return False


def _is_collect_tool(name: str) -> bool:
    return any(marker in name for marker in _COLLECT_TOOLS)


def _is_exfil_tool(name: str) -> bool:
    return any(marker in name for marker in _EXFIL_TOOLS)
