"""REST/API endpoint harvesting via MCP HTTP tools (MCTS-T-1069)."""

from __future__ import annotations

from typing import Any

_HTTP_TOOLS = (
    "http_request",
    "fetch",
    "api_call",
    "rest_api",
    "graphql_query",
    "http.get",
    "http.post",
    "webhook",
)

_SEQUENTIAL_THRESHOLD = 8
_VOLUME_BYTES_THRESHOLD = 5_000_000
_ROUND_THRESHOLD = 3


def detect_api_harvest(event: dict[str, Any]) -> bool:
    """Detect coordinated HTTP/API harvesting (volume, sequence, multi-round)."""
    rows = event.get("events")
    if isinstance(rows, list) and rows:
        return _detect_batch(rows)
    return _detect_single(event)


def _detect_single(event: dict[str, Any]) -> bool:
    tool = str(event.get("tool_name", "")).lower()
    if not _is_http_tool(tool):
        return False
    if int(event.get("response_bytes") or event.get("bytes_transferred") or 0) >= _VOLUME_BYTES_THRESHOLD:
        return True
    if int(event.get("sequential_calls") or 0) >= _SEQUENTIAL_THRESHOLD:
        return True
    if int(event.get("harvest_rounds") or event.get("round_count") or 0) >= _ROUND_THRESHOLD:
        return True
    url = str(event.get("url") or event.get("endpoint") or "")
    return bool(url and event.get("pagination") and int(event.get("page_count") or 0) >= 5)


def _detect_batch(rows: list[Any]) -> bool:
    session_http: dict[str, int] = {}
    session_bytes: dict[str, int] = {}
    session_urls: dict[str, list[str]] = {}

    for row in rows:
        if not isinstance(row, dict):
            continue
        tool = str(row.get("tool_name", "")).lower()
        if not _is_http_tool(tool):
            continue
        session = str(row.get("session_id") or "default")
        session_http[session] = session_http.get(session, 0) + 1
        session_bytes[session] = session_bytes.get(session, 0) + int(row.get("response_bytes") or 0)
        url = str(row.get("url") or row.get("endpoint") or "")
        if url:
            session_urls.setdefault(session, []).append(url)

    for session, count in session_http.items():
        if count >= _SEQUENTIAL_THRESHOLD:
            return True
        if session_bytes.get(session, 0) >= _VOLUME_BYTES_THRESHOLD:
            return True
        urls = session_urls.get(session, [])
        if len(urls) >= _SEQUENTIAL_THRESHOLD and _looks_sequential(urls):
            return True
    return False


def _is_http_tool(name: str) -> bool:
    return any(marker in name for marker in _HTTP_TOOLS) or name.startswith("http")


def _looks_sequential(urls: list[str]) -> bool:
    if len(urls) < 3:
        return False
    numbered = sum(1 for u in urls if any(c.isdigit() for c in u.split("/")[-1]))
    return numbered >= len(urls) // 2
