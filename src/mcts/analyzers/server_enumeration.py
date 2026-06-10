"""MCP server network enumeration probing (MCTS-T-1061)."""

from __future__ import annotations

from typing import Any

_PROBE_MARKERS = ("mcp/handshake", "tools/list", "initialize", "jsonrpc")
_SCAN_THRESHOLD = 20


def detect_server_enumeration(event: dict[str, Any]) -> bool:
    """Detect port scanning or protocol discovery against MCP endpoints."""
    if event.get("scan_detected") or event.get("port_scan"):
        return True
    probe_count = int(event.get("probe_count") or event.get("connection_attempts") or 0)
    if probe_count >= _SCAN_THRESHOLD:
        return True
    path = str(event.get("path") or event.get("request_path") or "").lower()
    if probe_count >= 5 and any(marker in path for marker in _PROBE_MARKERS):
        return True
    rows = event.get("events")
    if isinstance(rows, list):
        hosts: set[str] = set()
        for row in rows:
            if not isinstance(row, dict):
                continue
            host = str(row.get("host") or row.get("target_host") or "")
            if host:
                hosts.add(host)
        if len(hosts) >= 10:
            return True
    return False
