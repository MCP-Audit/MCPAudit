"""MCP API endpoint DNS resolution anomaly (MCTS-T-1074)."""

from __future__ import annotations

from typing import Any

_HOST_MARKERS = ("api.", "mcp.", "tools.", "agent.")
_TLD_MARKERS = (".com", ".io", ".ai")


def detect_dns_resolution_anomaly(event: dict[str, Any]) -> bool:
    """Detect suspicious DNS resolution for MCP/API endpoints."""
    if event.get("dns_resolution_anomaly") or event.get("hostname_mismatch"):
        return True
    if event.get("dns_cache_poison") or event.get("unexpected_resolution") or event.get("sinkholed"):
        return True

    query = str(event.get("query") or event.get("hostname") or event.get("host") or "").lower()
    if not query:
        return False
    if not any(marker in query for marker in _HOST_MARKERS) and not any(
        marker in query for marker in _TLD_MARKERS
    ):
        return False

    resolved = str(event.get("resolved_ip") or event.get("resolved_to") or "")
    expected = str(event.get("expected_ip") or "")
    if resolved and expected and resolved != expected:
        return True

    return bool(event.get("resolution_changed") or event.get("nxdomain_then_resolved"))
