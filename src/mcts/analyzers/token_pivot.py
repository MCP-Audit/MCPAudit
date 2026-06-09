"""Cross-service OAuth token pivot replay (MCTS-T-1053)."""

from __future__ import annotations

from typing import Any


def detect_token_pivot(event: dict[str, Any]) -> bool:
    """Detect the same bearer token reused across distinct resource servers."""
    token = str(event.get("token_id") or event.get("access_token_hash") or event.get("token_hash") or "")
    audiences = event.get("audiences") or event.get("resource_servers")
    if token and isinstance(audiences, list) and len(set(audiences)) > 1:
        return True
    if event.get("audience_validation_failed") and event.get("token_reuse_across_rs"):
        return True
    rows = event.get("events") or event.get("token_usage")
    if isinstance(rows, list) and token:
        seen_rs: set[str] = set()
        for row in rows:
            if not isinstance(row, dict):
                continue
            rs = str(row.get("resource_server") or row.get("audience") or "")
            if rs:
                if rs in seen_rs:
                    return True
                seen_rs.add(rs)
    return bool(event.get("cross_service_replay") or event.get("token_pivot_detected"))
