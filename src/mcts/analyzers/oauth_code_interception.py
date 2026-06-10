"""OAuth authorization code interception patterns (MCTS-T-1052)."""

from __future__ import annotations

from typing import Any


def detect_oauth_code_interception(event: dict[str, Any]) -> bool:
    """Detect auth-code races, duplicate exchanges, or Referer leakage."""
    if event.get("duplicate_token_exchange"):
        return True
    race_ms = event.get("exchange_race_ms")
    if isinstance(race_ms, (int, float)) and race_ms < 1000:
        return True
    referer = str(event.get("referer") or event.get("Referer") or "")
    if "code=" in referer and len(referer) > 20:
        return True
    auth_code = str(event.get("authorization_code") or event.get("code") or "")
    if auth_code and event.get("code_reuse_count", 0) > 1:
        return True
    if event.get("event_type") == "oauth_token_exchange" and event.get("exchange_count", 0) > 1:
        return True
    logs = event.get("logs")
    if isinstance(logs, list):
        codes_seen: set[str] = set()
        for row in logs:
            if not isinstance(row, dict):
                continue
            code = str(row.get("authorization_code") or row.get("code") or "")
            if code:
                if code in codes_seen:
                    return True
                codes_seen.add(code)
    return False
