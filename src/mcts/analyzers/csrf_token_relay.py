"""CSRF-mediated OAuth token relay (MCTS-T-1063)."""

from __future__ import annotations

from typing import Any


def detect_csrf_token_relay(event: dict[str, Any]) -> bool:
    """Detect OAuth tokens passed via CSRF to foreign resource servers."""
    if event.get("csrf_detected") and event.get("token_forwarded"):
        return True
    origin = str(event.get("origin") or event.get("Origin") or "")
    target = str(event.get("target_host") or event.get("resource_server") or "")
    if origin and target and origin not in target and event.get("bearer_token_present"):
        return True
    if event.get("event_type") == "csrf_token_relay":
        return True
    return bool(event.get("cross_site_request") and event.get("oauth_token_in_request"))
