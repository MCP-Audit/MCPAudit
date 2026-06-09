"""Cross-agent instruction injection on shared buses (MCTS-T-1062)."""

from __future__ import annotations

import re
from typing import Any

INJECTION_MARKERS: tuple[re.Pattern[str], ...] = (
    re.compile(r"ignore\s+other\s+agents?", re.I),
    re.compile(r"override\s+agent\s+instructions?", re.I),
    re.compile(r"you\s+are\s+now\s+agent", re.I),
    re.compile(r"forward\s+this\s+to\s+all\s+agents?", re.I),
    re.compile(r"system\s+directive", re.I),
)


def detect_cross_agent_injection(event: dict[str, Any]) -> bool:
    """Detect spoofed directives injected into multi-agent message buses."""
    message = str(event.get("message") or event.get("content") or event.get("payload") or "")
    if not message:
        return False
    bus = str(event.get("bus_type") or event.get("channel") or "").lower()
    if bus and "agent" not in bus and event.get("event_type") != "agent_message":
        return False
    if any(pattern.search(message) for pattern in INJECTION_MARKERS):
        return True
    if event.get("sender_spoofed") and event.get("broadcast"):
        return True
    return bool(event.get("cross_agent_injection"))
