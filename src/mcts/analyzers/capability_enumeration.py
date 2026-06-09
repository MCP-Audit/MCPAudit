"""Capability-mapping prompt enumeration (MCTS-T-1054)."""

from __future__ import annotations

import re

CAPABILITY_PROMPT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"what\s+(?:tools|functions|capabilities)\s+(?:do\s+you|can\s+you)", re.I),
    re.compile(r"list\s+(?:all\s+)?(?:your\s+)?(?:tools|functions|capabilities)", re.I),
    re.compile(r"what\s+can\s+you\s+do", re.I),
    re.compile(r"show\s+(?:me\s+)?(?:all\s+)?(?:available\s+)?tools", re.I),
    re.compile(r"enumerate\s+(?:mcp\s+)?tools", re.I),
    re.compile(r"tools/list", re.I),
    re.compile(r"which\s+apis?\s+(?:do\s+you|can\s+you)\s+access", re.I),
)


def detect_capability_enumeration(*, prompt: str = "", user_message: str = "") -> bool:
    """Detect conversational probing for MCP tool/capability inventory."""
    text = f"{prompt} {user_message}".strip()
    if not text:
        return False
    return any(pattern.search(text) for pattern in CAPABILITY_PROMPT_PATTERNS)
