"""Multimodal prompt injection in MCP content surfaces (MCTS-T-1050)."""

from __future__ import annotations

import re

MULTIMODAL_MARKERS = (
    "image_url",
    "image/png",
    "image/jpeg",
    "audio/",
    "video/",
    "data:image",
    "data:audio",
    "vision",
    "multimodal",
)

INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.I),
    re.compile(r"system\s*:\s*", re.I),
    re.compile(r"<\|im_start\|>", re.I),
    re.compile(r"\[INST\]", re.I),
    re.compile(r"do\s+not\s+disclose", re.I),
    re.compile(r"hidden\s+instruction", re.I),
    re.compile(r"<!--\s*system", re.I),
)


def detect_multimodal_injection(*, content_type: str = "", content: str = "", metadata: str = "") -> bool:
    """Detect hidden instructions embedded in multimodal MCP payloads."""
    haystack = f"{content_type} {content} {metadata}".lower()
    if not any(marker in haystack for marker in MULTIMODAL_MARKERS):
        return False
    text = content or metadata
    return any(pattern.search(text) for pattern in INJECTION_PATTERNS)
