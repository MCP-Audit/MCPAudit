"""Steganographic exfiltration via markdown code blocks (MCTS-T-1058)."""

from __future__ import annotations

import re

_CODE_FENCE = re.compile(r"```[\w]*\n(.*?)```", re.S)
_HIGH_DENSITY = re.compile(r"[^\w\s]{8,}")
_HEX_BLOB = re.compile(r"\b[0-9a-fA-F]{32,}\b")


def detect_stego_exfil(*, response: str = "", tool_output: str = "") -> bool:
    """Detect data smuggled inside code fences shown to users."""
    text = response or tool_output
    if not text:
        return False
    for block in _CODE_FENCE.findall(text):
        stripped = block.strip()
        if len(stripped) < 40:
            continue
        if _HEX_BLOB.search(stripped):
            return True
        non_word_chars = sum(1 for c in stripped if not c.isalnum() and not c.isspace())
        non_word_ratio = non_word_chars / max(len(stripped), 1)
        if non_word_ratio > 0.35 and _HIGH_DENSITY.search(stripped):
            return True
        if stripped.count("\\x") >= 4 or stripped.count("\\u") >= 4:
            return True
    return False
