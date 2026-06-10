"""Disinformation or poisoned output in MCP responses (MCTS-T-1079)."""

from __future__ import annotations

from typing import Any

_DISINFO_MARKERS = (
    "<!-- system:",
    "hidden instruction",
    "disinformation",
    "false claim",
    "fabricated",
    "do not verify",
    "ignore safety",
    "override instructions",
)

_ZERO_WIDTH = ("\u200b", "\u200c", "\u200d")


def detect_disinformation_output(event: dict[str, Any]) -> bool:
    """Detect disinformation or hidden instructions in MCP tool/LLM output."""
    if event.get("disinformation_output"):
        return True

    output = str(event.get("tool_output") or event.get("llm_response") or event.get("content") or "")
    if not output:
        return False

    lowered = output.lower()
    if any(marker in lowered for marker in _DISINFO_MARKERS):
        return True
    return any(char in output for char in _ZERO_WIDTH)
