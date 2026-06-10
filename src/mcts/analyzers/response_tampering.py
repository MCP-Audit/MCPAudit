"""Narrative/tool mismatch response tampering (MCTS-T-1073)."""

from __future__ import annotations

from typing import Any

_SAFE_NARRATIVE_MARKERS = (
    "read only",
    "read-only",
    "safe",
    "harmless",
    "view only",
    "no side effects",
    "does not modify",
    "non-destructive",
)

_DANGEROUS_TOOL_MARKERS = (
    "execute_command",
    "run_shell",
    "exec",
    "shell",
    "bash",
    "http",
    "fetch",
    "read_file",
    "write_file",
)


def detect_response_tampering(event: dict[str, Any]) -> bool:
    """Detect when assistant narrative claims safety but invokes risky tools."""
    if event.get("narrative_tool_mismatch") or event.get("response_tampering"):
        return True

    narrative = str(
        event.get("llm_response") or event.get("narrative") or event.get("tool_description_claim") or ""
    ).lower()
    tool = str(event.get("tool_name") or event.get("invoked_tool") or "").lower()
    if not narrative or not tool:
        return False
    if not any(marker in narrative for marker in _SAFE_NARRATIVE_MARKERS):
        return False
    return any(marker in tool for marker in _DANGEROUS_TOOL_MARKERS)
