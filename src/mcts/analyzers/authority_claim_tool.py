"""Privileged tool invocation after authority-claim pretext (MCTS-T-1072)."""

from __future__ import annotations

from typing import Any

_PRETEXT_MARKERS = (
    "i am the admin",
    "as your developer",
    "system override",
    "authorized by",
    "security team",
    "administrator said",
    "it department",
    "compliance requires",
    "maintenance mode",
    "override policy",
)

_PRIVILEGED_TOOL_MARKERS = (
    "filesystem.write",
    "filesystem.delete",
    "fs.write",
    "shell",
    "exec",
    "process.spawn",
    "http.request",
    "network.fetch",
    "secrets.",
    "admin.",
    "deploy",
    "db.execute",
    "sql.execute",
)


def detect_authority_claim_tool(event: dict[str, Any]) -> bool:
    """Detect high-privilege tool use preceded by a false authority pretext."""
    if event.get("authority_claim_pretext") or event.get("authority_claim_tool"):
        return True

    pretext = str(
        event.get("user_message") or event.get("prompt") or event.get("prior_context") or ""
    ).lower()
    tool = str(event.get("tool_name", "")).lower()
    if not tool or not any(marker in tool for marker in _PRIVILEGED_TOOL_MARKERS):
        return False
    return any(marker in pretext for marker in _PRETEXT_MARKERS)
