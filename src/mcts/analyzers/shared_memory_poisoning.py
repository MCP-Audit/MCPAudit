"""Shared memory / vector store poisoning via MCP memory tools (MCTS-T-1076)."""

from __future__ import annotations

from typing import Any

_MEMORY_TOOL_MARKERS = (
    "save_memory",
    "add_embedding",
    "store_knowledge",
    "upsert_vector",
)

_POISON_MARKERS = (
    "ignore previous",
    "disable safety",
    "always execute",
    "hidden instruction",
    "override system",
    "bypass filter",
    "do not tell",
)


def detect_shared_memory_poisoning(event: dict[str, Any]) -> bool:
    """Detect poisoned payloads written to shared agent memory or vector stores."""
    if event.get("shared_memory_poisoning"):
        return True

    tool = str(event.get("tool_name", "")).lower()
    if not any(marker in tool for marker in _MEMORY_TOOL_MARKERS):
        return False

    content = str(
        event.get("content") or event.get("memory_payload") or event.get("tool_parameters") or ""
    ).lower()
    return any(marker in content for marker in _POISON_MARKERS)
