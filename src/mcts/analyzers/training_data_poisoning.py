"""Training pipeline data poisoning via MCP outputs (MCTS-T-1066)."""

from __future__ import annotations

import re
from typing import Any

_POISON_MARKERS: tuple[re.Pattern[str], ...] = (
    re.compile(r"<!--\s*TRIGGER:", re.I),
    re.compile(r"\[USER_DATA_PLACEHOLDER\]", re.I),
    re.compile(r"adversarial_pattern", re.I),
    re.compile(r"hidden_trigger", re.I),
    re.compile(r"backdoor_activation", re.I),
    re.compile(r"model_manipulation", re.I),
    re.compile(r"data_exfiltration_marker", re.I),
    re.compile(r"steganographic", re.I),
    re.compile(r"zero_width|zero-width|\u200b", re.I),
    re.compile(r"unicode_poisoning", re.I),
)

_BENIGN_MARKERS = (
    "legitimate_documentation",
    "educational_content",
    "security_training",
)


def detect_training_data_poisoning(
    *,
    tool_output: str = "",
    metadata: dict[str, Any] | None = None,
    event: dict[str, Any] | None = None,
) -> bool:
    """Detect poisoned content destined for model training pipelines."""
    if event:
        tool_output = str(event.get("tool_output") or event.get("mcp_tool_output") or tool_output)
        metadata = event.get("data_metadata") if isinstance(event.get("data_metadata"), dict) else metadata
        if not metadata and event.get("training_flag"):
            metadata = {"training_flag": event.get("training_flag")}

    if not tool_output:
        return False
    if any(marker in tool_output.lower() for marker in _BENIGN_MARKERS):
        return False

    has_poison = any(p.search(tool_output) for p in _POISON_MARKERS)
    if not has_poison:
        return False

    if metadata:
        if metadata.get("training_flag") is True:
            return True
        if str(metadata.get("data_quality", "")).lower() == "high":
            return True

    return bool(event and event.get("training_pipeline")) or has_poison
