"""Chat-based covert backchannel indicators (MCTS-T-1057)."""

from __future__ import annotations

import base64
import re

_ENCODED_BLOCK = re.compile(r"(?:[A-Za-z0-9+/]{24,}={0,2}|[0-9a-fA-F]{32,})")
_C2_MARKERS = ("decode this", "base64 payload", "run the following", "execute decoded", "bot command")


def detect_chat_backchannel(*, llm_response: str = "", tool_output: str = "") -> bool:
    """Detect encoded command blobs embedded in model responses for bot decode."""
    text = f"{llm_response} {tool_output}".strip()
    if not text:
        return False
    lowered = text.lower()
    if any(marker in lowered for marker in _C2_MARKERS) and _ENCODED_BLOCK.search(text):
        return True
    for match in _ENCODED_BLOCK.findall(text):
        if len(match) >= 24:
            try:
                decoded = base64.b64decode(match + "==", validate=False)
                if len(decoded) >= 8 and any(
                    token in decoded.lower() for token in (b"curl", b"wget", b"bash", b"powershell", b"http")
                ):
                    return True
            except Exception:
                continue
    return False
