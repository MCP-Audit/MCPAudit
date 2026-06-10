"""Covert channel and high-entropy parameter exfiltration (MCTS-T-1049)."""

from __future__ import annotations

import base64
import math
import re
from collections import Counter
from typing import Any

_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")
_HEX_RE = re.compile(r"\b[0-9a-fA-F]{64,}\b")
_MIN_ENTROPY = 4.5
_MIN_LENGTH = 32


def detect_covert_channel(*, tool_parameters: Any = None, tool_output: str = "") -> bool:
    """Detect base64/hex smuggling or high-entropy blobs in tool I/O."""
    haystack = _stringify(tool_parameters) + " " + tool_output
    if not haystack.strip():
        return False
    for match in _BASE64_RE.findall(haystack):
        if len(match) >= _MIN_LENGTH and _looks_like_payload(match):
            return True
    for match in _HEX_RE.findall(haystack):
        if _shannon_entropy(match) >= _MIN_ENTROPY:
            return True
    for token in haystack.split():
        if (
            len(token) >= _MIN_LENGTH
            and _shannon_entropy(token) >= _MIN_ENTROPY + 0.5
            and not token.startswith(("http://", "https://", "sha256:", "uuid:"))
        ):
            return True
    return False


def _stringify(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return " ".join(_stringify(v) for v in value.values())
    if isinstance(value, list):
        return " ".join(_stringify(v) for v in value)
    return str(value) if value is not None else ""


def _looks_like_payload(blob: str) -> bool:
    try:
        decoded = base64.b64decode(blob + "==", validate=False)
    except Exception:
        return _shannon_entropy(blob) >= _MIN_ENTROPY
    return len(decoded) >= 16


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())
