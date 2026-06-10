"""Dangerous agent CLI flag weaponization (MCTS-T-1051)."""

from __future__ import annotations

import re
from typing import Any

DANGEROUS_CLI_FLAGS: tuple[re.Pattern[str], ...] = (
    re.compile(r"--dangerously[-_]?(?:skip[-_]?permissions|allow[-_]?all|bypass)", re.I),
    re.compile(r"--(?:no[-_]?sandbox|disable[-_]?sandbox)", re.I),
    re.compile(r"--(?:yolo|force|unsafe)", re.I),
    re.compile(r"--(?:auto[-_]?approve|approve[-_]?all)", re.I),
    re.compile(r"--(?:shell|exec|-c)\s", re.I),
)

RECON_EXFIL_FLAGS: tuple[str, ...] = (
    "--dump",
    "--export-all",
    "--full-access",
    "--read-only=false",
    "--trust-all",
)


def detect_cli_weaponization(*, command: str = "", args: Any = None, tool_parameters: Any = None) -> bool:
    """Detect MCP or agent CLI invocations with dangerous permissive flags."""
    text = command
    if isinstance(args, list):
        text += " " + " ".join(str(a) for a in args)
    elif isinstance(args, str):
        text += " " + args
    text += " " + _stringify(tool_parameters)
    if not text.strip():
        return False
    if any(pattern.search(text) for pattern in DANGEROUS_CLI_FLAGS):
        return True
    lowered = text.lower()
    hits = sum(1 for flag in RECON_EXFIL_FLAGS if flag in lowered)
    return hits >= 2


def _stringify(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return " ".join(str(v) for v in value.values())
    if isinstance(value, list):
        return " ".join(str(v) for v in value)
    return str(value) if value else ""
