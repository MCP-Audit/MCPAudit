"""Runtime destructive MCP tool invocation detection (MCTS-T-1048)."""

from __future__ import annotations

import re
from typing import Any

DESTRUCTIVE_TOOL_MARKERS = (
    "delete",
    "remove",
    "wipe",
    "truncate",
    "drop_table",
    "drop-table",
    "purge",
    "reset-db",
    "reset_database",
    "rm_",
)

DESTRUCTIVE_COMMAND_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\brm\s+-rf\b", re.I),
    re.compile(r"\brm\s+-r\b", re.I),
    re.compile(r"\bfind\s+.+\s-delete\b", re.I),
    re.compile(r"\bdrop\s+table\b", re.I),
    re.compile(r"\btruncate\s+table\b", re.I),
    re.compile(r"\bdelete\s+from\b", re.I),
    re.compile(r"\bdrop\s+database\b", re.I),
)

SENSITIVE_PATH_MARKERS = (
    "/var",
    "/home",
    "/etc",
    ".git",
    ".venv",
    "s3://",
    "gs://",
    "/buckets/",
    "/storage/",
)


def detect_data_destruction(
    *,
    tool_name: str,
    tool_parameters: Any = None,
    method: str | None = None,
) -> bool:
    """Return True when a tool invocation indicates destructive data operations."""
    lowered = tool_name.lower()
    if not any(marker in lowered for marker in DESTRUCTIVE_TOOL_MARKERS) and not (
        lowered == "http" and str(method or "").upper() == "DELETE"
    ):
        return False
    params = _flatten_params(tool_parameters)
    if any(pattern.search(params) for pattern in DESTRUCTIVE_COMMAND_PATTERNS):
        return True
    if any(marker in params for marker in SENSITIVE_PATH_MARKERS) and (
        "recursive" in params.lower() or "rm" in lowered or "delete" in lowered
    ):
        return True
    http_method = method
    if isinstance(tool_parameters, dict):
        http_method = http_method or tool_parameters.get("method")
    if lowered == "http" and str(http_method or "").upper() == "DELETE":
        path = params.lower()
        if any(marker in path for marker in SENSITIVE_PATH_MARKERS):
            return True
    return bool(any(marker in lowered for marker in ("wipe", "purge", "drop_table", "truncate")))


def _flatten_params(params: Any) -> str:
    if isinstance(params, str):
        return params
    if not isinstance(params, dict):
        return ""
    parts: list[str] = []
    for key in ("command", "path", "query", "sql", "target", "bucket", "key"):
        value = params.get(key)
        if isinstance(value, str):
            parts.append(value)
    return " ".join(parts)
