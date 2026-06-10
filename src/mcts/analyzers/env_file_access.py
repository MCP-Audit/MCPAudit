"""Environment and secret file access via MCP file tools (MCTS-T-1067)."""

from __future__ import annotations

_ENV_FILE_MARKERS = (
    "/.env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".env.staging",
    "/secrets.",
    "/credentials",
)

_FILE_TOOL_MARKERS = (
    "read_file",
    "file_reader",
    "read_text_file",
    "get_file_contents",
    "load_file",
    "filesystem_read",
)


def detect_env_file_access(*, tool_name: str, file_path: str = "", path: str = "") -> bool:
    """Detect MCP file tools targeting environment or credential files."""
    target = (file_path or path).lower().replace("\\", "/")
    if not target:
        return False
    if not any(marker in target for marker in _ENV_FILE_MARKERS):
        return False
    lowered = tool_name.lower()
    return any(marker in lowered for marker in _FILE_TOOL_MARKERS) or "file" in lowered or "read" in lowered
