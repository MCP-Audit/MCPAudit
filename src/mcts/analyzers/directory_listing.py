"""Suspicious directory listing on sensitive paths (MCTS-T-1068)."""

from __future__ import annotations

_LIST_TOOL_MARKERS = (
    "list_directory",
    "dir",
    "filesystem_list_directory",
    "list_dir",
    "browse_directory",
    "ls",
)

_SENSITIVE_LIST_PATHS = (
    "/etc",
    "/root",
    "/.ssh",
    "/var/log",
    "/proc",
    "/sys",
    "id_rsa",
    ".aws",
    "credentials",
    "secrets",
)


def detect_suspicious_directory_listing(
    *,
    tool_name: str,
    path: str = "",
    directory: str = "",
) -> bool:
    """Detect directory listing tools aimed at sensitive system locations."""
    lowered = tool_name.lower()
    if not any(marker in lowered for marker in _LIST_TOOL_MARKERS) and (
        "list" not in lowered and "dir" not in lowered
    ):
        return False
    target = (path or directory).lower().replace("\\", "/")
    if not target:
        return False
    return any(marker in target for marker in _SENSITIVE_LIST_PATHS)
