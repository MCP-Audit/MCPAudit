"""MCP server root privilege abuse (MCTS-T-1071)."""

from __future__ import annotations

from typing import Any

_ROOT_PRIVILEGED_TOOLS = (
    "execute_command",
    "run_shell",
    "docker_run",
    "sys_admin",
    "docker",
)


def detect_root_privilege_abuse(event: dict[str, Any]) -> bool:
    """Detect MCP server or tool execution running with root-level privileges."""
    if event.get("root_privilege_abuse") or event.get("running_as_root"):
        return True
    if event.get("uid") == 0 or event.get("euid") == 0:
        return True

    tool = str(event.get("tool_name", "")).lower()
    if not any(marker in tool for marker in _ROOT_PRIVILEGED_TOOLS):
        return False

    run_as = str(event.get("user") or event.get("run_as") or event.get("effective_user") or "").lower()
    if run_as in {"root", "0", "administrator", "nt authority\\system"}:
        return True

    params = str(event.get("tool_parameters") or event.get("args") or "").lower()
    return any(marker in params for marker in ("sudo", "runas root", "uid=0", "--privileged"))
