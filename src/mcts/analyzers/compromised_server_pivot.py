"""Compromised MCP server lateral pivot (MCTS-T-1064)."""

from __future__ import annotations

from typing import Any

_WORKSPACE_PATH_MARKERS = (
    "/workspace/shared",
    "/.mcp/config",
    "/workspace/build-scripts",
    "/workspace/.env",
    "docker-compose.yml",
)

_PIVOT_PROCESSES = ("ssh", "scp", "rsync", "docker", "kubectl", "runc")
_CONTAINER_ESCAPE_ACTIONS = ("host_mount", "privileged_execution", "socket_access")
_CONFIG_CHANGE_TYPES = (
    "credential_added",
    "network_config_modified",
    "container_config_modified",
)
_SCRIPT_EXTENSIONS = (".sh", ".py", ".js", ".json", ".yaml", ".yml")


def detect_compromised_server_pivot(event: dict[str, Any]) -> bool:
    """Detect a compromised MCP server pivoting across workspace hosts."""
    event_type = str(event.get("event_type") or event.get("EventType") or "").lower()
    source = str(event.get("source_type") or event.get("SourceType") or "").lower()

    if event_type == "file_access" and source == "mcp_server":
        path = str(event.get("target_path") or event.get("path") or "").lower()
        access = str(event.get("access_type") or event.get("AccessType") or "").lower()
        if (
            access in {"write", "modify"}
            and any(m in path for m in _WORKSPACE_PATH_MARKERS)
            and any(path.endswith(ext) for ext in _SCRIPT_EXTENSIONS)
        ):
            return True

    if event_type == "network_connection" and source == "mcp_server":
        port = str(event.get("destination_port") or event.get("DestinationPort") or "")
        dest_type = str(event.get("destination_type") or event.get("DestinationType") or "")
        if dest_type == "workspace_host" and port not in {"80", "443", ""}:
            return True

    if event_type == "process_execution" and source == "mcp_server":
        proc = str(event.get("process_name") or event.get("ProcessName") or "").lower()
        if any(p in proc for p in _PIVOT_PROCESSES) and (
            event.get("target_host") == "different_host" or event.get("cross_host")
        ):
            return True

    if event_type == "container_activity" and source == "mcp_server":
        action = str(event.get("action") or event.get("Action") or "").lower()
        if action in _CONTAINER_ESCAPE_ACTIONS and event.get("target_type") == "host_system":
            return True

    if event_type == "configuration_change" and source == "mcp_server":
        path = str(event.get("target_path") or event.get("path") or "").lower()
        change = str(event.get("change_type") or event.get("ChangeType") or "").lower()
        if any(m in path for m in _WORKSPACE_PATH_MARKERS) and change in _CONFIG_CHANGE_TYPES:
            return True

    return bool(event.get("compromised_server_pivot") or event.get("workspace_pivot_detected"))
