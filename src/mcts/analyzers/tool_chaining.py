"""Privilege-escalating MCP tool chain detection (MCTS-T-1045)."""

from __future__ import annotations

from typing import Any

_LOW_PRIV_SUFFIXES = ("_reader", "_access", "_basic", "_list", "_get", "_search")
_HIGH_PRIV_MARKERS = ("admin_", "system_", "execute_", "manage_", "delete_", "shell", "exec", "sudo", "root")
_PRIV_ESCALATIONS = frozenset({"low_to_medium", "medium_to_high", "low_to_high"})


def detect_tool_chaining(event: dict[str, Any]) -> bool:
    """Detect indirect multi-tool pivots from low-privilege to high-privilege tools."""
    if _detect_escalation_event(event):
        return True
    source = str(event.get("source_tool") or event.get("SourceTool") or "").lower()
    dest = str(
        event.get("destination_tool") or event.get("DestinationTool") or event.get("tool_name") or ""
    ).lower()
    if source and dest and _is_low_priv(source) and _is_high_priv(dest):
        interaction = str(event.get("interaction_type") or event.get("InteractionType") or "").lower()
        if interaction in {"data_transfer", "chain", "pivot", ""}:
            chain_len = int(event.get("chain_length") or event.get("ChainLength") or 0)
            if chain_len > 1 or event.get("execution_method") == "indirect":
                return True
    chain = event.get("tool_chain") or event.get("chain")
    if isinstance(chain, list) and len(chain) >= 2:
        return _chain_escalates(chain)
    return False


def _detect_escalation_event(event: dict[str, Any]) -> bool:
    privilege = str(event.get("privilege_change") or event.get("PrivilegeChange") or "")
    if privilege in _PRIV_ESCALATIONS:
        chain_len = int(event.get("chain_length") or event.get("ChainLength") or 0)
        if chain_len > 1 or str(event.get("execution_method") or event.get("ExecutionMethod")) == "indirect":
            return True
    return False


def _chain_escalates(chain: list[Any]) -> bool:
    names = [str(item).lower() for item in chain if item]
    if len(names) < 2:
        return False
    return _is_low_priv(names[0]) and any(_is_high_priv(name) for name in names[1:])


def _is_low_priv(name: str) -> bool:
    return any(name.endswith(suffix) for suffix in _LOW_PRIV_SUFFIXES) or name.startswith(
        ("read_", "get_", "list_")
    )


def _is_high_priv(name: str) -> bool:
    return any(marker in name for marker in _HIGH_PRIV_MARKERS)
