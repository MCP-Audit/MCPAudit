"""Credential relay chain to higher-privilege tools (MCTS-T-1059)."""

from __future__ import annotations

from typing import Any

_CREDENTIAL_TOOLS = ("token", "credential", "secret", "auth", "session", "oauth", "password")
_PRIVILEGED_TOOLS = ("admin", "execute", "shell", "deploy", "delete", "write", "sudo", "root", "manage")


def detect_credential_relay(event: dict[str, Any]) -> bool:
    """Detect stolen credentials chained into a higher-privilege tool invocation."""
    chain = event.get("tool_chain") or event.get("chain")
    if isinstance(chain, list) and len(chain) >= 2:
        return _chain_is_relay(chain)
    prior = str(event.get("prior_tool") or event.get("credential_source_tool") or "").lower()
    current = str(event.get("tool_name") or event.get("privileged_tool") or "").lower()
    if prior and current and _is_credential_tool(prior) and _is_privileged_tool(current):
        if event.get("token_forwarded") or event.get("credential_relay"):
            return True
        if event.get("same_session") and event.get("time_delta_ms", 99999) < 5000:
            return True
    return bool(event.get("credential_relay_detected"))


def _chain_is_relay(chain: list[Any]) -> bool:
    names = [str(item).lower() for item in chain if item]
    if len(names) < 2:
        return False
    cred_idx = next((i for i, n in enumerate(names) if _is_credential_tool(n)), None)
    priv_idx = next((i for i, n in enumerate(names) if _is_privileged_tool(n)), None)
    return cred_idx is not None and priv_idx is not None and cred_idx < priv_idx


def _is_credential_tool(name: str) -> bool:
    return any(marker in name for marker in _CREDENTIAL_TOOLS)


def _is_privileged_tool(name: str) -> bool:
    return any(marker in name for marker in _PRIVILEGED_TOOLS)
