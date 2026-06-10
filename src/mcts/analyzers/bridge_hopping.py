"""Cross-chain bridge hopping for laundering (MCTS-T-1077)."""

from __future__ import annotations

from typing import Any

_BRIDGE_TOOL_MARKERS = (
    "bridge",
    "cross_chain",
    "multichain",
    "stargate",
    "hop_protocol",
    "synapse",
    "celer",
)


def detect_bridge_hopping(event: dict[str, Any]) -> bool:
    """Detect rapid cross-chain bridge sequences indicative of laundering."""
    if event.get("cross_chain_laundering") or event.get("bridge_hopping"):
        return True

    tool = str(event.get("tool_name", "")).lower()
    if not any(marker in tool for marker in _BRIDGE_TOOL_MARKERS):
        return False

    hops = int(event.get("chain_hops") or event.get("bridge_count") or 0)
    if hops >= 2:
        return True
    return bool(event.get("rapid_bridge_sequence"))
