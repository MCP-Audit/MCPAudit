"""OAuth implicit flow downgrade detection (MCTS-T-1047)."""

from __future__ import annotations

_IMPLICIT_RESPONSE_TYPES = frozenset({"token", "id_token", "id_token token", "token id_token"})


def detect_oauth_implicit_flow(config: dict) -> bool:
    """Detect OAuth configs forcing deprecated implicit flow instead of auth code + PKCE."""
    response_type = _first_str(
        config,
        ("response_type", "responseType", "oauth_response_type", "grant_type"),
    ).lower()
    if response_type in _IMPLICIT_RESPONSE_TYPES:
        return True
    if "implicit" in response_type:
        return True
    flow = _first_str(config, ("oauth_flow", "flow", "auth_flow")).lower()
    if flow == "implicit":
        return True
    return any(detect_oauth_implicit_flow(block) for block in _nested_oauth_blocks(config))


def _first_str(config: dict, keys: tuple[str, ...]) -> str:
    for key in keys:
        value = config.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _nested_oauth_blocks(config: dict) -> list[dict]:
    blocks: list[dict] = []
    for key in ("oauth", "oauth2", "auth", "authentication"):
        value = config.get(key)
        if isinstance(value, dict):
            blocks.append(value)
    return blocks
