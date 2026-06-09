"""MCP server version and fingerprint probing (MCTS-T-1055)."""

from __future__ import annotations

import re

VERSION_PROBE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"/version\b", re.I),
    re.compile(r"/health\b", re.I),
    re.compile(r"/\.well-known/mcp", re.I),
    re.compile(r"server[-_]?version", re.I),
    re.compile(r"mcp[-_]?protocol[-_]?version", re.I),
)

VERSION_HEADER_MARKERS = ("x-mcp-version", "mcp-version", "server-version", "x-server-version")


def detect_version_enumeration(*, path: str = "", url: str = "", headers: dict | None = None) -> bool:
    """Detect version endpoint probing or version header harvesting."""
    target = f"{path} {url}".strip()
    if target and any(pattern.search(target) for pattern in VERSION_PROBE_PATTERNS):
        return True
    if headers:
        lowered = {str(k).lower(): str(v) for k, v in headers.items()}
        if any(marker in lowered for marker in VERSION_HEADER_MARKERS):
            return True
        for value in lowered.values():
            if re.search(r"\d+\.\d+\.\d+", value) and "mcp" in value.lower():
                return True
    return False
