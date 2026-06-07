"""SAF-MCP mitigation dossier URL helpers."""

from __future__ import annotations

SAF_MCP_MITIGATION_BASE = "https://github.com/SAF-MCP/saf-mcp/tree/main/mitigations"
SAF_MCP_TECHNIQUE_BASE = "https://github.com/SAF-MCP/saf-mcp/tree/main/techniques"


def mitigation_url(mitigation_id: str) -> str:
    return f"{SAF_MCP_MITIGATION_BASE}/{mitigation_id}"


def technique_url(technique_id: str) -> str:
    return f"{SAF_MCP_TECHNIQUE_BASE}/{technique_id}"


def mitigation_links(mitigation_ids: list[str]) -> list[dict[str, str]]:
    return [{"id": mid, "url": mitigation_url(mid)} for mid in mitigation_ids]
