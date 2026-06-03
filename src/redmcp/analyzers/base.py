"""Base analyzer interface."""

from __future__ import annotations

from abc import ABC, abstractmethod

from redmcp.mcp.models import MCPServerInfo
from redmcp.reporting.models import Finding


class BaseAnalyzer(ABC):
    """Interface implemented by all RedMCP security analyzers."""

    name: str = "base"

    @abstractmethod
    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        """Run analysis and return findings."""
