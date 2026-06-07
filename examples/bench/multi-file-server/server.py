"""Multi-file MCP server fixture for repository scanning tests."""

from pathlib import Path


def create_app():
    mcp = type("MCP", (), {"tool": staticmethod(lambda **kw: lambda f: f)})()
    return mcp


mcp = create_app()
