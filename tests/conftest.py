"""Shared pytest fixtures."""

from pathlib import Path

import pytest

EXAMPLE_SERVER = Path(__file__).parent.parent / "examples" / "vulnerable-mcp-server" / "server.py"


@pytest.fixture
def example_server_path() -> Path:
    return EXAMPLE_SERVER
