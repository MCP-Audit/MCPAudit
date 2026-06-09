"""Tests for live discovery warning tracking and meta-findings."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.mcp.models import MCPServerInfo
from mcts.probe.discovery_meta import (
    discovery_meta_findings,
    list_failure_warning,
    tools_list_failed,
)
from mcts.probe.models import LiveServerConfig
from mcts.probe.session import probe_stdio


def test_list_failure_warning_includes_stderr_hint() -> None:
    warning = list_failure_warning("list_tools", RuntimeError("boom"), None)
    assert warning.startswith("list_tools failed:")
    assert "--stderr-file" in warning


def test_list_failure_warning_notes_captured_stderr() -> None:
    warning = list_failure_warning("list_tools", RuntimeError("boom"), "/tmp/err.log")
    assert "/tmp/err.log" in warning


def test_discovery_meta_findings_emitted_for_warnings() -> None:
    server = MCPServerInfo(
        discovery_mode="live",
        initialize_succeeded=True,
        discovery_warnings=["list_tools failed: timeout"],
    )
    findings = discovery_meta_findings(server)
    assert len(findings) == 1
    assert findings[0].id == "live-discovery-incomplete"
    assert findings[0].analyzer == "live_discovery"
    assert findings[0].severity.value == "high"


def test_tools_list_failed_detector() -> None:
    assert not tools_list_failed(["list_prompts failed: x"])
    assert tools_list_failed(["list_tools failed: x"])


@pytest.mark.asyncio
async def test_probe_stdio_records_list_tools_failure() -> None:
    fake_init = SimpleNamespace(instructions=None, serverInfo=SimpleNamespace(version="1.0.0"))

    mock_session = AsyncMock()
    mock_session.initialize = AsyncMock(return_value=fake_init)
    mock_session.list_tools = AsyncMock(side_effect=RuntimeError("tools unavailable"))
    mock_session.list_prompts = AsyncMock(return_value=SimpleNamespace(prompts=[]))
    mock_session.list_resources = AsyncMock(return_value=SimpleNamespace(resources=[]))

    class FakeClientSession:
        def __init__(self, read, write):
            pass

        async def __aenter__(self):
            return mock_session

        async def __aexit__(self, *args):
            return None

    class FakeStdioClient:
        def __init__(self, params):
            self.params = params

        async def __aenter__(self):
            return (None, None)

        async def __aexit__(self, *args):
            return None

    fake_stdio_module = SimpleNamespace(stdio_client=FakeStdioClient)
    fake_mcp_module = SimpleNamespace(
        ClientSession=FakeClientSession,
        StdioServerParameters=lambda **kwargs: SimpleNamespace(**kwargs),
    )

    import builtins

    original_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "mcp.client.stdio":
            return fake_stdio_module
        if name == "mcp":
            return fake_mcp_module
        return original_import(name, globals, locals, fromlist, level)

    with patch.object(builtins, "__import__", side_effect=fake_import):
        info = await probe_stdio(
            LiveServerConfig(command="python", args=["server.py"], stderr_file="/tmp/mcp.err")
        )

    assert info.initialize_succeeded is True
    assert info.tools == []
    assert len(info.discovery_warnings) == 1
    assert info.discovery_warnings[0].startswith("list_tools failed:")
    assert "/tmp/mcp.err" in info.discovery_warnings[0]


def test_scanner_adds_meta_finding_for_partial_live_discovery(tmp_path: Path) -> None:
    server = MCPServerInfo(
        name="demo",
        discovery_mode="live",
        initialize_succeeded=True,
        discovery_warnings=["list_tools failed: denied"],
    )
    config = ScanConfig(target=tmp_path, live=True)
    report = Scanner(config).analyze_server(server)
    meta = [f for f in report.findings if f.analyzer == "live_discovery"]
    assert len(meta) == 1
