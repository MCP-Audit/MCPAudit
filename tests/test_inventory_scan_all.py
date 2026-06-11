"""Inventory scan-all JSON serialization."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from mcts.inventory.models import InventoryEntry
from mcts.inventory.scan_all import _row
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import RiskScore, ScanReport, ScanSummary, ScoreBasis


def test_inventory_row_json_serializable() -> None:
    report = ScanReport(
        version="0.0.0",
        target="server.py",
        scanned_at=datetime.now(UTC),
        server=MCPServerInfo(name="demo"),
        findings=[],
        summary=ScanSummary(),
        score=RiskScore(
            overall=100,
            risk_index=0,
            raw_risk=0,
            penalty=0,
            basis=ScoreBasis(critical=0, high=0, medium=0, low=0, scorable_total=0, excluded_non_scorable=0),
        ),
        scoring_version="legacy",
    )
    entry = InventoryEntry(client="c", server_name="s", config_path="p")
    row = _row(
        entry,
        report=report.model_dump(mode="json"),
        score=100,
        findings=0,
        scoring_version="legacy",
    )
    payload = json.dumps({"scan_results": [row]})
    assert "scan_results" in payload
