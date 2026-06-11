"""API gate_violations field on scan responses."""

from __future__ import annotations

import pytest


def test_scan_response_includes_gate_violations(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from mcts.api.app import app

    monkeypatch.delenv("MCTS_LIVE_OK", raising=False)
    client = TestClient(app)
    response = client.post(
        "/scan",
        json={
            "target": "examples/vulnerable-mcp-server/server.py",
            "scoring_mode": "v2",
            "max_absolute_risk": 100,
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["scoring_mode"] == "v2"
    assert "gate_violations" in payload
    assert isinstance(payload["gate_violations"], list)
    assert payload["gate_violations"]
