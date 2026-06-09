"""Tests for surface-scoped analyzer selection."""

from __future__ import annotations

from mcts.analyzers.prompt_injection import PromptInjectionAnalyzer
from mcts.analyzers.supply_chain import SupplyChainAnalyzer
from mcts.core.surface_analyzers import analyzer_allowed_for_surfaces


def test_prompt_only_scan_allows_prompt_analyzers() -> None:
    assert analyzer_allowed_for_surfaces(
        PromptInjectionAnalyzer(),
        ["prompt", "instruction"],
        enabled=True,
    )


def test_prompt_only_scan_blocks_supply_chain() -> None:
    assert not analyzer_allowed_for_surfaces(
        SupplyChainAnalyzer(target=__import__("pathlib").Path(".")),
        ["prompt", "instruction"],
        enabled=True,
    )


def test_full_surface_scan_allows_supply_chain() -> None:
    assert analyzer_allowed_for_surfaces(
        SupplyChainAnalyzer(target=__import__("pathlib").Path(".")),
        ["tool", "prompt", "resource", "instruction"],
        enabled=True,
    )
