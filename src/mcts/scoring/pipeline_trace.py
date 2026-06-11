"""Test-only pipeline event trace for scanner ordering (invariant I2)."""

from __future__ import annotations

EVENTS: list[str] = []


def record(event: str) -> None:
    EVENTS.append(event)


def clear() -> None:
    EVENTS.clear()
