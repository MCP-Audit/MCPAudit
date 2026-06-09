"""SQL database dump patterns via MCP SQL tools (MCTS-T-1043)."""

from __future__ import annotations

import re
from typing import Any

SQL_TOOL_MARKERS: tuple[str, ...] = (
    "sql.query",
    "sql.execute",
    "db.query",
    "db.execute",
    "database_query",
    "database.query",
    "cloud-sql.query",
    "cloud-sql.execute",
    "run_sql",
    "execute_sql",
)

DUMP_SQL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"select\s+\*\s+from", re.I),
    re.compile(r"\bpg_dump\b", re.I),
    re.compile(r"\bmysqldump\b", re.I),
    re.compile(r"\bbackup\s+database\b", re.I),
    re.compile(r"\bexport\s+data\b", re.I),
    re.compile(r"\bcopy\s+.+\s+to\s+stdout", re.I),
    re.compile(r"\binto\s+outfile\b", re.I),
    re.compile(r"\bdrop\s+table\b", re.I),
    re.compile(r"\btruncate\s+table\b", re.I),
)

_LARGE_ROW_THRESHOLD = 100_000


def detect_sql_dump(*, tool_name: str, tool_parameters: Any = None, result: Any = None) -> bool:
    """Return True when a SQL-capable MCP tool shows dump-like activity."""
    if not _is_sql_tool(tool_name):
        return False
    sql_text = _extract_sql(tool_parameters)
    if sql_text and any(pattern.search(sql_text) for pattern in DUMP_SQL_PATTERNS):
        return True
    row_count = _extract_row_count(result)
    return row_count is not None and row_count >= _LARGE_ROW_THRESHOLD


def _is_sql_tool(tool_name: str) -> bool:
    lowered = tool_name.lower().replace("-", "_")
    if any(marker.replace(".", "_") in lowered or marker in lowered for marker in SQL_TOOL_MARKERS):
        return True
    return any(token in lowered for token in ("sql", "query", "database")) and "graphql" not in lowered


def _extract_sql(params: Any) -> str:
    if isinstance(params, str):
        return params
    if not isinstance(params, dict):
        return ""
    for key in ("sql", "query", "statement", "command", "text"):
        value = params.get(key)
        if isinstance(value, str):
            return value
    return " ".join(str(value) for value in params.values() if isinstance(value, str))


def _extract_row_count(result: Any) -> int | None:
    if not isinstance(result, dict):
        return None
    for key in ("row_count", "rows", "estimated_rows", "affected_rows"):
        value = result.get(key)
        if isinstance(value, int):
            return value
    return None
