# Readiness Scanning

> [Documentation](../index.md) → [Scanning](README.md)

**Readiness** checks assess production reliability of MCP tools — timeouts, retries, error schemas, descriptions, rate limits, and operational documentation. This is **separate from the security risk score** and does not affect `score.overall`.

Implementation: `readiness/heuristics.py`, `readiness/opa.py`, `readiness/llm_judge.py` · CLI: `mcts readiness`.

---

## When to use

| Scenario | Command |
|----------|---------|
| Platform team onboarding | `mcts readiness ./mcp-server/` |
| Pre-production checklist | Run after `mcts scan` for security |
| Policy-based gates | `mcts readiness ./repo/ --opa` (requires `opa` CLI) |
| Semantic review | `mcts readiness ./repo/ --llm-judge` (requires `--extra llm`) |

---

## Usage

```bash
mcts readiness examples/vulnerable-mcp-server/server.py
mcts readiness ./repo/ -o readiness.json
mcts readiness ./repo/ --opa
mcts readiness ./repo/ --llm-judge
```

Output includes a **readiness score** (0–100), `production_ready` flag, and per-tool HEUR findings.

---

## Rules (HEUR-001 – HEUR-020)

| Category | Rules |
|----------|-------|
| Timeout guards | HEUR-001, HEUR-002 |
| Retry config | HEUR-003, HEUR-004, HEUR-005 |
| Error handling | HEUR-006, HEUR-007, HEUR-008 |
| Description quality | HEUR-009, HEUR-010 |
| Input validation | HEUR-011, HEUR-012 |
| Operational config | HEUR-013, HEUR-014, HEUR-015 |
| Resource management | HEUR-016, HEUR-017 |
| Safety | HEUR-018, HEUR-019, HEUR-020 |

Optional **OPA** policies in `readiness/policies/*.rego` add policy violations when `opa` is installed.

Optional **LLM judge** evaluates actionable errors, failure modes, and scope clarity (opt-in only).

Readiness findings use analyzer key `readiness` and are excluded from security scoring.

---

## Related

- [CLI Reference — mcts readiness](../platform/cli.md#mcts-readiness)
- [Scoring Specification](../reporting/scoring-spec.md) — security score only
