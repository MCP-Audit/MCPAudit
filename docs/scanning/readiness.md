# Readiness Scanning

> [Documentation](../index.md) → [Scanning](README.md)

**Readiness scanning** checks whether your MCP server is production-ready — things like error handling, timeouts, documentation, and rate limits. This is **separate from security scoring** and does not affect your security score.

> **Want security checks?** Use `mcts scan` instead. Readiness is for operational quality.

---

## In plain English

Security scanning (`mcts scan`) finds vulnerabilities. Readiness scanning (`mcts readiness`) checks whether your server is **well-built for production** — does it have proper error schemas? Are descriptions clear? Are there timeouts? Is logging configured?

Think of it as a code quality check specifically for MCP servers. Readiness findings use their own IDs (HEUR-001 through HEUR-020) and appear separately from security findings.

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
