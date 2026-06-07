# Platform

> [Documentation](../index.md) → **Platform**

Operational guides for running MCTS locally, in CI, and via the published GitHub Action.

---

## Guides

| Page | Contents |
|------|----------|
| [CLI Reference](cli.md) | Complete reference: `scan`, `report`, `inventory`, `fuzz`, all flags, exit codes, env vars, examples |
| [CI Integration](ci-integration.md) | GitHub Action, SARIF upload, gate patterns, live/fuzz in CI, inventory audit |

---

## Commands at a glance

| Command | Purpose |
|---------|---------|
| `mcts scan` | Full security scan |
| `mcts report` | JSON → HTML dashboard |
| `mcts inventory` | Local MCP config discovery |
| `mcts fuzz` | Protocol fuzz probes |
| `mcts pentest` | Stub (planned) |

---

## Related

- [Getting Started](../get-started/getting-started.md)
- [Scoring Specification](../reporting/scoring-spec.md)
- [GitHub Action README](../../action/README.md)
- [Documentation index](../index.md)
