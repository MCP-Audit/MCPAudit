# Platform

> [Documentation](../index.md) → **Platform**

Platform docs cover how to **run MCTS** — from the command line, in CI/CD pipelines, or via REST API.

> **New user?** Start with [Getting Started](../get-started/getting-started.md) before reading the full CLI reference.

---

## Commands at a glance

| Command | What it does | When to use |
|---------|--------------|-------------|
| `mcts scan` | Full security scan | Default — scan source code, live, remote, or snapshot |
| `mcts report` | JSON → HTML dashboard | Share results with security teams or leadership |
| `mcts inventory` | List local MCP configs | Audit which servers are installed on your machine |
| `mcts fuzz` | Protocol fuzz probes | Test how a server handles malformed input |
| `mcts readiness` | Production readiness checks | Operational heuristics (separate from security score) |
| `mcts serve` | Start REST API server | Programmatic scans from other tools or services |

---

## Guides

| Page | What you'll learn |
|------|-------------------|
| [CLI Reference](cli.md) | Every command, flag, and exit code |
| [REST API](rest-api.md) | `mcts serve` — programmatic scan endpoints |
| [CI Integration](ci-integration.md) | GitHub Action, SARIF upload, pipeline gate patterns |

---

## Common workflows

### Daily development

```bash
mcts scan ./server.py                          # Quick check in terminal
mcts scan ./server.py --theme minimal          # Cleaner output
```

### CI/CD pipeline

```bash
mcts scan ./server.py --fail-on-critical --min-score 70 -o report.json
mcts scan ./server.py -f sarif -o report.sarif
```

Or use the [GitHub Action](../../action/README.md). See [CI Integration](ci-integration.md).

### Share with stakeholders

```bash
mcts scan ./server.py -o report.json
mcts report report.json -o security-report.html
```

---

## Planned platform features

| Feature | Status |
|---------|--------|
| `mcts inspect`, `mcts vet`, `mcts watch` | Planned |
| `--ci` preset flag | Planned |
| Pre-commit hook installer | Planned |

Full backlog: [Feature Expansion Plan](../more/feature-expansion-plan.md)

---

## Related

- [Getting Started](../get-started/getting-started.md)
- [Scoring Specification](../reporting/scoring-spec.md)
- [GitHub Action README](../../action/README.md)
- [Glossary](../glossary.md)
- [Documentation index](../index.md)
