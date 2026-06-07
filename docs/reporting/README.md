# Reporting

> [Documentation](../index.md) → **Reporting**

How MCTS presents risk: auditable scores, technique IDs, and multi-format export.

---

## Guides

| Page | Contents |
|------|----------|
| [Scoring Specification](scoring-spec.md) | Weights, exponential formula, category breakdown, CI gates, worked examples |
| [Threat Taxonomy](taxonomy.md) | MCTS-T / MCTS-M catalog, runtime techniques, Sigma rules, regression fixtures |
| [HTML Security Dashboard](html-report.md) | Dashboard pages, scoring display, export, implementation, design system |

---

## Output formats

| Format | Command | Use case |
|--------|---------|----------|
| Terminal | `mcts scan` (default) | Developer feedback |
| JSON | `mcts scan -o report.json` | Automation, `mcts report` input |
| SARIF | `mcts scan -f sarif -o report.sarif` | GitHub Code Scanning |
| HTML | `mcts report report.json` | Executive / security review |

---

## Related

- [CLI — output formats](../platform/cli.md)
- [CI Integration](../platform/ci-integration.md)
- [Documentation index](../index.md)
