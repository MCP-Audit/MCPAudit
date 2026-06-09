# Reporting

> [Documentation](../index.md) → **Reporting**

Reporting is how MCTS **presents** scan results — as a security score, categorized findings, and exportable files you can share with your team or plug into CI.

> **Just ran your first scan?** Your terminal already showed a report. To share results, see [HTML Security Dashboard](html-report.md).
> **Setting up CI gates?** See [Scoring Specification](scoring-spec.md).

---

## Output formats at a glance

| Format | How to generate | Best for |
|--------|-------------------|----------|
| **Terminal** | `mcts scan ./server.py` (default) | Quick developer feedback during development |
| **JSON** | `mcts scan ./server.py -o report.json` | Automation, input for HTML report, custom tooling |
| **SARIF** | `mcts scan ./server.py -f sarif -o report.sarif` | GitHub Code Scanning, GitLab, Azure DevOps |
| **HTML** | `mcts report report.json -o report.html` | Sharing with security teams, leadership, auditors |

---

## Understanding your score

| Score range | Grade | Meaning |
|-------------|-------|---------|
| 76–100 | A–B | Good security posture |
| 51–75 | C | Moderate issues — review before production |
| 26–50 | D | Significant issues — remediation needed |
| 0–25 | F | Critical issues — do not deploy |

The score is calculated from finding severities using a transparent formula — never hardcoded. See [Scoring Specification](scoring-spec.md) for the math and CI gate examples.

---

## Guides

| Page | What you'll learn |
|------|-------------------|
| [Scoring Specification](scoring-spec.md) | How the 0–100 score is calculated, category breakdown, CI gate thresholds |
| [Threat Taxonomy](taxonomy.md) | MCTS-T technique IDs and MCTS-M mitigation IDs on every finding |
| [HTML Security Dashboard](html-report.md) | Generate and customize the executive HTML report |

---

## Planned reporting features

| Feature | Status |
|---------|--------|
| CycloneDX / AI-BOM export | Planned |
| Scan history and trend charts | Planned |
| Interactive attack-graph HTML | Planned |

Full backlog: [Feature Expansion Plan](../more/feature-expansion-plan.md)

---

## Related

- [CLI — output formats](../platform/cli.md)
- [CI Integration](../platform/ci-integration.md)
- [Glossary](../glossary.md)
- [Documentation index](../index.md)
