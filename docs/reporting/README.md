# Reporting

> [Documentation](../index.md) → **Reporting**

How MCTS **presents** results — scores, exports, and shareable reports.

> **Just ran your first scan?** The terminal already showed a summary. To share with others, generate [HTML](html-report.md).

---

## Output formats

| Format | Command | Best for |
|--------|---------|----------|
| **Terminal** | `mcts scan ./server.py` | Quick feedback while coding |
| **JSON** | `mcts scan … -o report.json` | Automation, input for HTML report |
| **SARIF** | `mcts scan … -f sarif -o report.sarif` | GitHub / GitLab Code Scanning |
| **HTML** | `mcts report report.json -o report.html` | Leadership and security reviews |

---

## Score at a glance

| Score | Grade | Meaning |
|-------|-------|---------|
| 76–100 | A–B | Good posture |
| 51–75 | C | Review before production |
| 26–50 | D | Significant issues |
| 0–25 | F | Do not deploy |

Details: [Scoring specification](scoring-spec.md)

---

## Guides

| Page | When to read |
|------|--------------|
| [Scoring specification](scoring-spec.md) | CI gates and score formula |
| [HTML dashboard](html-report.md) | Executive report layout |
| [Threat taxonomy](taxonomy.md) | MCTS-T technique IDs on findings |

---

## Related

- [Getting started](../get-started/getting-started.md)
- [CI integration](../platform/ci-integration.md)
- [Documentation index](../index.md)
