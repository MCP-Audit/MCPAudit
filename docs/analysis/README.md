# Analysis

> [Documentation](../index.md) → **Analysis**

Analysis is the step where MCTS **examines** discovered tools, schemas, and source code and **produces security findings**. This section explains what checks run, how they work, and how findings become a scored report.

> **Just want to know what MCTS checks?** Start with [Security Checks Reference](security-checks.md).
> **Want the full pipeline?** See [Architecture](architecture.md).

---

## How analysis works (simple view)

```
Discovered tools & code  →  20+ security checks  →  Findings with severity  →  Score (0–100)
```

1. **Discovery** (see [Scanning](../scanning/README.md)) produces a list of tools, their descriptions, input schemas, and handler source code
2. **Analyzers** run automated checks — each looking for a specific type of problem (permissions, injection, secrets, etc.)
3. **Enrichment** attaches technique IDs (`MCTS-T-*`) and mitigation IDs (`MCTS-M-*`) to each finding
4. **Scoring** converts findings into a 0–100 security score (see [Scoring Spec](../reporting/scoring-spec.md))
5. **Reporting** outputs results in terminal, JSON, SARIF, or HTML

---

## Guides

| Page | What you'll learn |
|------|-------------------|
| [Security Checks Reference](security-checks.md) | Every check MCTS runs — what it looks for, severity, and how to enable it |
| [Architecture](architecture.md) | Full pipeline internals: data models, analyzer registry, extension points |

---

## Key concepts

| Concept | Plain-language explanation |
|---------|---------------------------|
| **Finding** | A security issue MCTS detected, with a severity (Critical/High/Medium/Low), description, and remediation advice |
| **Analyzer** | One automated security check. MCTS runs 20 by default; 25+ with optional flags |
| **Attack chain** | A sequence of tools that together create serious risk (e.g. read data → send over network) |
| **Technique ID** | A label like `MCTS-T-1003` that identifies the threat type — useful for tracking and compliance |
| **Compliance finding** | OWASP LLM Top 10 mapping — shown in reports but does **not** affect the security score |

---

## Related

- [Scanning modes](../scanning/README.md) — how data is collected before analysis
- [Threat Taxonomy](../reporting/taxonomy.md) — technique and mitigation IDs
- [Scoring Specification](../reporting/scoring-spec.md) — how findings become a score
- [Glossary](../glossary.md)
- [Documentation index](../index.md)
