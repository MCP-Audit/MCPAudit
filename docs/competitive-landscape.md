# MCP Security Tool Landscape

Reference catalog of MCP security tools MCTS was evaluated against during design. **Upstream repos are not vendored in this project** — this page preserves the useful comparison context in first-party docs.

For MCTS-specific strengths and gaps, see [Competitive Positioning](competitive-positioning.md). For SAF-MCP taxonomy relationship, see [External Frameworks](external-frameworks.md).

---

## Tool catalog

| Tool | Upstream | Role | Notable capabilities |
|------|----------|------|----------------------|
| **MCTS** | [MCP-Audit/MCTS](https://github.com/MCP-Audit/MCTS) | MCP server scanner + CI gates | Local-first, SARIF, HTML dashboard, attack chains, MCTS-T taxonomy, stdio live probe, safe fuzz defaults |
| **mcp-scanner** | [cisco-ai-defense/mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) | Multi-engine MCP scanner | Live stdio/SSE/HTTP, YARA, tree-sitter SAST, behavioral LLM alignment, REST API |
| **MCPScan** | Community Semgrep pipeline | Repo + metadata scanner | Semgrep rules + optional LLM stages on descriptions/code |
| **agent-scan** | [snyk/agent-scan](https://github.com/snyk/agent-scan) | Agent/MCP discovery + cloud analysis | 10+ client configs, live introspection, Snyk cloud findings, enterprise guard |
| **agent-security-scanner-mcp** | ProofLayer / agent-security | Full-stack agent security | Semgrep 1700+ rules, SBOM, compliance frameworks, MCP server mode |
| **mcp-guard** | Community monolith | Repo ZIP + dynamic fuzz | Broad `tools/call` fuzz by default, CVSS-style scoring (claims exceed shipped code in places) |
| **McpSafetyScanner** | [johnhalloran321/mcpSafetyScanner](https://github.com/johnhalloran321/mcpSafetyScanner) | LLM red-team narrative | Agent team audit flow, markdown reports (early alpha) |
| **scanner-main** | [SAF-MCP/scanner](https://github.com/SAF-MCP/scanner) | SAF-MCP corpus consumer (Rust) | LLM-assisted scan over technique specs, MCP tools for IDE agents |
| **saf-mcp** | [SAF-MCP/saf-mcp](https://github.com/SAF-MCP/saf-mcp) | Threat intelligence framework | SAF-T techniques, Sigma YAML, mitigations — not an executable scanner |
| **mcp-fortress** | Various | Package + gamification scanner | npm/PyPI CVE, MCP server mode, React dashboard (verify claims against source) |

---

## Peer highlights (what informed MCTS)

### mcp-scanner (Cisco)

- **Take:** Multi-transport live probing is the bar for protocol depth; tree-sitter + taint for SAST.
- **MCTS today:** Stdio live probe, Python/TS MCP-specific static discovery, no YARA/cloud API dependency.
- **Gap:** SSE/HTTP transports, deep taint analysis.

### MCPScan

- **Take:** Semgrep corpus is valuable for generic code issues; LLM stages need keys and add non-determinism.
- **MCTS today:** MCP-boundary analyzers, deterministic CI, regression harness.
- **Gap:** Optional Semgrep extra (roadmap).

### agent-scan (Snyk)

- **Take:** Broad client inventory and enterprise upload patterns.
- **MCTS today:** Four-client inventory, local findings, SARIF/HTML without token.
- **Gap:** More agent clients, runtime guard (out of scope).

### agent-security-scanner-mcp

- **Take:** SBOM/compliance and MCP-as-a-tool for IDE integration.
- **MCTS today:** Attack chains, lean install, MCP-specific scoring.
- **Gap:** SBOM, `mcts-mcp` server mode (Phase 3).

### mcp-guard

- **Take:** Dynamic fuzz finds protocol/handler issues static analysis misses; aggressive `tools/call` needs guardrails.
- **MCTS today:** Consent-tiered fuzz (`safe` default read-only); modular analyzers; SARIF + CI exit codes.
- **Lesson:** Several marketed features (SARIF, CI gates, sandbox) are not in mcp-guard source — validate peer claims against code.

### McpSafetyScanner

- **Take:** LLM red-team narratives complement structured scanners.
- **MCTS today:** Structured JSON/SARIF/HTML; `mcts pentest` stub for future agent-assisted testing.

### scanner-main + saf-mcp

- **Take:** OpenSSF SAF-MCP is the authoritative MCP **threat vocabulary**; scanners should map findings to stable IDs without vendoring the full corpus.
- **MCTS today:** First-party `MCTS-T-*` / `MCTS-M-*` catalog; informal upstream crosswalk for research only — see [External Frameworks](external-frameworks.md).

---

## Capability matrix (at a glance)

| Capability | mcp-scanner | agent-scan | agent-security | mcp-guard | MCTS |
|------------|-------------|------------|----------------|-----------|------|
| Offline core scan | Partial | No (findings cloud) | Partial | Yes | **Yes** |
| SARIF | No | No | Yes | No | **Yes** |
| HTML executive report | No | No | Yes | No | **Yes** |
| CI score gates | Partial | No | Partial | No | **Yes** |
| Live MCP probe | **Multi-transport** | Yes | No | Partial | Stdio |
| Attack chains | Implicit | No | No | No | **Capability graph** |
| Config inventory | Yes | **Broadest** | Partial | No | 4 clients |
| Semgrep / deep SAST | **Yes** | No | **Yes** | Regex | MCP-focused |
| Safe fuzz default | N/A | N/A | N/A | No | **Yes** |

---

## When to use which tool

| Need | Recommendation |
|------|----------------|
| Offline PR gates, SARIF, scorecard, HTML for MCP repos | **MCTS** |
| Live multi-transport probe + YARA + Cisco API enrichment | mcp-scanner |
| Fleet-wide agent config discovery + Snyk cloud | agent-scan |
| Broad Semgrep + SBOM + compliance frameworks | agent-security-scanner-mcp |
| Maximum destructive fuzz on a lab server (accept risk) | mcp-guard aggressive mode |
| Threat modeling vocabulary and Sigma reference rules | saf-mcp (framework, not scanner) |
| LLM narrative red-team (experimental) | McpSafetyScanner |

---

## Related

- [Competitive Positioning](competitive-positioning.md)
- [External Frameworks](external-frameworks.md)
- [Roadmap](roadmap.md)
