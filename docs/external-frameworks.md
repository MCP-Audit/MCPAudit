# External Threat Frameworks

MCTS uses a **first-party taxonomy** (`MCTS-T-*` techniques, `MCTS-M-*` mitigations). External frameworks — especially [OpenSSF SAF-MCP](https://github.com/SAF-MCP/saf-mcp) — inform detection patterns and roadmap priorities but are **not vendored** in this repository.

**Product source of truth:** `src/mcts/taxonomy/techniques.json` · [Threat Taxonomy](taxonomy.md)

---

## SAF-MCP vs MCTS

| Dimension | SAF-MCP | MCTS |
|-----------|---------|------|
| **What it is** | Threat intelligence framework | Automated MCP security scanner |
| **Primary output** | Technique dossiers, Sigma YAML, mitigations | Findings, scores, JSON/SARIF/HTML |
| **Execution** | Static git repository + reference scripts | CLI: `mcts scan`, `inventory`, `fuzz` |
| **Answers** | "What attacks exist and how do they work?" | "Does my server/config exhibit this risk?" |

They are **complementary**: SAF-MCP is closer to MITRE ATT&CK; MCTS is closer to SAST/DAST for MCP artifacts.

```
        SAF-MCP (threat taxonomy)
                 │
     patterns, fixtures, mitigations
                 │
    ┌────────────┼────────────┐
    ▼            ▼            ▼
  MCTS      MCPScan    mcp-scanner
 (scanner)  (Semgrep)   (multi-engine)
    │            │            │
    └────────────┴────────────┘
                 │
         Findings use native IDs
         (MCTS-T-* on MCTS reports)
```

---

## Informative upstream crosswalk (research only)

MCTS reports **do not** emit `SAF-T*` IDs. Maintainers may use this table for gap analysis when reading upstream dossiers:

| MCTS-T ID | Informative SAF-MCP peer |
|-----------|--------------------------|
| MCTS-T-1001 | SAF-T1001, SAF-T1402 (tool poisoning) |
| MCTS-T-1001.002 | SAF-T1001.002 / SAF-T1501 (full-schema poisoning) |
| MCTS-T-1002 | SAF-T1105 (path traversal) |
| MCTS-T-1008 | SAF-T1008 (tool shadowing) |
| MCTS-T-1011–1019 | SAF-T1007–T1308 (OAuth family) |
| MCTS-T-1013 | SAF-T1201 (rug pull) |
| MCTS-T-1014 / 1015 | SAF-T1002, SAF-T1003 (supply chain) |
| MCTS-T-1022 | SAF-T1505 (semantic credentials) |
| MCTS-T-1026 | SAF-T1603 (behavioral extraction) |
| MCTS-T-1034 | SAF-T2106 (vector poisoning) |
| MCTS-T-1040 | SAF-T1205 (persistent redefinition) |
| MCTS-T-1041 | SAF-T1401 (instruction steganography) |

Do not reintroduce upstream ID fields on `Finding` — use `technique_id` and optional `evidence` tags only.

---

## What MCTS adopted from upstream research

Patterns and fixtures were mined from SAF-MCP reference artifacts into MCTS-owned modules (Apache-2.0 / CC-BY-4.0 — attribute upstream when publishing comparisons):

| Area | MCTS modules | Status |
|------|--------------|--------|
| TPA / metadata poisoning patterns | `tpa_patterns.py`, `prompt_injection`, `metadata_integrity`, `sigma_metadata` | Shipped |
| Homoglyph, Unicode tag block, mixed-script | `tpa_patterns.py` | Shipped |
| Recursive schema / FSP | `schema_fsp.py`, `schema_surface.py` | Partial |
| Credential regex + semantic secrets | `data_leakage.py`, `embedding_secrets.py` (`--semantic-secrets`) | Shipped |
| Path traversal encodings | `path_traversal.py`, fuzz payloads | Shipped |
| Sigma metadata rules | `taxonomy/sigma/metadata_rules.json`, `--sigma-rules-path` | Shipped |
| OAuth dossiers | `oauth_config.py`, runtime OAuth cluster | Shipped (MCTS-T-1011–1019) |
| Rug pull / redefinition | `metadata_diff.py`, `tool_redefinition.py`, `--baseline` | Shipped |
| Supply chain signals | `supply_chain.py` | Shipped |
| NDJSON-style regression fixtures | `tests/fixtures/regression/MCTS-T-*/` | Shipped (34+ IDs, CI ≥80% gate) |

---

## Static vs runtime detection (important)

Most SAF-MCP Sigma rules assume **runtime telemetry** (`tool_description`, `path`, `oauth_token`, `event_type: file_access`). MCTS primarily performs **pre-deployment static analysis** on source and discovered tool metadata, plus optional live/fuzz telemetry via `--live`, `mcts fuzz`, and `--runtime-events`.

Both layers are valid; they are not drop-in substitutes. Runtime rules must be adapted to metadata/source context when porting patterns.

---

## Roadmap informed by upstream density

SAF-MCP tactic distribution suggests prioritization for remaining MCTS work:

- **Initial Access + Execution + Privilege Escalation** — highest technique density (TPA, prompt injection, OAuth, cross-server)
- **Next regression fixtures** — multimodal, exfiltration, C2 cluster techniques not yet gated in CI
- **Optional advanced** — embedding-based detection (SAF-M-63 style), deeper behavioral probes, vector-store checks for RAG MCP servers

---

## What not to port blindly

| Upstream artifact | Why caution |
|-------------------|-------------|
| Runtime Sigma rules on static repos | Log field names do not exist in source scans |
| Behavioral demo thresholds | Tuned for conversation logs, not tool manifests |
| Attack PoC scripts | Use as test vectors only — do not bundle into scanner |
| Index-only techniques | Wait for mature dossiers before MCTS-T promotion |

---

## Licensing when borrowing patterns

| SAF-MCP content | License | MCTS practice |
|-----------------|---------|---------------|
| Technique READMEs | CC-BY-4.0 | Cite upstream in docs; product output uses MCTS-T only |
| Sigma YAML, test scripts | Apache-2.0 | Compile into owned modules; no upstream paths in fixtures |
| Example PoCs | Apache-2.0 | Inform regression cases and pattern lists |

---

## Related

- [Threat Taxonomy](taxonomy.md)
- [Competitive Landscape](competitive-landscape.md)
- [Architecture — Taxonomy](architecture.md#taxonomy-taxonomy)
