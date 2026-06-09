# Architecture

> [Documentation](../index.md) → [Analysis](README.md)

How MCTS works internally: discovery → analyzers → scoring → report.

| Read this if you… | Jump to |
|-------------------|---------|
| Just want to scan | [Getting started](../get-started/getting-started.md) — skip this doc |
| Need to understand a finding | [Security checks](security-checks.md) |
| Are contributing code | [Quick start for contributors](../../CONTRIBUTING.md#quick-start-for-first-time-contributors) + [Extension points](#extension-points) |
| Are debugging a scan | [Scan lifecycle](#scan-lifecycle) + [Debugging](#debugging-scans) |

> Terms: [Glossary](../glossary.md)

---

## On this page

1. [At a glance](#at-a-glance)
2. [End-to-end pipeline](#end-to-end-pipeline)
3. [Entry points](#entry-points)
4. [Scan lifecycle](#scan-lifecycle)
5. [Core data models](#core-data-models)
6. [Layers](#layers)
7. [Analyzers](#analyzers)
8. [Scoring and reporting](#scoring-and-reporting)
9. [Supporting commands](#supporting-commands)
10. [Package layout](#package-layout)
11. [Extension points](#extension-points)
12. [Debugging scans](#debugging-scans)

Roadmap and planned work: [Product roadmap](../more/roadmap.md) (not covered here).

---

## At a glance

When you run `mcts scan ./server.py`:

1. **Discover** — Build an `MCPServerInfo` snapshot (tools, prompts, resources, handler source, optional live schemas)
2. **Analyze** — Run security analyzers; each returns `Finding` objects
3. **Post-process** — Dedupe, enrich with MCTS-T IDs, append OWASP compliance meta-findings
4. **Score** — Compute 0–100 score (compliance findings excluded from score)
5. **Report** — Terminal UI, JSON, SARIF, or HTML via `mcts report`

**Orchestrator:** `Scanner` in `src/mcts/core/scanner.py`  
**Config:** `ScanConfig` in `src/mcts/core/config.py`  
**CLI:** `mcts scan` in `src/mcts/cli/main.py`

---

## End-to-end pipeline

```mermaid
flowchart LR
  subgraph input [Input]
    CLI["CLI / API"]
    CFG["ScanConfig"]
  end

  subgraph discover [Discovery]
    STATIC["Static Py/TS"]
    LIVE["Live stdio / HTTP"]
    SNAP["JSON snapshot"]
    STATIC --> MERGE["MCPServerInfo"]
    LIVE --> MERGE
    SNAP --> MERGE
  end

  subgraph analyze [Analysis]
    ANA["Analyzers"]
    DEDUPE["Dedupe + enrich"]
    COMP["Compliance OWASP"]
    ANA --> DEDUPE --> COMP
  end

  subgraph output [Output]
    SCORE["RiskScoringEngine"]
    REP["ScanReport"]
    OUT["Terminal · JSON · SARIF · HTML"]
    SCORE --> REP --> OUT
  end

  CLI --> CFG --> STATIC
  CFG --> LIVE
  CFG --> SNAP
  MERGE --> ANA
  COMP --> SCORE
```

ASCII equivalent:

```
ScanConfig ──► Discovery (static / live / snapshot) ──► MCPServerInfo
                              │
                              ▼
                    Analyzers (parallel, sequential loop)
                              │
                              ▼
              filters → dedupe → enrich (MCTS-T) → compliance
                              │
                              ▼
                    RiskScoringEngine → ScanReport → outputs
```

---

## Entry points

| Surface | Module | Typical use |
|---------|--------|-------------|
| **CLI** | `cli/main.py` | `mcts scan`, `inventory`, `fuzz`, `vet`, `pentest` |
| **REST API** | `api/app.py` | `mcts serve` — same `Scanner`, JSON in/out |
| **Python API** | `core/scanner.py` | `Scanner(ScanConfig).run()` or `.analyze_server(info)` |
| **MCP server mode** | `mcp_server/` | `mcts-mcp` tools for IDE agents |

All scan paths converge on `Scanner.analyze_server(MCPServerInfo)`.

---

## Scan lifecycle

`Scanner.run()` discovers first; `Scanner.analyze_server()` runs the analysis pipeline (also used by API and tests with pre-built snapshots).

### 1. Discovery (`MCPClient.discover()`)

| Source | When | Module |
|--------|------|--------|
| Python static AST | Default repo/file scan | `discovery/static.py` |
| TypeScript/JS patterns | `--languages typescript` | `discovery/static_js.py` |
| Live stdio MCP | `--live` | `discovery/live.py`, `probe/session.py` |
| Remote HTTP/SSE | `--url` | `probe/http_session.py` |
| Exported JSON | `--snapshot` | `discovery/static_json.py` |
| Client config launch | `--config` + `--server` | `discovery/live_config.py` |

Static + live can merge when `merge_static_live` is true (default). See [Scanning overview](../scanning/README.md).

### 2. Attach runtime context

- Merge `--runtime-events` file rows with live / behavioral probe events
- Attach `surface_scan` options (`--surfaces`, MIME allowlist)
- Emit `discovery_meta` findings if live discovery was incomplete

### 3. Run analyzers

Loop registered analyzers; skip disabled or filtered ones (`--analyzers`, config toggles). See [Analyzers](#analyzers).

Optional: `probe_protocol_security()` when `--protocol-probe` + `--url`.

### 4. Post-process findings

| Step | Function | Purpose |
|------|----------|---------|
| Filter | `_apply_filters()` | `--tool-filter`, `--analyzer-filter`, `--severity-filter`, `--technique` |
| Metadata dedupe | `dedupe_metadata_findings()` | Collapse duplicate metadata hits |
| Sigma dedupe | `dedupe_sigma_findings()` | Collapse duplicate Sigma matches |
| Enrich | `enrich_findings()` | Attach `technique_id`, `mitigation_ids`, crosswalk evidence |
| Compliance | `ComplianceChecker.check()` | OWASP LLM + MCP meta-findings (**non-scoring**) |

### 5. Score and verify

`RiskScoringEngine.score()` → `ScoreBasis`; `verify()` asserts score matches findings (regression guard).

### 6. Build `ScanReport`

Includes `attack_graph` from `AttackChainAnalyzer`, partitioned `score_breakdown`, scan scope notes, and `analyzers_executed` audit list.

Optional: `--save-baseline` writes tool metadata snapshot for rug-pull detection on future scans.

---

## Core data models

Defined in `mcp/models.py` and `reporting/models.py`.

### MCPServerInfo

The **single input** every analyzer receives.

| Field | Purpose |
|-------|---------|
| `tools`, `prompts`, `resources` | MCP surfaces with schemas and text |
| `instructions` | Server system instructions when exposed |
| `source_files` | Path → content cache for SAST |
| `runtime_events` | Telemetry rows for runtime analyzers |
| `discovery_mode` | `static`, `live`, `merged`, `config-static`, etc. |
| `surface_scan` | Per-scan surface and MIME options |

### MCPTool (key fields)

| Field | Purpose |
|-------|---------|
| `name`, `description`, `input_schema` | Tool metadata |
| `handler_snippet`, `source_file`, `source_line` | Static SAST context |
| `capability` | `CapabilityProfile` for attack chains |

### Finding

| Field | Purpose |
|-------|---------|
| `analyzer` | Source check (e.g. `permission_analyzer`) |
| `severity` | `critical` / `high` / `medium` / `low` |
| `technique_id` | MCTS-T-* (after enrichment) |
| `evidence`, `location` | Proof and source line |
| `tool` | Related tool name when applicable |

### ScanReport

| Field | Purpose |
|-------|---------|
| `findings`, `summary` | All issues and severity counts |
| `score` | Overall score + auditable `basis` |
| `server` | Full discovery snapshot |
| `attack_graph` | Capability-graph paths for UI |
| `analyzers_executed` | Which checks ran |

Full field lists: source models in `reporting/models.py`.

---

## Layers

### Discovery (`discovery/`, `mcp/client.py`)

Turns a filesystem path, live process, or JSON file into `MCPServerInfo`.

| Module | Role |
|--------|------|
| `static.py` | Python `@tool` AST, schemas, handler snippets |
| `static_js.py` | TS/JS registerTool / handler patterns |
| `static_merge.py`, `static_runner.py` | Multi-language repo walks |
| `live.py`, `live_config.py` | Stdio / config-based live probe |
| `static_json.py` | Air-gapped snapshot load |
| `merge.py` | Static + live merge |
| `env_expand.py`, `json5_util.py` | IDE config parsing |

Guides: [Live](../scanning/live-scanning.md) · [Remote](../scanning/remote-scanning.md) · [Snapshot](../scanning/static-snapshot.md) · [TypeScript](../scanning/typescript-discovery.md)

### Probe (`probe/`)

Transport, consent, and event extraction for live modes.

| Module | Role |
|--------|------|
| `session.py` | Async stdio MCP session |
| `http_session.py` | Streamable HTTP / SSE |
| `auth.py` | Bearer, headers, OAuth client credentials |
| `consent.py` | `--i-understand-live-risk` / `MCTS_LIVE_OK` |
| `behavioral.py`, `events.py` | Runtime event rows for analyzers |
| `protocol_checks.py` | Active MCPS HTTP checks |

### Orchestration (`core/scanner.py`)

Builds analyzer list in `_build_analyzers()`, runs lifecycle above. Filters and technique mode applied after analyzers complete.

### Analyzers (`analyzers/`)

See [Analyzers](#analyzers) below.

### Taxonomy (`taxonomy/`)

| Asset | Role |
|-------|------|
| `techniques.json` | MCTS-T catalog |
| `mapper.py` | `enrich_findings()` |
| `crosswalk.json` | External framework IDs in evidence |
| `sigma/metadata_rules.json` | Bundled metadata Sigma rules |

### Scoring (`scoring/`)

Exponential decay formula; compliance excluded. Details: [Scoring spec](../reporting/scoring-spec.md).

### Reporting (`reporting/`, `report/`, `ui/`)

| Output | Path |
|--------|------|
| JSON / SARIF | `reporting/models.py`, `reporting/sarif.py` |
| Terminal | `ui/dashboard.py`, themes in `ui/theme.py` |
| HTML | `report/generators/html_report.py` |

---

## Analyzers

All analyzers implement `BaseAnalyzer.analyze(server: MCPServerInfo) -> list[Finding]` (`analyzers/base.py`).

Registered in `Scanner._build_analyzers()`. User-facing descriptions: [Security checks](security-checks.md).

### Always registered (core)

Run unless disabled by `_is_enabled()` or `--analyzers` subset.

| Key | Focus |
|-----|-------|
| `permission_analyzer` | Destructive / high-risk tool names and descriptions |
| `metadata_integrity` | Description poisoning patterns |
| `prompt_injection` | Injection heuristics in metadata |
| `tool_shadowing` | Duplicate tool names within server |
| `line_jumping` | Context precedence attacks |
| `tool_abuse` | Path traversal in metadata |
| `schema_surface` | Full schema poisoning (FSP) |
| `data_leakage` | Secrets in source + metadata |
| `command_execution` | Shell/exec in handlers |
| `path_validation` | Missing path checks |
| `runtime_events` | Telemetry cluster (delegates to sub-detectors) |
| `sigma_metadata` | Bundled + custom Sigma YAML |
| `oauth_config` | OAuth misconfiguration |
| `supply_chain` | Dependency posture heuristics |

### Default-on (config toggles)

| Key | Toggle | Focus |
|-----|--------|-------|
| `surface_metadata` | `enable_surface_metadata` (default on) | Multi-surface poisoning |
| `prompt_defense` | `enable_prompt_defense` (default on) | Missing defensive language |
| `behavioral_static` | `enable_behavioral_static` (default on) | Description vs handler + taint |
| `jailbreak` | `enable_jailbreak` (default on) | Manipulation resistance |
| `attack_chains` | `enable_attack_chains` (default on) | Capability-graph BFS |

### Conditional on inputs

| Key | Enabled when |
|-----|--------------|
| `metadata_diff` | `--baseline` provided |
| `embedding_secrets` | `--semantic-secrets` |
| `cross_server` | Inventory with ≥2 servers (e.g. `inventory --scan`) |
| `toxic_flows` | Inventory with ≥2 servers + `--full-toxic-flows` |

### Opt-in (flags / extras)

| Key | Flag | Notes |
|-----|------|-------|
| `vulnerable_package` | `--pip-audit` | Requires `supplychain` extra |
| `npm_audit` | `--npm-audit` | npm audit subprocess |
| `yara_metadata` | `--yara` | Requires `yara` extra |
| `llm_judge` | `--llm-judge` | Requires `MCTS_LLM_API_KEY` |
| `llm_metadata_triage` | `--llm-triage` | malicious / safe / suspect |
| `semgrep_sast` | `--semgrep` | Requires `semgrep` CLI on PATH |
| `cloud_inspect` | `--cloud-inspect` | Requires cloud API key |
| `virustotal` | `--virustotal` | Hash lookup |

### Multi-surface iteration

`analyzers/surfaces.py` defines `ScanSurface` for tools, prompts, resources, and instructions. Surface-aware analyzers iterate via `scan_surfaces(server)`.

### Behavioral SAST (`sast/`)

Used by `behavioral_static`. Python AST taint + optional tree-sitter for TS/Go/Rust. Semgrep rules in `sast/semgrep/rules/`. Install deep parsers: `uv sync --extra sast`.

### Runtime sub-detectors

`RuntimeEventsAnalyzer` routes telemetry rows to focused modules (e.g. `rug_pull.py`, `command_injection.py`, `tool_redefinition.py`). Technique mapping: [Threat taxonomy](../reporting/taxonomy.md) and `tests/fixtures/regression/MCTS-T-*/`.

### Attack chains (`capability/`, `analyzers/attack_chains.py`)

`capability/inferrer.py` assigns per-tool flags (`reads_untrusted_input`, `egresses_network`, `executes_commands`, …). BFS finds paths like read → exfiltrate. Graph stored on `ScanReport.attack_graph`.

---

## Scoring and reporting

| Metric | Formula | Notes |
|--------|---------|-------|
| Raw risk | C×25 + H×10 + M×3 + L×1 | Linear weighted sum |
| Overall score | `round(100 × e^(-raw/50))` | Higher is better |
| Risk index | `min(100, raw_risk)` | Higher is worse |

`compliance` analyzer findings are **informational only** — they do not affect score.

Outputs:

- **Terminal** — Rich dashboard (`ui/`)
- **JSON** — full `ScanReport` dump
- **SARIF** — `--format sarif` for GitHub Code Scanning
- **HTML** — `mcts report` executive dashboard

---

## Supporting commands

These share discovery/models but use separate entry paths:

| Command | Module | Role |
|---------|--------|------|
| `mcts fuzz` | `fuzz/` | Protocol probes → `runtime_events` JSON |
| `mcts inventory` | `inventory/` | Client config discovery; feeds cross-server / toxic-flow analyzers |
| `mcts vet` | `vet/` | Pre-install PyPI/npm/OCI checks |
| `mcts pentest` | `pentest/` | Structured recon + attack chains |
| `mcts readiness` | `readiness/` | HEUR-001–020 (separate from security score) |
| `mcts serve` | `api/` | REST wrapper around `Scanner` |

---

## Package layout

```
src/mcts/
├── cli/           # Typer commands and flag wiring
├── core/          # Scanner, ScanConfig, target resolution
├── mcp/           # MCPServerInfo models, MCPClient.discover()
├── discovery/     # Static, live, snapshot, merge
├── probe/         # Live transport, consent, behavioral events
├── analyzers/     # Security checks (subclass BaseAnalyzer)
├── sast/          # Taint analysis + Semgrep rule pack
├── capability/    # Tool capability profiles
├── scoring/       # RiskScoringEngine, category partitions
├── compliance/    # OWASP mapping (non-scoring)
├── taxonomy/      # MCTS-T/M, Sigma, crosswalk, enrichment
├── reporting/     # Pydantic models, SARIF
├── report/        # HTML dashboard templates
├── ui/            # Terminal Rich UI
├── inventory/     # Client config + skills discovery
├── fuzz/          # Fuzz runner
├── vet/           # Package vetting
├── pentest/       # Pentest phases
├── governance/    # YAML policy gates
├── readiness/     # Production heuristics + OPA
├── api/           # FastAPI (mcts serve)
├── mcp_server/    # mcts-mcp stdio tools
├── output/        # Analysis dir, history, artifacts
└── testing/       # Regression harness
```

---

## Extension points

### Add an analyzer

1. Create `src/mcts/analyzers/your_check.py`:

```python
from mcts.analyzers.base import BaseAnalyzer
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Finding, Severity

class YourAnalyzer(BaseAnalyzer):
    name = "your_check"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        ...
```

2. Register in `Scanner._build_analyzers()` (`core/scanner.py`).
3. Add CLI flag in `cli/main.py` + field on `ScanConfig` if opt-in.
4. Add tests in `tests/`; regression fixture under `tests/fixtures/regression/MCTS-T-*/` when adding a technique.
5. Document in [Security checks](security-checks.md).

If the check needs inventory context, pass `inventory=` like `OAuthConfigAnalyzer`.

### Add a runtime detector

Add a module under `analyzers/` and wire it from `RuntimeEventsAnalyzer` (`runtime_events.py`) for the relevant event types.

### Add discovery for a language

Extend `discovery/static_runner.py` and add a parser module (see `static_js.py` pattern).

### Add a Semgrep rule

Add YAML under `sast/semgrep/rules/`; map `metadata.technique_id` to MCTS-T.

Contributor quick start: [CONTRIBUTING.md](../../CONTRIBUTING.md#quick-start-for-first-time-contributors)

---

## Debugging scans

| Symptom | Where to look |
|---------|---------------|
| No tools discovered | Discovery logs; try `--auto`; check `--languages`, exclude dirs |
| Score seems wrong | `score.basis` in JSON; compliance findings are non-scoring |
| Analyzer missing from report | `analyzers_executed` on `ScanReport`; check `--analyzers` subset and opt-in flags |
| Live scan incomplete | `discovery_warnings` → `live_discovery` findings; `--strict-live` |
| False positive | Analyzer module + fixture in `tests/fixtures/regression/` |
| Technique ID missing | `taxonomy/mapper.py` catalog + `enrich_findings()` |

**Useful commands:**

```bash
uv run mcts scan ./server.py -o /tmp/report.json
uv run python -c "import json; r=json.load(open('/tmp/report.json')); print(r['analyzers_executed'])"
uv run pytest tests/test_scanner.py -q
uv run pytest tests/fixtures/regression/ -q   # if applicable
```

---

## Related

- [Security checks reference](security-checks.md) — what each analyzer looks for
- [Scoring specification](../reporting/scoring-spec.md)
- [Threat taxonomy](../reporting/taxonomy.md)
- [CLI reference](../platform/cli.md)
- [CONTRIBUTING.md](../../CONTRIBUTING.md)
