# RedMCP

**Offensive security testing framework for Model Context Protocol (MCP) servers.**

Make MCP security testing as easy as running a linter.

```bash
redmcp scan ./server.py
```

## Problem

MCP servers expose databases, APIs, file systems, cloud resources, and SaaS tools to AI agents — often without rigorous security review. RedMCP helps teams find issues before attackers do.

## Features

| Module | Status | Description |
|--------|--------|-------------|
| Permission Analyzer | ✅ Alpha | Flags destructive and over-privileged tools |
| Prompt Injection Simulator | ✅ Alpha | Tests known injection attack patterns |
| Tool Abuse Testing | ✅ Alpha | Detects path traversal and misuse surfaces |
| Data Leakage Detection | ✅ Alpha | Scans for secrets and sensitive references |
| Agent Jailbreak Testing | 🚧 Planned | Resistance scoring against jailbreak suites |
| Multi-Step Attack Chains | ✅ Alpha | Identifies dangerous tool combinations |
| Risk Scoring Engine | ✅ Alpha | CVSS-inspired security score (0–100) |
| Compliance Checks | ✅ Alpha | OWASP LLM Top 10 & MCP best practices |
| CI/CD Integration | 🚧 Planned | GitHub Action for pipeline gates |
| HTML Reports | ✅ Alpha | `redmcp report` → `security-report.html` |
| MCP Fuzzer | 🔮 Roadmap | `redmcp fuzz` |
| RedMCP Agent | 🔮 Roadmap | `redmcp pentest` |

## Quick Start

### Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (recommended)

### Install

```bash
git clone https://github.com/redmcp/redmcp.git
cd redmcp
uv sync --all-extras
```

### Scan an MCP server

```bash
uv run redmcp scan examples/vulnerable-mcp-server/server.py
```

Save JSON results and generate HTML:

```bash
uv run redmcp scan examples/vulnerable-mcp-server/server.py -o report.json
uv run redmcp report report.json -o security-report.html
```

### CI gate (fail on critical)

```bash
uv run redmcp scan ./server.py --fail-on-critical
```

## Architecture

```
           ┌──────────────┐
           │ MCP Server   │
           └──────┬───────┘
                  │
                  ▼
         ┌─────────────────┐
         │ RedMCP Scanner  │
         └─────────────────┘
                  │
     ┌────────────┼────────────┐
     ▼            ▼            ▼
Permission   Injection     Leakage
Analyzer      Engine       Scanner
     ▼            ▼            ▼
       Risk Scoring Engine
                  ▼
          Security Report
```

## Project Structure

```
RedMCP/
├── src/redmcp/          # Main package (src layout)
│   ├── cli/             # Typer CLI (`scan`, `report`, `fuzz`, `pentest`)
│   ├── core/            # Scanner orchestration
│   ├── analyzers/       # Security analyzers
│   ├── scoring/         # Risk scoring engine
│   ├── compliance/      # OWASP & MCP compliance checks
│   ├── reporting/       # Models & HTML reports
│   └── mcp/             # MCP client & discovery
├── tests/               # pytest suite
├── examples/            # Sample vulnerable MCP servers
├── action/              # GitHub Action (planned)
└── docs/                # Documentation
```

## Development

```bash
uv sync --all-extras
uv run pytest
uv run ruff check src tests
uv run ruff format src tests
pre-commit install
```

## Positioning

| Tool | Domain |
|------|--------|
| SonarQube | Code quality |
| OWASP ZAP | Web security |
| Trivy | Container security |
| Semgrep | Static analysis |
| **RedMCP** | **MCP security** |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## Security

To report vulnerabilities, see [SECURITY.md](SECURITY.md).
