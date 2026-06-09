# Scanning

> [Documentation](../index.md) → **Scanning**

Scanning is how MCTS **finds** MCP servers and **collects data** about their tools, prompts, resources, and handler code. This data feeds into the security analyzers described in [Analysis](../analysis/README.md).

> **Unfamiliar with scan modes?** See [Which scan mode should I use?](#which-scan-mode-should-i-use) below, or check the [Glossary](../glossary.md).

---

## Which scan mode should I use?

Answer these questions to pick the right mode:

**Do you have the server's source code?**
- **Yes** → Start with a static scan: `mcts scan ./repo/`
- **No, but it's running locally** → Use live probe: `mcts scan . --config ~/.cursor/mcp.json --server my-server --live --i-understand-live-risk`
- **No, it's hosted remotely** → Use remote scan: `mcts scan . --url https://... --i-understand-live-risk`
- **No, but you have an exported JSON file** → Use snapshot: `mcts scan . --snapshot tools.json`

**Do you need runtime schemas (what the server actually advertises)?**
- Add `--live --i-understand-live-risk` to merge live tool listings with static analysis

**Do you want to test protocol robustness?**
- Run fuzz first, then feed results into scan: `mcts fuzz ... -o fuzz.json` → `mcts scan ... --runtime-events fuzz.json`

**Do you want to audit what's installed on your machine?**
- Run inventory: `mcts inventory --scan`

---

## Mode comparison

| Mode | Reads source code | Starts server | Needs network | Best for |
|------|:-:|:-:|----------|
| **Static** (default) | Yes | No | No | Daily development, CI on repos |
| **Live probe** | Optional | Yes | No | Verifying runtime tool schemas |
| **Remote** | No | No | Yes | Hosted MCP endpoints |
| **Snapshot** | No | No | No | Air-gapped CI |
| **Fuzz** | No | Yes | No | Protocol hardening tests |
| **Inventory** | Optional | No | No | Auditing local MCP configs |

---

## Guides

| Guide | What you'll learn |
|-------|-------------------|
| [Live Scanning](live-scanning.md) | How to probe a running server, consent model, merge with static analysis |
| [Remote Scanning](remote-scanning.md) | Scan hosted HTTP/SSE servers with authentication |
| [Static Snapshot](static-snapshot.md) | Scan from exported JSON without network or subprocess |
| [Protocol Fuzzing](fuzzing.md) | Safe/standard/aggressive fuzz levels and CI usage |
| [TypeScript Discovery](typescript-discovery.md) | Scan Node.js MCP servers without `npm install` |
| [Config Inventory](inventory.md) | Find MCP servers in Cursor, Claude, VS Code, Windsurf configs |
| [Readiness Scanning](readiness.md) | Production readiness checks (separate from security scoring) |

---

## How scanning feeds analysis

```
Your source code ──┐
Running server ────┼──► Discovered tools & schemas ──► Security analyzers ──► Findings & score
Fuzz telemetry ────┤
Local configs ─────┘
```

After discovery, every scan mode produces the same `MCPServerInfo` structure that all analyzers consume. The scan mode only affects **what data is collected**, not **what checks run**.

Deep dive: [Architecture — Discovery](../analysis/architecture.md#discovery-layer-discovery)

---

## Planned discovery modes

These features are on the roadmap but not yet shipped:

| Mode | Status | Notes |
|------|--------|-------|
| Machine-wide scan (all client configs) | Planned | Scan all MCP servers without specifying a target |
| 12+ agent clients (Gemini, Codex, etc.) | Partial | More client config paths |
| Skills directories + `SKILL.md` | Planned | Scan agent skill files |
| Remote fuzz (`mcts fuzz --url`) | Planned | Fuzz hosted servers, not just stdio |

See [Feature Expansion Plan](../more/feature-expansion-plan.md) for the full backlog.

---

## Related

- [Getting Started](../get-started/getting-started.md)
- [CLI Reference](../platform/cli.md)
- [Glossary](../glossary.md)
- [Documentation index](../index.md)
