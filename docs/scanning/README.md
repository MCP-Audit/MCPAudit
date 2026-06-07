# Scanning

> [Documentation](../index.md) → **Scanning**

MCTS discovers MCP servers through **static source analysis**, optional **live stdio probing**, **protocol fuzzing**, and **client config inventory**. Discovery output becomes `MCPServerInfo` — the input to all security analyzers.

---

## Mode selection guide

| Your situation | Recommended mode | Command |
|----------------|------------------|---------|
| Python/TS source in repo | Static scan | `mcts scan ./repo/` |
| Need runtime tool schemas | Static + live merge | `mcts scan ./repo/ --live --i-understand-live-risk` |
| npm package, no source | Config + live | `mcts scan . --config ... --server X --live ...` |
| Protocol hardening test | Fuzz → scan pipeline | `mcts fuzz ... -o fuzz.json` then `--runtime-events` |
| Audit laptop MCP installs | Inventory | `mcts inventory --scan` |
| Node server, no `npm install` | TS static discovery | `mcts scan ./repo/ --languages typescript` |

---

## Guides

| Guide | What you'll learn |
|-------|-------------------|
| [Live Scanning](live-scanning.md) | Consent model, discovery modes, merge semantics, behavioral probe |
| [Protocol Fuzzing](fuzzing.md) | safe/standard/aggressive levels, probe catalog, CI usage |
| [TypeScript Discovery](typescript-discovery.md) | SDK patterns, Zod mapping, multi-language merge |
| [Config Inventory](inventory.md) | Client paths, JSON schema, cross-server shadowing |

---

## Data flow

```
Static (Py/TS) ──┐
Live probe ──────┼──► MCPServerInfo ──► Analyzers
Fuzz events ─────┤
Inventory ───────┘ (cross-server context)
```

Deep dive: [Architecture — Discovery](../analysis/architecture.md#discovery-layer-discovery)

---

## Related

- [Getting Started](../get-started/getting-started.md)
- [CLI Reference](../platform/cli.md)
- [Documentation index](../index.md)
