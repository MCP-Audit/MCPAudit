# Static JSON Snapshot Scanning

> [Documentation](../index.md) → [Scanning](README.md)

**Snapshot scanning** analyzes a pre-exported JSON file of MCP tool metadata — no source code, no running server, no network. Ideal for air-gapped environments or CI pipelines that export tool lists separately.

> **Have source code?** A regular static scan is simpler: `mcts scan ./repo/`

---

## In plain English

Sometimes you can't run MCTS against live source code or a running server — for example, in an air-gapped CI environment. Snapshot mode lets you export your server's tool list as JSON (from a trusted environment) and scan that file offline.

MCTS reads the JSON, extracts tool names, descriptions, and schemas, and runs the same security analyzers as a normal scan. Handler source code checks won't run (there's no source), but metadata checks (permissions, poisoning, schema issues) still work.

---

## When to use

| Scenario | Why snapshot mode |
|----------|-------------------|
| CI without subprocess/network | Scan exported JSON artifact only |
| Regulated environments | No live MCP connection |
| Comparing analyzer versions | Same input across MCTS releases |
| PR review of tool metadata | Scan changed `tools.json` from build |

---

## Input formats

### Combined snapshot object

```json
{
  "tools": [
    {
      "name": "fetch",
      "description": "Fetch a URL",
      "inputSchema": { "type": "object", "properties": { "url": { "type": "string" } } }
    }
  ],
  "prompts": [],
  "resources": [],
  "instructions": "You are a helpful assistant."
}
```

### Tools-only array

```json
[
  { "name": "greet", "description": "Say hello", "inputSchema": {} }
]
```

### Separate files (advanced)

Use individual paths via CLI when exporting prompts/resources separately (future flags); primary entry is `--snapshot`.

---

## Usage

```bash
# Export tools from a trusted environment, then scan offline
mcts scan . --snapshot ./artifacts/tools-list.json -o report.json

# With CI gates
mcts scan . --snapshot tools.json \
  --fail-on-critical --min-score 70 \
  -o report.json
```

`discovery_mode` on the resulting `MCPServerInfo` is `static-json`.

---

## Analyzers that apply

All metadata analyzers run on snapshot data:

- `SurfaceMetadataAnalyzer` — tools, prompts, resources, instructions
- `SigmaMetadataAnalyzer`, `PromptInjectionAnalyzer`, etc. on tools
- `PromptDefenseAnalyzer` on prompts/instructions
- Supply chain analyzers still scan the **repository** at `target` when `--pip-audit` / `--npm-audit` are set

Snapshot mode does **not** produce live `runtime_events` unless you also pass `--runtime-events`.

---

## Exporting a snapshot

From a live scan (trusted server only):

```bash
mcts scan ./server.py --live --i-understand-live-risk -o live.json
# Extract server.tools from live.json → tools-list.json
```

Or use your MCP client's `tools/list` JSON-RPC response directly.

---

## Related

- [CLI Reference](../platform/cli.md#mcts-scan)
- [Remote Scanning](remote-scanning.md)
- [CI Integration](../platform/ci-integration.md)
