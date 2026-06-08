# Static JSON Snapshot Scanning

> [Documentation](../index.md) → [Scanning](README.md)

Air-gapped and CI-friendly mode: scan pre-exported MCP metadata JSON **without** launching a server or connecting to a network. Useful when a pipeline exports `tools/list` results from a trusted environment.

Implementation: `discovery/static_json.py`.

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
