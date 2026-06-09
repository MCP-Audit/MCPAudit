# TypeScript / JavaScript Static Discovery

> [Documentation](../index.md) → [Scanning](README.md)

MCTS can scan **Node.js MCP servers** written in TypeScript or JavaScript — without running Node or installing npm dependencies. It reads source files and extracts tool definitions using pattern matching.

> **Python servers?** Just run `mcts scan ./server.py` — Python discovery is the default.
> **Mixed repo?** Directory scans automatically discover both Python and TypeScript.

---

## In plain English

If your MCP server is written in TypeScript (using the `@modelcontextprotocol/sdk` or similar), MCTS can find your tools by reading the source code — the same way it reads Python `@tool` decorators. No `npm install` or Node.js runtime needed.

This means you can run `mcts scan ./my-ts-server/` in CI and get the same security checks (permissions, injection, secrets, attack chains) as you would for a Python server.

---

## Supported registration patterns

| Pattern | SDK / style | Extraction approach |
|---------|-------------|---------------------|
| `registerTool` | Modern `@modelcontextprotocol/sdk` `McpServer.registerTool("name", { inputSchema: {...} }, handler)` | Regex + balanced-brace parsing for schema object |
| `server.tool` | Shorthand `server.tool("name", { param: z.string() }, handler)` | Zod parameter mapping |
| `setRequestHandler(ListToolsRequestSchema)` | Legacy SDK | Inline `tools: [{ name, description, inputSchema }]` array |
| `setRequestHandler(CallToolRequestSchema)` | Legacy fallback | Tool names from `params.name === "..."` / `case "..."` branches |

### Zod → JSON Schema mapping

Common Zod types are converted to JSON Schema fragments for analyzers:

| Zod | JSON Schema type |
|-----|------------------|
| `z.string()` | `{ "type": "string" }` |
| `z.number()` | `{ "type": "number" }` |
| `z.boolean()` | `{ "type": "boolean" }` |
| `z.array(...)` | `{ "type": "array", "items": ... }` |
| `z.object({...})` | `{ "type": "object", "properties": {...} }` |

Inline JSON Schema `properties` in `inputSchema` objects are preserved as-is.

---

## File types scanned

`.ts`, `.tsx`, `.js`, `.jsx`, `.mjs`, `.cjs`

### Excluded by default

| Pattern | Reason |
|---------|--------|
| `node_modules/` | Third-party code |
| `dist/`, `build/` | Compiled output |
| `tests/`, `__tests__/` | Test fixtures |
| `.git`, venv dirs | Same as Python static discovery |

Configure via `ScanConfig.exclude_dirs` and `exclude_globs` in `core/config.py`.

---

## Usage

```bash
# Scan TS MCP repo (Python + TypeScript by default)
mcts scan examples/bench/multi-file-ts-server/

# TypeScript only
mcts scan ./my-node-mcp-server/ --languages typescript

# Python only (skip JS/TS)
mcts scan ./mixed-repo/ --languages python

# Single entry file
mcts scan src/server.ts
```

---

## Multi-language merge

`ScanConfig.languages` defaults to `["python", "typescript"]`.

For directory targets:

1. `discover_static()` runs Python discovery (`discovery/static.py`) if `python` is listed
2. Runs JS/TS discovery if `typescript` is listed
3. `static_merge.py` merges tools **by name** — when both languages define the same tool, the entry with the **richer** `input_schema` wins

This allows monorepos with Python wrappers and TypeScript implementations to produce a unified tool list.

---

## What analyzers receive

Each discovered tool becomes an `MCPTool`:

| Field | Source |
|-------|--------|
| `name` | Registration pattern |
| `description` | String literal or doc comment near registration |
| `input_schema` | Parsed JSON Schema / Zod mapping |
| `source_file` | Relative path to `.ts`/`.js` file |
| `source_line` | Approximate registration line |
| `handler_snippet` | Surrounding source context when extractable |
| `discovered_via` | `"static"` |
| `capability` | Inferred by `capability/inferrer.py` for attack chains |

Source-aware analyzers (`command_execution`, `path_validation`, `data_leakage`) scan `handler_snippet` and full file content when available.

---

## Limitations

| Limitation | Workaround |
|------------|------------|
| Regex-based, not full AST | Covers common MCP SDK patterns; edge cases may miss dynamic registration |
| No `npm install` / type checking | Zero-dependency CI tradeoff |
| Dynamic tool names | Not resolved without live probe — use `--live` |
| Minified bundles | Skipped via `dist/` exclusion — scan source instead |
| Deep handler taint analysis | Planned: optional tree-sitter depth (roadmap) |

---

## Combining with live probe

When TS source exists **and** you run `--live`:

```bash
mcts scan ./my-ts-server/ --live --i-understand-live-risk
```

Static discovery extracts handler source; live probe validates runtime schemas. Merge mode produces `discovery_mode: merged`.

For npm-published servers without source, use config-based live scan:

```bash
mcts scan . --config ~/.cursor/mcp.json --server ts-server \
  --live --i-understand-live-risk
```

---

## Benchmark fixture

`examples/bench/multi-file-ts-server/` exercises multi-file TS discovery in CI. See `tests/` for regression coverage.

---

## Related

- [Architecture — Discovery](../analysis/architecture.md#discovery-layer-discovery)
- [CLI — `--languages`](../platform/cli.md#mcts-scan)
- [Live Scanning](live-scanning.md)
