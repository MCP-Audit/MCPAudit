# REST API

> [Documentation](../index.md) → [Platform](README.md)

MCTS exposes an optional **FastAPI** server for programmatic scans — same `Scanner` class as the CLI.

Implementation: `api/app.py` · CLI: `mcts serve`.

---

## Install

```bash
uv sync --extra api
```

Adds `fastapi` and `uvicorn`.

---

## Start server

```bash
mcts serve --host 127.0.0.1 --port 8080
# OpenAPI docs: http://127.0.0.1:8080/docs
```

---

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check `{ "status": "ok" }` |
| `POST` | `/scan` | Full security scan |
| `POST` | `/scan-tool` | Scan a single tool by name |
| `POST` | `/scan-all-tools` | Scan each tool separately |
| `POST` | `/scan-prompt` | Scan a single prompt |
| `POST` | `/scan-all-prompts` | Scan all prompts |
| `POST` | `/scan-resource` | Scan a single resource URI |
| `POST` | `/scan-all-resources` | Scan all resources |
| `POST` | `/scan-instructions` | Scan server instructions |
| `POST` | `/readiness` | Production readiness (HEUR + optional OPA) |

### `POST /scan` body

```json
{
  "target": ".",
  "live": false,
  "url": "https://mcp.example.com/mcp",
  "transport": "streamable-http",
  "bearer_token": "optional",
  "surfaces": ["tool", "prompt", "resource", "instruction"],
  "resource_mime_allowlist": ["text/plain", "application/json"],
  "pip_audit": false,
  "protocol_probe": false
}
```

Response: full `ScanReport` JSON (`model_dump()`).

### Example

```bash
curl -s -X POST http://127.0.0.1:8080/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "examples/vulnerable-mcp-server/server.py"}' | jq .score

curl -s -X POST http://127.0.0.1:8080/scan-prompt \
  -H "Content-Type: application/json" \
  -d '{"target": ".", "prompt_name": "support_template", "live": true, "url": "..."}'
```

---

## Related

- [CLI Reference](cli.md)
- [Remote Scanning](../scanning/remote-scanning.md)
