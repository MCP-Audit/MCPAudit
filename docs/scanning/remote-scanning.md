# Remote MCP Scanning (HTTP / SSE)

> [Documentation](../index.md) → [Scanning](README.md)

MCTS can connect to **production remote MCP servers** over streamable HTTP or SSE — not only local stdio subprocesses. Remote probing uses the official MCP Python SDK (`streamable_http_client`, `sse_client`) and supports Bearer tokens, custom headers, and OAuth client credentials.

Implementation: `probe/http_session.py`, `probe/auth.py`, `discovery/live.py`.

---

## When to use

| Scenario | Command pattern |
|----------|-----------------|
| Hosted MCP endpoint (HTTPS) | `mcts scan . --url https://host/mcp --i-understand-live-risk` |
| SSE transport | `--url https://host/sse --transport sse` |
| Authenticated endpoint | `--bearer-token "$TOKEN"` or `--header "X-Api-Key: ..."` |
| Protocol security audit | Add `--protocol-probe` for MCPS-style HTTP checks |
| Config with remote URL | `--config mcp.json --server name` when entry has `url` field |

---

## Install

```bash
uv sync --extra mcp
```

---

## Basic usage

```bash
# Streamable HTTP (default transport)
mcts scan . \
  --url https://mcp.example.com/mcp \
  --i-understand-live-risk

# SSE
mcts scan . \
  --url https://mcp.example.com/sse \
  --transport sse \
  --i-understand-live-risk

# Bearer auth
mcts scan . \
  --url https://mcp.example.com/mcp \
  --bearer-token "$MCP_TOKEN" \
  --i-understand-live-risk
```

Custom headers (repeatable):

```bash
mcts scan . \
  --url https://gateway.example.com/mcp \
  --header "Authorization: Bearer $TOKEN" \
  --header "X-Tenant-Id: acme" \
  --i-understand-live-risk
```

---

## OAuth client credentials

Set environment variables or use config JSON fields (`oauthTokenUrl`, `oauthClientId`, etc.):

| Variable | Purpose |
|----------|---------|
| `MCTS_BEARER_TOKEN` | Pre-issued bearer token |
| OAuth fields in config | `oauth_token_url`, `oauth_client_id`, `oauth_client_secret`, `oauth_scopes` |

`RemoteAuth` in `probe/auth.py` fetches a token before connecting when OAuth fields are present.

---

## Protocol security probes

Active checks against the HTTP endpoint (encryption, auth, rate-limit headers):

```bash
mcts scan . \
  --url http://insecure.example.com/mcp \
  --protocol-probe \
  --i-understand-live-risk
```

Findings use analyzer `protocol_probe` and map to **MCTS-T-1027**. Checks include:

- MCPS-001 — plaintext HTTP
- MCPS-002 — unauthenticated 200 responses
- MCPS-009 — missing rate-limit headers

---

## Multi-surface scanning

Remote scans list tools, prompts, resources, and instructions. Analyze all surfaces:

```bash
mcts scan . \
  --url https://mcp.example.com/mcp \
  --surfaces tool,prompt,resource,instruction \
  --i-understand-live-risk
```

`SurfaceMetadataAnalyzer` applies poisoning patterns to every surface type.

---

## Consent

Remote probing still requires `--i-understand-live-risk` or `MCTS_LIVE_OK=1` — you are connecting to a real server that may log or process probe traffic.

---

## Limitations

| Limitation | Detail |
|------------|--------|
| Read-only probe | `list_*` only during scan; use `mcts fuzz` for protocol stress |
| OAuth flows | Client credentials supported; interactive browser OAuth not yet |
| WebSocket | Not supported |

---

## Related

- [Live Scanning](live-scanning.md) — stdio probing and merge semantics
- [CLI Reference — remote flags](../platform/cli.md#mcts-scan)
- [Static Snapshot](static-snapshot.md) — air-gapped alternative
