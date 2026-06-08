# Remote bearer MCP server (fixture notes)

Use MCTS against a remote HTTP/SSE MCP deployment with bearer auth:

```bash
mcts scan --url https://host.example/mcp \
  --transport streamable-http \
  --bearer-token "$MCP_TOKEN" \
  --protocol-probe \
  --surfaces tool,prompt,resource,instruction \
  --i-understand-live-risk
```

For dual-header gateway setups, repeat `--header`:

```bash
mcts scan --url https://gateway.example/mcp \
  --header "X-Gateway-Key: $GATEWAY_KEY" \
  --header "Authorization: Bearer $UPSTREAM_TOKEN" \
  --i-understand-live-risk
```

Static prompt-only CI without launching a server:

```bash
mcts scan --snapshot examples/fixtures/prompts-snapshot.json --surfaces prompt,instruction
```
