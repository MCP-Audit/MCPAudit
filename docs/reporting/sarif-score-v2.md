# SARIF `mcts/scoreV2` extension

MCTS SARIF output (`--format sarif`) includes optional run properties when `score_v2` is present:

```json
{
  "runs": [{
    "properties": {
      "mcts/scoreV2": {
        "absoluteRisk": 2260,
        "securityScore": 12,
        "riskLevel": "critical"
      }
    }
  }]
}
```

## Code Scanning adoption

GitHub Code Scanning ingests SARIF by default but **does not surface custom run properties** in the Security tab. Consumers must:

1. Parse SARIF JSON in CI or dashboards.
2. Read `runs[].properties["mcts/scoreV2"]` explicitly.
3. Gate on `absoluteRisk` / `securityScore` with `--min-security-score` or `--max-absolute-risk` in the MCTS CLI/Action instead of relying on Code Scanning UI alone.

Legacy `score.overall` is not written to SARIF run properties in v2.0 — use CLI gates or custom SARIF post-processing for dual-score policies.
