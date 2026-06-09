# HTML Security Dashboard

> [Documentation](../index.md) → [Reporting](README.md)

The HTML dashboard turns a JSON scan report into a **shareable, self-contained web page** — suitable for security reviews, leadership briefings, or audit documentation.

> **Haven't generated a report yet?** Run `mcts scan ./server.py -o report.json` first, then `mcts report report.json -o report.html`.

---

## In plain English

After scanning, you get a JSON file with all findings and scores. The HTML dashboard converts that JSON into a polished web page with:

- A visual score gauge and letter grade (A–F)
- Partitioned area scores (MCP Surface, Supply Chain, Dependency Hygiene) when present
- Severity breakdown, category radar chart, and scan history trend
- A searchable findings table with **location**, **MCTS-T technique links**, and remediation advice
- Attack chain visualization
- **OWASP LLM Top 10** and **OWASP MCP Top 10** mapping (including coverage gaps)
- Scan notes and static-scan tool-discovery disclaimers
- One-click export to PDF

The output is a single HTML file — no server needed to view it. Open it in any browser and share it via email or Slack.

---

## Quick start

```bash
# 1. Run a scan and save JSON
mcts scan examples/vulnerable-mcp-server/server.py -o report.json

# 2. Build the HTML dashboard
mcts report report.json -o security-report.html

# 3. Open in a browser
open security-report.html   # macOS
xdg-open security-report.html   # Linux
```

The output is one HTML file with **inlined CSS and JavaScript**. Chart.js and Inter font load from CDN on first open; scan data and brand assets are embedded for portability.

---

## Page structure

### Overview (landing)

| Section | Content |
|---------|---------|
| **Header** | MCTS logo, target path, scan timestamp, export menu |
| **Report guide** | How to read scores vs counts, quick-jump links |
| **Score gauge** | Doughnut chart showing `score.overall` (0–100 security points) |
| **Grade card** | Letter grade A–F derived from score |
| **Posture badge** | Critical / High / Medium / Low risk label |
| **Issues summary** | Severity table with counts and meanings |
| **Area sub-scores** | MCP Surface, Supply Chain, Dependency Hygiene, Composite (when `score_breakdown` present) |
| **Checks summary** | Analyzers run, passed, with findings, categories clear |
| **Executive summary** | Narrative posture + P1/P2 recommended actions |
| **Top findings / passed checks** | Quick lists linking to detail pages |
| **Category breakdown** | Progress bars per risk dimension |
| **Radar chart** | Your categories vs industry benchmark |
| **Trend panel** | Historical scores from `scan_history` or `mcts_analysis/history.json` |
| **Risk guide** | Reference cards for score ranges 0–25 through 76–100 |
| **Banners** | Tool-discovery notice (static scans), `scan_notes` |

Sidebar **Scan Information** includes target, **scan scope** (repository / live / snapshot / entrypoint), date/time, tools, and analyzers run.

### Sidebar pages

| Page | Purpose |
|------|---------|
| **Issues to Fix** | Search, filter by severity, sort; columns for location, technique, category, OWASP, tool, remediation |
| **All Checks** | Per-analyzer passed vs issues with severity breakdown |
| **How to Fix** | Prioritized P1–P4 remediation list with mitigation links |
| **Attack Paths** | SVG graph from `attack_graph` capability paths |
| **MCTS-T Map** | Full 79-technique catalog with Detected / Clear filters |
| **Capabilities** | Tool × capability matrix (reads input, egress, exec, etc.) |
| **OWASP Mapping** | LLM Top 10 findings + MCP Top 10 findings and coverage gaps |
| **Raw Data** | Full embedded `ScanReport` JSON for auditors |

Navigation is client-side (no server required).

---

## Findings table columns

| Column | Source | Notes |
|--------|--------|-------|
| Severity | `finding.severity` | Color-coded badge |
| Finding | `title` + `description` | Primary issue text |
| Location | `finding.location` | `file:line` for SAST; `—` when absent |
| Technique | `technique_id` + `technique_url` | Link to MCTS-T scenario when mapped |
| CWE | `finding.cwe_id` | Common Weakness Enumeration when mapped |
| Category | Analyzer label | Friendly name from `ANALYZER_LABELS` |
| OWASP | LLM Top 10 IDs | From `OWASP_LLM_ANALYZER_MAP` (same as compliance) |
| Affected Tool | `finding.tool` | MCP tool name when applicable |
| Confidence | `finding.confidence` | Analyzer confidence (0–100%) |
| Remediation | `recommendation` | Plus MCTS mitigation doc links |

Rows with structured **evidence** expand on click to show the full JSON blob.

Search matches title, category, tool, location, technique ID, CWE, and evidence summary.

---

## Scoring display

The dashboard mirrors CLI scoring exactly:

| Element | Source field | Notes |
|---------|--------------|-------|
| Security score | `score.overall` | Higher is better (0–100 points, not a %) |
| Risk index | `score.risk_index` | Shown in tooltip/detail |
| Letter grade | Computed in `report/data.py` | A=90+, F&lt;60 |
| Severity counts | `summary.*` | Scorable findings |
| Area sub-scores | `score_breakdown` | MCP Surface, Supply Chain, Dependency Hygiene, Composite |
| Category bars | `CATEGORY_DEFS` weighting | Higher bar = more risk in dimension |
| Formula tooltip | `score.basis` | Shows weighted calculation from severity counts |

**Important:** Security scores are **points**, not pass rates. A low overall score with elevated category bars is expected when severe findings are present.

---

## Attack chain graph

Renders `ScanReport.attack_graph` from `AttackChainAnalyzer`:

- Nodes = tools with capability profiles
- Edges = inferred attack transitions (read→exfil, read→exec, etc.)
- Empty state when no chains detected (no synthetic fake edges)

---

## OWASP mapping

### LLM Top 10

`llm_owasp_mappings()` uses `OWASP_LLM_ANALYZER_MAP` from `compliance/checks.py` (full LLM01–LLM10):

- **Finding cards** — categories where mapped analyzers reported issues
- **Coverage gap cards** — categories with no findings from mapped analyzers (mirrors compliance `owasp_llm_gaps` evidence)

### MCP Top 10

`mcp_owasp_mappings()` uses the same analyzer→category map as `ComplianceChecker` (`MCP_ANALYZER_MAP` in `compliance/checks.py`):

- **Finding cards** — MCP categories where mapped analyzers reported issues
- **Coverage gap cards** — MCP categories with no findings from mapped analyzers (mirrors compliance meta-findings when `compliance-mcp-top10-gaps` is emitted)

Compliance meta-findings do not affect the security score.

---

## Export options

Header **Export** menu and sidebar actions:

| Action | Mechanism |
|--------|-----------|
| **Download JSON** | Embedded `ScanReport` blob |
| **Save HTML** | Browser save of current document |
| **Print / PDF** | `@media print` styles for executive PDFs |

No data is sent to MCTS servers — all processing is local in the browser.

---

## Implementation architecture

```
mcts report report.json
        │
        ▼
ScanReport.model_validate_json()
        │
        ▼
report/data.py → build_dashboard_payload()
        │
        ▼
report/generators/html_report.py
  ├── Jinja2: templates/dashboard.html
  ├── Inline: assets/styles.css, assets/dashboard.js
  └── Embed: brand/logo-report.png (base64)
        │
        ▼
security-report.html (single file)
```

### Key files

| Path | Role |
|------|------|
| `report/templates/dashboard.html` | Jinja2 shell and section layout |
| `report/assets/styles.css` | Enterprise dark card design system |
| `report/assets/dashboard.js` | Charts, tables, navigation, export |
| `report/assets/icons/` | SVG severity icons |
| `report/data.py` | ScanReport → dashboard JSON |
| `report/generators/html_report.py` | Assembly and inlining |
| `compliance/checks.py` | MCP Top 10 analyzer map (shared with compliance) |
| `brand/logo-report.png` | Hex icon embed (no wordmark — legible at 44×44) |

Entry: `mcts.reporting.html.write_html_report()` delegates to generator.

### Tests

`tests/test_html_report.py` — payload builder validation, location/technique fields, MCP mappings, self-contained HTML smoke checks, delegation from CLI.

---

## Design system

All dashboard cards share:

| Token | Value |
|-------|-------|
| Background | `#0b1730` |
| Border radius | 16px |
| Border | `1px solid rgba(255,255,255,.06)` |
| Shadow | `0 8px 32px rgba(0,0,0,.35)` |
| Transition | 200ms hover lift |

Severity cards: **4px top accent**, gradient backgrounds, large numeric counts, footer risk badges.

---

## CDN dependencies

When opened in a browser, the file may fetch:

| Resource | Purpose |
|----------|---------|
| Chart.js | Radar and trend charts |
| Inter font | Typography |

Scan data itself never leaves the file. See [SECURITY.md](../../SECURITY.md).

---

## Planned enhancements

| Feature | Phase | GAP |
|---------|-------|-----|
| Interactive attack-graph UI (force-directed) | 2 | GAP-218 |
| Standalone `mcts trend` CLI | 2 | History embedded in HTML today |
| Diff view vs baseline | 2 | `--baseline` snapshots |
| Credential / blast-radius graph pages | 3 | L7-07 |

See [Feature Expansion Plan — Reporting](../more/feature-expansion-plan.md#reporting-10) and [Roadmap](../more/roadmap.md).

---

## Related

- [CLI Reference — `mcts report`](../platform/cli.md#mcts-report)
- [Scoring Specification](scoring-spec.md)
- [Architecture — Reporting](../analysis/architecture.md#reporting)
- [Getting Started](../get-started/getting-started.md)
