# Strict UI Charting & Visual Specifications for SecOps Risk Metrics

This guide establishes the mandatory visual design patterns, data schemas, and axis-type isolation rules for Risk Metrics threat hunting reports across Vega-Lite, Chart.js, and Generative UI environments.

---

## 1. Strict Axis-Type Isolation Invariants

To avoid rendering errors where categorical strings collide with numeric quantities:
* **Left Y-Axis**: Reserved strictly for linear event volumes (`quantitative` in Vega-Lite / `type: "linear"` in Chart.js).
* **Right Y-Axis ($y_1$)**: Reserved strictly for statistical scores ($Z$-score $\sigma$, Threat Distance $D$, Calibrated Risk Index $\text{CRI}$, Posterior Rate).
* **X-Axis**: Strictly temporal timestamps/dates (`temporal` / `type: "time"`) or categorical entity names (`nominal` / `type: "category"`).
* **Rule**: NEVER place string identifiers (`host`, `user`) on any numeric Y-axis.

---

## 2. Vega-Lite Template: 30-Day Behavioral Baseline Envelope

Visualizes an entity's 30-day baseline envelope (historical mean line with a shaded $\pm 3\sigma$ confidence band) alongside daily observed volumes:

```json
{
  "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
  "description": "30-Day Behavioral Baseline Envelope (Mean ± 3σ)",
  "data": {
    "values": [
      {"date": "2026-08-01", "observed": 12, "baseline_mean": 10.5, "baseline_lower": 4.5, "baseline_upper": 16.5, "z_score": 0.5},
      {"date": "2026-08-26", "observed": 185, "baseline_mean": 10.5, "baseline_lower": 4.5, "baseline_upper": 16.5, "z_score": 15.2}
    ]
  },
  "layer": [
    {
      "mark": {"type": "area", "color": "#1a73e8", "opacity": 0.15},
      "encoding": {
        "x": {"field": "date", "type": "temporal", "title": "Evaluation Date (UTC)"},
        "y": {"field": "baseline_lower", "type": "quantitative", "title": "Event Volume"},
        "y2": {"field": "baseline_upper"}
      }
    },
    {
      "mark": {"type": "line", "color": "#1a73e8", "strokeDash": [4, 4], "strokeWidth": 2},
      "encoding": {
        "x": {"field": "date", "type": "temporal"},
        "y": {"field": "baseline_mean", "type": "quantitative"}
      }
    },
    {
      "mark": {"type": "line", "point": {"filled": true, "size": 60, "color": "#d93025"}, "color": "#d93025", "strokeWidth": 2.5},
      "encoding": {
        "x": {"field": "date", "type": "temporal"},
        "y": {"field": "observed", "type": "quantitative"}
      }
    }
  ]
}
```

---

## 3. Vega-Lite Template: Dual-Y Outlier Volume vs. Threat Score

```json
{
  "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
  "description": "Dual-Y Outlier Hunt (Volume vs Threat Distance / Z-Score)",
  "data": {
    "values": [
      {"entity": "srv-db-01.corp", "observed": 450, "score": 8.4, "cri": 98},
      {"entity": "srv-app-04.corp", "observed": 280, "score": 4.2, "cri": 68}
    ]
  },
  "resolve": {"scale": {"y": "independent"}},
  "layer": [
    {
      "mark": {"type": "bar", "color": "#76c0f8", "opacity": 0.7},
      "encoding": {
        "x": {"field": "entity", "type": "nominal", "title": "Entity Identifier", "sort": "-y"},
        "y": {"field": "observed", "type": "quantitative", "title": "Observed Volume"}
      }
    },
    {
      "mark": {"type": "line", "point": {"filled": true, "size": 75, "color": "#d93025"}, "color": "#d93025", "strokeWidth": 2.5},
      "encoding": {
        "x": {"field": "entity", "type": "nominal", "sort": "-y"},
        "y": {
          "field": "score",
          "type": "quantitative",
          "title": "Anomaly Score (σ / D)",
          "axis": {"orient": "right", "grid": false}
        }
      }
    },
    {
      "mark": {"type": "rule", "color": "#d93025", "strokeDash": [5, 5]},
      "encoding": {
        "y": {"datum": 3.0, "type": "quantitative", "axis": {"orient": "right"}}
      }
    }
  ]
}
```

---

## 4. Visual Rendering Plane, Post-Search Collation & Anti-Simulation Invariant

To guarantee data integrity while supporting rich graphical visualizations and eliminating Markdown DOM sanitizer text-collapse, threat hunting strictly bifurcates execution into two planes:

### A. The Analytical Data Plane (Chronicle Native — Strictly Zero Python Simulation)
* **Single Source of Truth**: All statistical baselining, event counting, 30-day UEBA lookups, and standardized score calculations ($Z_i$) MUST execute natively inside Chronicle SIEM via `udm_search`.
* **Zero Simulation Guarantee**: Python is STRICTLY PROHIBITED from constructing YARA-L queries, fetching raw SIEM logs, computing baselines, or faking detection metrics. Every base metric presented in reports must originate directly from Chronicle.

### B. The Post-Search Collation & Visual Reduction Plane (Sanctioned Repo Scripts Allowed)
* **Post-Search Execution Exemption**: Once verified JSON results are returned from `udm_search`, local Python execution via `run_command` is permitted SOLELY on sanctioned repository scripts (`scripts/radar_collector.py`, `scripts/triage_formatter.py`, `scripts/chart_generator.py`).
* **Post-Search Collation**: When hunts fan out across decoupled micro-queries (due to Chronicle's 4-join limit) or multi-day sliding horizons, sanctioned scripts are authorized to merge the results and compute exact mathematical composite formulas ($D = \sqrt{\sum Z_i^2}$, Calibrated Risk Index $\text{CRI}$, and CUSUM drift) that Chronicle YARA-L cannot compute natively.
* **Anti-Scratch-Script Guardrail**: Writing or executing ad-hoc scratch scripts (`scratch/test.py`) during threat hunts is strictly prohibited.

### C. The Tri-Surface Visual Rendering Contract (Jetski Embed vs. Generic MCP vs. CLI)
To guarantee visual fidelity across diverse frontend clients:

1. **Jetski Environment (`run_command` present)**:
   * **MANDATORY `<agent-embed>` (ZERO DATA-URI / ZERO RAW SVG IN CHAT)**:
     * In Jetski Web UI, the Markdown parser (`rehype-sanitize`) and CSP strictly block raw `<svg>` tags and `data:image/svg+xml;base64` Data-URIs (rendering as broken image placeholders).
     * Therefore, in Jetski, **ALL visual charts** (whether 360° radar, Mode B 14-day timeline, or Mode A distribution) MUST be written to an HTML artifact in `<artifact_dir>/<chart_name>.html` and embedded in Pillar 1 using:
       `<agent-embed src="file:///<artifact_dir>/<chart_name>.html"></agent-embed>`
     * Inside `<agent-embed>`, SVG, HTML, and Tailwind CSS render natively in an isolated sandboxed iframe with zero sanitizer stripping:
       ```html
       <!DOCTYPE html>
       <html>
       <head>
         <meta charset="utf-8">
         <script src="https://www.gstatic.com/antigravity/web/dev/tailwindcss.min.js"></script>
       </head>
       <body class="bg-transparent text-[var(--foreground)] antialiased p-2 flex justify-center">
         <div class="bg-[var(--card)] border border-[var(--border)] rounded-xl p-3 shadow-sm">
           <svg ...>...</svg>
         </div>
       </body>
       </html>
       ```
     * In Pillar 1, output ONLY `<agent-embed src="file:///<artifact_dir>/<chart_name>.html"></agent-embed>` and link `[Open Visual Chart](file:///<artifact_dir>/<chart_name>.html)`. Omit ASCII card.

2. **Generic MCP / Custom Client Environment (no `run_command`)**:
   * **Semantic Client Tool Discovery**: If an active client-side tool declares radar or SVG chart generation, invoke it (Section 6).
   * **Inline SVG**: If no client tool is present and the client's renderer supports inline SVG, emit pure inline `<svg>` directly in markdown.
   * **NEVER emit `data:image/svg+xml;base64`**: Blocked by modern web sanitizers.

3. **Terminal / CLI Fallback (`--format ascii`)**:
   * When operating in a CLI or plain-text environment (or when the analyst explicitly requests `'cli'` or `'ascii'`), output formatted ASCII/Unicode magnitude bars.

---

## 5. Visual Surface Mapping by Hunt Archetype (Pillar 1 Specification)

To prevent cognitive distortion and preserve investigative clarity, the visual surface rendered in **Pillar 1 (Statistical Outlier Report)** must strictly match the hunt archetype:

| Hunt Archetype | Operational Objective | Pillar 1 Visual Surface | Downstream Next Step |
| :--- | :--- | :--- | :--- |
| **Vector / Fleet Outlier Hunt (Mode A: 24h Snapshot)** | Fleet-wide ranking of outliers on a specific behavioral vector (Cloud CRUD, Network Egress, Logins, File Executions). | **Dual-Y Outlier Bar / Distribution Chart**: `<agent-embed>` in Jetski; inline SVG in generic MCP; ASCII table in CLI. | Summarize ranked fleet in Pillar 3. If an entity exhibits extreme novelty ($Z \ge 3.0\sigma$), proactively suggest a 360° deep-dive in Pillar 4. |
| **Vector / Fleet Outlier Hunt (Mode B: 14d Timeline)** | Temporal longitudinal trajectory tracking to determine inception date, burst duration, or gradual CUSUM drift. | **Longitudinal Baseline Envelope & Inception Timeline**: `<agent-embed>` in Jetski; inline SVG in generic MCP; ASCII timeline in CLI. | Analyze onset timing in Pillar 4; suggest 360° cross-sector verification if multi-stage compromise is suspected. |
| **360° Entity Health Check (Explicit Request or Accepted Pivot)** | Multi-vector evaluation of a *single specific entity* across all 5 behavioral sectors to measure aggregate threat distance ($D$). | **360° Behavioral Risk Radar**: Rendered via `scripts/radar_collector.py` as `<agent-embed>` in Jetski; Client visual tool or inline SVG in generic MCP; ASCII radar in CLI. | Recommend host isolation, credential suspension, or SOAR case escalation. |

> [!WARNING]
> **Anti-Conflation Mandate**: NEVER insert a 360° Radar profile or 5-sector table into Pillar 1 of a Vector/Fleet Outlier Hunt. Forcing an entity deep-dive before presenting fleet search results creates cognitive confusion and forces zero-padding on unqueried sectors.

---

## 6. Client-Side Visualization Tool Contract (Generic Endpoint Discovery)

To maintain strict modularity, client-independence, and portability across heterogeneous AI environments (Jetski, custom Gemini/Claude SDK clients, web consoles, and headless automation), skills must never hardcode proprietary client-side function names.

### A. Semantic Tool Discovery Protocol
When rendering **Pillar 1** of a 360° Entity Health Check:
1. **Tool Roster Introspection**: The agent inspects its list of active client tools (`gemini_functions` / tool definitions).
2. **Intent Matching**: If any active tool's name or description declares capability to generate or render radar charts, pentagon risk graphs, or SVG visualizations (e.g. descriptions mentioning *"360-degree behavioral risk pentagon radar"*, *"radar SVG chart"*, or *"render visualization"*):
   * The agent **MUST** delegate visual rendering to that client-side tool rather than attempting manual ASCII or raw XML generation.
3. **Dynamic Schema Binding**:
   * The agent extracts the tool's expected parameter schema.
   * **Entity Binding**: Passes the target identity into the entity argument (e.g. `username`, `entity`, or `user_id`).
   * **Telemetry Scores Binding**: Maps the 5 computed sector Z-scores into the tool's expected dictionary or keyword structure (e.g. `telemetry_data={"Auth": Z1, "Cloud": Z2, "Workspace": Z3, "Egress": Z4, "DNS": Z5}`).
4. **Pillar 1 Output**: The raw SVG or HTML returned by the tool is emitted directly inside Pillar 1. The ASCII fallback card is omitted.

### B. Fallback Hierarchy When No Visualization Tool Exists
If no active tool in the agent's toolset declares visual chart rendering:
1. **Local Shell Execution**: If `run_command` is available (Jetski environment), execute `scripts/radar_collector.py` to write the standalone HTML artifact and render `<agent-embed>`.
2. **Pure Inline SVG**: If running in an MCP environment without local shell or client visual tools, emit pure inline `<svg>` directly into the Markdown stream.
3. **Plaintext / CLI**: Render the ASCII cross-axis card ONLY when the analyst explicitly requests `'cli'` or `'ascii'`.
