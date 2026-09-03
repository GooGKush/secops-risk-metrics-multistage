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

### C. The Dual-Mode Visual Contract (ASCII Universal Baseline + Graphical Layer)
To ensure 100% compatibility across both rich web dashboards and plain-text/ASCII environments (terminals, SOAR case walls, email gateways):
1. **Universal ASCII Baseline (Pillar 3 Table)**:
   * Every report MUST include the CommonMark summary table with the `Visual Magnitude` column populated with Unicode/ASCII progress bars (`▰▰▰▱▱` or `████░░░░`). This guarantees full visual comprehension in 100% of environments.
2. **Graphical Layer (Data-URI Image / SVG)**:
   * In graphical environments, the 360° Radar is rendered as a **Markdown Data-URI Image**:
     ```markdown
     ![360° Behavioral Risk Radar](data:image/svg+xml;base64,<BASE64_ENCODED_SVG>)
     ```
   * **Why Data-URI Image?** Standard chat Markdown renderers (and DOM sanitizers like DOMPurify) frequently strip raw `<svg>` tags and concatenate inner `<text>` elements into an unformatted text wall. Wrapping the SVG inside a standard Markdown image `![alt](data:image/svg+xml;base64,...)` causes the parser to treat it as an `<img>` element, preserving the graphical render and preventing text collapse.
3. **Terminal / CLI Fallback (`--format ascii`)**:
   * When operating in a CLI or plain-text environment, `scripts/radar_collector.py --format ascii` outputs a formatted horizontal ASCII bar chart displaying spoke deviations and thresholds without emitting raw XML:
     ```bash
     python3 scripts/radar_collector.py --entity "frank.kolzig" --data '<JSON_SPOKES>' --format ascii
     ```

---

## 5. Visual Surface Mapping by Hunt Archetype (Pillar 1 Specification)

To prevent cognitive distortion and preserve investigative clarity, the visual surface rendered in **Pillar 1 (Statistical Outlier Report)** must strictly match the hunt archetype:

| Hunt Archetype | Operational Objective | Pillar 1 Visual Surface | Downstream Next Step |
| :--- | :--- | :--- | :--- |
| **Vector / Fleet Outlier Hunt (Mode A: 24h Snapshot)** | Fleet-wide ranking of outliers on a specific behavioral vector (Cloud CRUD, Network Egress, Logins, File Executions). | **Dual-Y Outlier Bar / Distribution Chart**: Horizontal SVG bar chart comparing top entities' observed activity ($k$) against their 30-day baseline mean ($\mu$) with $\pm 3\sigma$ threshold indicators. | Summarize ranked fleet in Pillar 3. If an entity exhibits extreme novelty ($Z \ge 3.0\sigma$), proactively suggest a 360° deep-dive in Pillar 4. |
| **Vector / Fleet Outlier Hunt (Mode B: 14d Timeline)** | Temporal longitudinal trajectory tracking to determine inception date, burst duration, or gradual CUSUM drift. | **Longitudinal Baseline Envelope & Inception Timeline**: Time-series SVG line chart displaying daily observed volume across the 14-day evaluation window against the shaded 30-day historical baseline envelope. | Analyze onset timing in Pillar 4; suggest 360° cross-sector verification if multi-stage compromise is suspected. |
| **360° Entity Health Check (Explicit Request or Accepted Pivot)** | Multi-vector evaluation of a *single specific entity* across all 5 behavioral sectors to measure aggregate threat distance ($D$). | **360° Behavioral Risk Radar**: Rendered via `scripts/radar_collector.py` as an `<agent-embed>` in Jetski or Markdown Data-URI SVG, accompanied by the 5-sector spoke table. | Recommend host isolation, credential suspension, or SOAR case escalation. |

> [!WARNING]
> **Anti-Conflation Mandate**: NEVER insert a 360° Radar profile or 5-sector table into Pillar 1 of a Vector/Fleet Outlier Hunt. Forcing an entity deep-dive before presenting fleet search results creates cognitive confusion and forces zero-padding on unqueried sectors.
