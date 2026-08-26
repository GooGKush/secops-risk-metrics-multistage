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
