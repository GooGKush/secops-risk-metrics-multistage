"""Chart Generation & UI Visualization for SecOps Risk Metrics.

Author: Greg Kushmerek
Version: 1.0.0
"""

from typing import Any, Dict, List, Optional


class RiskMetricsChartGenerator:
  """Generates strictly-typed Vega-Lite and Chart.js specifications for UEBA Risk Metrics."""

  @staticmethod
  def generate_baseline_envelope_chart(
      timeline_records: List[Dict[str, Any]],
      entity_id: str = "Target Entity",
      metric_name: str = "Event Count",
      threshold_sigma: float = 3.0,
      title: Optional[str] = None,
  ) -> Dict[str, Any]:
    """Generates a 30-Day Behavioral Baseline Envelope chart (Mean ± 3σ band with observed daily points)."""
    if not title:
      title = f"30-Day Behavioral Baseline Envelope: {entity_id} ({metric_name})"

    return {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "title": title,
        "width": 680,
        "height": 340,
        "data": {"values": timeline_records},
        "layer": [
            # 1. Baseline Envelope Area (Mean ± 3σ)
            {
                "mark": {"type": "area", "color": "#1a73e8", "opacity": 0.15},
                "encoding": {
                    "x": {"field": "date", "type": "temporal", "title": "Evaluation Date (UTC)"},
                    "y": {"field": "baseline_lower", "type": "quantitative", "title": f"Volume: {metric_name}"},
                    "y2": {"field": "baseline_upper"},
                },
            },
            # 2. Historical Baseline Mean Line
            {
                "mark": {"type": "line", "color": "#1a73e8", "strokeDash": [4, 4], "strokeWidth": 2},
                "encoding": {
                    "x": {"field": "date", "type": "temporal"},
                    "y": {"field": "baseline_mean", "type": "quantitative"},
                    "tooltip": [
                        {"field": "date", "type": "temporal", "title": "Date"},
                        {"field": "baseline_mean", "type": "quantitative", "title": "30d Baseline Mean"},
                        {"field": "baseline_stddev", "type": "quantitative", "title": "30d StdDev"},
                    ],
                },
            },
            # 3. Daily Observed Volume Points & Line
            {
                "mark": {"type": "line", "point": {"filled": True, "size": 60, "color": "#d93025"}, "color": "#d93025", "strokeWidth": 2.5},
                "encoding": {
                    "x": {"field": "date", "type": "temporal"},
                    "y": {"field": "observed", "type": "quantitative"},
                    "tooltip": [
                        {"field": "date", "type": "temporal", "title": "Date"},
                        {"field": "observed", "type": "quantitative", "title": "Observed Value"},
                        {"field": "z_score", "type": "quantitative", "title": "Daily Z-Score (σ)"},
                    ],
                },
            },
        ],
    }

  @staticmethod
  def generate_dual_y_outlier_chart(
      outlier_records: List[Dict[str, Any]],
      target_metric: str = "metrics.network_bytes_outbound",
      score_field: str = "z_score",
      score_title: str = "Anomaly Score (Z-Score σ)",
      threshold_val: float = 3.0,
      title: Optional[str] = None,
  ) -> Dict[str, Any]:
    """Generates a True Dual-Y Axis chart: Volume (Left Bar) vs Statistical Score (Right Line) across entities."""
    if not title:
      title = f"Ranked Outliers: {target_metric} (Volume vs {score_title})"

    return {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "title": title,
        "width": 680,
        "height": 340,
        "data": {"values": outlier_records},
        "resolve": {"scale": {"y": "independent"}},
        "layer": [
            # Layer 0: Observed Volume Bar (Left Axis)
            {
                "mark": {"type": "bar", "color": "#76c0f8", "opacity": 0.7},
                "encoding": {
                    "x": {"field": "entity", "type": "nominal", "title": "Entity Identifier", "sort": "-y"},
                    "y": {
                        "field": "observed",
                        "type": "quantitative",
                        "axis": {"title": f"Observed Volume ({target_metric})", "titleColor": "#1a73e8"},
                    },
                    "tooltip": [
                        {"field": "entity", "type": "nominal", "title": "Entity"},
                        {"field": "observed", "type": "quantitative", "title": "Observed"},
                        {"field": "baseline_mean", "type": "quantitative", "title": "30d Baseline Mean"},
                    ],
                },
            },
            # Layer 1: Statistical Anomaly Score Line (Right Axis)
            {
                "mark": {"type": "line", "point": {"filled": True, "size": 75, "color": "#d93025"}, "color": "#d93025", "strokeWidth": 2.5},
                "encoding": {
                    "x": {"field": "entity", "type": "nominal", "sort": "-y"},
                    "y": {
                        "field": score_field,
                        "type": "quantitative",
                        "axis": {
                            "title": score_title,
                            "orient": "right",
                            "titleColor": "#d93025",
                            "grid": False,
                        },
                    },
                    "tooltip": [
                        {"field": "entity", "type": "nominal", "title": "Entity"},
                        {"field": score_field, "type": "quantitative", "title": score_title},
                        {"field": "cri", "type": "quantitative", "title": "Calibrated Risk Index (CRI)"},
                    ],
                },
            },
            # Layer 2: Significance Threshold Reference Rule (Right Axis)
            {
                "mark": {"type": "rule", "color": "#d93025", "strokeDash": [5, 5], "strokeWidth": 1.5},
                "encoding": {
                    "y": {
                        "datum": threshold_val,
                        "type": "quantitative",
                        "axis": {"orient": "right"},
                    },
                },
            },
        ],
    }

  @staticmethod
  def generate_chartjs_dual_y(
      outlier_records: List[Dict[str, Any]],
      target_metric: str = "metrics.auth_attempts_fail",
      score_field: str = "z_score",
      threshold_val: float = 3.0,
  ) -> Dict[str, Any]:
    """Generates Chart.js configuration with isolated linear axes."""
    labels = [r.get("entity", "unknown") for r in outlier_records]
    volumes = [r.get("observed", 0) for r in outlier_records]
    scores = [r.get(score_field, 0.0) for r in outlier_records]

    return {
        "type": "bar",
        "data": {
            "labels": labels,
            "datasets": [
                {
                    "type": "bar",
                    "label": f"24h Observed Volume ({target_metric})",
                    "data": volumes,
                    "yAxisID": "y",
                    "backgroundColor": "rgba(118, 192, 248, 0.65)",
                    "borderColor": "rgba(26, 115, 232, 1.0)",
                    "borderWidth": 1,
                },
                {
                    "type": "line",
                    "label": "Statistical Score (σ / D)",
                    "data": scores,
                    "yAxisID": "y1",
                    "borderColor": "rgba(217, 48, 37, 1.0)",
                    "backgroundColor": "rgba(217, 48, 37, 0.2)",
                    "pointRadius": 6,
                    "tension": 0.1,
                },
            ],
        },
        "options": {
            "responsive": True,
            "scales": {
                "x": {"title": {"display": True, "text": "Entity Identifier"}},
                "y": {
                    "type": "linear",
                    "position": "left",
                    "title": {"display": True, "text": "Event Volume"},
                },
                "y1": {
                    "type": "linear",
                    "position": "right",
                    "grid": {"drawOnChartArea": False},
                    "title": {"display": True, "text": "Statistical Score (Z-Score / D)"},
                },
            },
        },
    }

  @staticmethod
  def generate_mermaid_timeline_chart(
      dates: List[str],
      series_data: Dict[str, List[float]],
      title: str = "14-Day Longitudinal Threat Scores Timeline",
      max_y: float = 8.0,
  ) -> str:
    """Generates a Mermaid xychart-beta block for native markdown rendering."""
    formatted_dates = [f'"{d}"' for d in dates]
    date_str = ", ".join(formatted_dates)

    chart_lines = [
        "```mermaid",
        "xychart-beta",
        f'    title "{title}"',
        f"    x-axis [{date_str}]",
        f'    y-axis "Threat Score (Sigma / D)" 0 --> {max_y:.1f}',
    ]

    for label, points in series_data.items():
      formatted_points = [f"{p:.2f}" for p in points]
      chart_lines.append(f"    line [{', '.join(formatted_points)}]")

    chart_lines.append("```")
    return "\n".join(chart_lines)

