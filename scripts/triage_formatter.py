"""CommonMark Cyber-First 6-Pillar Structured Triage Report Formatter.

Author: Greg Kushmerek
"""

from typing import Any, Dict, List, Optional


class CommonMarkTriageFormatter:
  """Formats outlier findings into executive markdown triage reports with plain-English impact cards."""

  @staticmethod
  def format_report(
      reduced_data: Dict[str, Any],
      target_metric: str,
      statistical_model: str,
      anomaly_threshold: float,
      executed_query: Optional[str] = None,
      audit_result: Optional[Any] = None,
      sparse_callout: Optional[str] = None,
  ) -> str:
    # 1. Post-Flight Audit Gate Check
    if audit_result is not None and not getattr(audit_result, "is_valid", True):
      violations = "\n".join(f"  • {e}" for e in getattr(audit_result, "errors", []))
      rec_query = getattr(audit_result, "recommended_query", None)
      if rec_query:
        return (
            f"### 🔄 POST-FLIGHT AUDIT: AUTO-CORRECTED CANONICAL QUERY READY\n\n"
            f"> [!WARNING]\n"
            f"> **Execution Audit Detected Non-Compliant Query Construction**:\n"
            f"{violations}\n>\n"
            f"> • **Self-Healing Action**: The pipeline has auto-generated the canonical YARA-L 2.0 multi-stage query below.\n\n"
            f"```yara\n{rec_query}\n```\n\n"
            f"---\n"
            f"**Would you like me to execute this auto-corrected query now, or exit this hunt?**\n"
        )
      else:
        return (
            f"### ❌ POST-FLIGHT EXECUTION AUDIT FAILED\n\n"
            f"> [!CAUTION]\n"
            f"> **Deceptive / Non-Compliant Execution Blocked**:\n"
            f"{violations}\n>\n"
            f"> **Action Taken**: 6-Pillar Triage Report generation was aborted to prevent presenting unverified ad-hoc calculations as 30-day UEBA baselines.\n"
        )

    outliers = reduced_data.get("top_outliers", [])
    total_outliers = reduced_data.get("outlier_count", 0)
    score_key = reduced_data.get("primary_score_metric", "anomaly_score")

    report = [
        f"### ⚡ Statistical Outlier Report: `{target_metric}` ({statistical_model})",
        "",
        "> [!NOTE]",
        "> **📊 Engine: Google SecOps UEBA & Risk Analytics**",
        "> • **Baseline Horizon**: 30-Day Pre-Computed Behavioral Tables (`window: 30d`)",
        "> • **Confidence Tier**: High-Confidence Population Baseline ($N = 30$ daily observations)",
        "",
    ]

    if sparse_callout:
      report.extend([sparse_callout, ""])

    report.extend([
        f"* **Outliers Detected**: **{total_outliers} entities** exceeded the configured threshold (`> {anomaly_threshold}`).",
        f"* **Active Search Window**: 24-Hour Active Evaluation Window (Today's Observations).",
        f"* **Historical Baseline Horizon**: 30-Day Pre-Computed Behavioral Context (`window: 30d`).",
        "",
        "---",
        "",
        "#### 💻 Executed Multi-Stage YARA-L Query",
        "",
        "```yara",
        executed_query or f"// Exact query executed for metric: {target_metric}\n// Model: {statistical_model}",
        "```",
        "",
        "---",
        "",
        "#### 📊 Ranked Outlier Summary (Top Anomalies)",
        "",
    ])

    if "MULTI_SECTOR" in statistical_model.upper():
      report.extend([
          "| Entity Identifier | Auth Anomaly (Z_Auth) | Proc Anomaly (Z_Proc) | Net Anomaly (Z_Net) | Threat Distance (D) | CRI Score (0–100) | Visual Magnitude |",
          "| :---------------- | :-------------------- | :-------------------- | :------------------ | :------------------ | :---------------- | :--------------- |",
      ])
      for record in outliers:
        entity = record.get("entity", "unknown")
        z_auth = record.get("z_auth", 0.0)
        z_proc = record.get("z_proc", 0.0)
        z_net = record.get("z_net", 0.0)
        d_val = record.get("threat_distance", record.get("threat_norm", record.get("anomaly_score", 0.0)))
        cri_val = record.get("cri", record.get("cri_score", 99))
        cri_badge = record.get("cri_badge", "CRITICAL")
        bar = record.get("visual_bar", "████████")
        report.append(f"| `{entity}` | `+{z_auth:.1f}σ` | `+{z_proc:.1f}σ` | `+{z_net:.1f}σ` | `+{d_val:.2f}σ` | **`{cri_val}`** ({cri_badge}) | `{bar}` |")
    else:
      report.extend([
          "| Entity Identifier | 24h Observed | Baseline Mean (30d) | Baseline StdDev | Credibility / Z-Score | CRI Score (0–100) | Visual Magnitude |",
          "| :---------------- | :----------- | :------------------ | :-------------- | :-------------------- | :---------------- | :--------------- |",
      ])
      for record in outliers:
        entity = record.get("entity", "unknown")
        observed = record.get("observed", record.get("observed_val", record.get("observed_24h", "-")))
        hist_avg = record.get("hist_avg", record.get("historical_avg", record.get("avg_30d", "-")))
        hist_std = record.get("hist_stddev", record.get("historical_stddev", record.get("stddev_30d", "-")))
        score_val = record.get(score_key, record.get("z_score", record.get("anomaly_score", "-")))
        cri_val = record.get("cri", record.get("cri_score", 99))
        cri_badge = record.get("cri_badge", "CRITICAL")
        bar = record.get("visual_bar", "████████")
        report.append(f"| `{entity}` | `{observed}` | `{hist_avg}` | `{hist_std}` | `+{score_val}σ` | **`{cri_val}`** ({cri_badge}) | `{bar}` |")

    report.extend([
        "",
        "> [!TIP]",
        "> **🎯 Calibrated Risk Index (CRI, 0–100 Scale) Interpretation Guide** — $S$ denotes this report's score column: a scalar $Z$ for single-metric reports, the multi-sector threat distance $D$ for multi-sector reports. Bands mirror the Chronicle severity ladder applied to ingested findings, so a finding carries the same label here and in its UDM event.",
        "> • **CRI 80–100 (🔴 Critical)**: Coordinated multi-stage breach or extreme statistical surge ($S \\ge 5.3\\sigma$). Trigger immediate containment.",
        "> • **CRI 60–79 (🟠 High)**: Pronounced outlier well past the significance boundary ($3.7\\sigma \\le S < 5.3\\sigma$). Prioritize for Tier-2 SOC investigation.",
        "> • **CRI 40–59 (🟡 Medium)**: Spans the $3.0\\sigma$ significance boundary ($2.3\\sigma \\le S < 3.7\\sigma$; $p < 0.0013$ for a scalar $Z$, $p \\approx 0.0088$ for a clamped 3-sector $D$). Findings at $\\text{CRI} \\ge 50$ are eligible for Clean Hand-Off ingestion.",
        "> • **CRI 20–39 (🔵 Low)**: Behavioral drift below the significance boundary ($0.7\\sigma \\le S < 2.3\\sigma$). Add to observation queue / monitor.",
        "> • **CRI 0–19 (🟢 Informational)**: Routine background enterprise baseline variance ($S < 0.7\\sigma$). Suppress alert.",
        "",
        "---",
        "",
        "#### 🔍 Forensic Vector Breakdown & Impact Analysis",
        "",
        "> [!IMPORTANT]",
        f"> **Threat Translation & Attack Scenarios: {target_metric} ({statistical_model})**",
        f"> * **The Core Finding**: Outliers detected exceeding {anomaly_threshold} significance threshold.",
        "> * **Security Significance**: Volume explosion or multi-vector correlation indicating anomalous breakout.",
        "> * **Potential Attack Scenarios**: Ransomware staging, credential stuffing, data exfiltration, lateral movement.",
        "> * **Legitimate False Positives**: Scheduled backup jobs, administrative bulk updates, patch deployments.",
        "> * **SOC Action Playbook**: 1. Inspect affected entity, 2. Check process tree, 3. Validate egress network destinations.",
        "",
        "---",
        "",
        "#### 🎯 Chronicle UI Manual Pivot (Triage Reference Only)",
        "",
        "> [!NOTE]",
        "> **Manual Chronicle UI Web Pivot** (Copy & paste into Chronicle Search UI for forensic timeline drilldown. Not for agent tool execution):",
        f"> `metadata.event_type = \"USER_LOGIN\" AND principal.user.userid = \"{outliers[0].get('entity', 'target_user') if outliers else 'target_user'}\"`",
        "",
        "---",
        "",
        "#### 🔬 Statistical & Mathematical Appendix (Technical Details)",
        "<details open>",
        "<summary>🔬 <b>Statistical & Mathematical Appendix (Technical Details)</b></summary>",
        "",
        "##### 📐 Mathematical Formulations & Parameter Derivations",
        f"* **Model Formulation**: {statistical_model}",
        "* **Degrees of Freedom ($N$)**: 30 daily observation periods.",
        r"* **Multi-Sector Threat Norm ($D$)**: Euclidean Distance $D = \sqrt{\sum \max(0, Z_i)^2}$ over $K = 3$ sectors. Clamping makes $D$ a rectified norm, not $\chi_3$: null mean $\mathbb{E}[D] \approx 0.97$, with point mass $P(D = 0) = 12.5\%$ when no sector exceeds baseline.",
        r"* **Calibrated Risk Index**: $\text{CRI} = \text{clamp}\left(\text{round}\left(\frac{100}{1 + \exp(-0.6 \cdot (S - 3.0))}\right),\, 0,\, 100\right)$, evaluated on the score column $S$ defined above. Because $S$ is non-negative under clamping, the attainable floor is $\text{CRI} = 14$ at $S = 0$.",
        "</details>",
    ])

    return "\n".join(report)
