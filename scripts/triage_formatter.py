"""CommonMark Cyber-First 6-Pillar Structured Triage Report Formatter.

Author: Greg Kushmerek
"""

from typing import Any, Dict, List, Optional


class CommonMarkTriageFormatter:
  """Formats outlier findings into executive markdown triage reports with plain-English impact cards."""

  OUTCOME_SHAPES = (
      "ACUTE_OUTLIER",
      "CLEAN_OR_SUBTHRESHOLD",
      "FLEET_WAVE",
      "SPARSE_BASELINE",
  )

  @staticmethod
  def classify_hunt_outcome(
      reduced_data: Dict[str, Any],
      anomaly_threshold: float = 3.0,
  ) -> str:
    """Deterministically classifies post-execution hunt results into one of 4 outcome shapes."""
    outliers = reduced_data.get("top_outliers", [])
    total_outliers = reduced_data.get("outlier_count", len(outliers))
    if total_outliers == 0 or not outliers:
      return "CLEAN_OR_SUBTHRESHOLD"

    if reduced_data.get("fleet_wave") is True or total_outliers >= 10 or len(outliers) >= 10:
      return "FLEET_WAVE"

    active_days_vals = []
    for r in outliers:
      for k in ("active_days", "hist_active_days", "historical_active_days", "active_baseline_days"):
        if k in r and r[k] is not None:
          try:
            active_days_vals.append(float(r[k]))
          except (TypeError, ValueError):
            pass
          break
    if active_days_vals and all(days < 7.0 for days in active_days_vals):
      return "SPARSE_BASELINE"

    score_key = reduced_data.get("primary_score_metric", "anomaly_score")
    scores = []
    for r in outliers:
      raw_score = r.get(
          score_key,
          r.get("z_score", r.get("threat_distance", r.get("threat_norm", r.get("anomaly_score", 0.0)))),
      )
      try:
        scores.append(float(raw_score))
      except (TypeError, ValueError):
        pass
    if scores and max(scores) < anomaly_threshold:
      return "CLEAN_OR_SUBTHRESHOLD"

    return "ACUTE_OUTLIER"

  MITRE_KILLCHAIN_PROGRESSION: Dict[str, Dict[str, str]] = {
      "auth": {
          "tactic": "TA0001 Initial Access / TA0006 Credential Access",
          "upstream": "TA0001 Initial Access (`circadian_von_mises_2stage.yl2`)",
          "downstream": "TA0002 Execution (`CREDENTIAL_ACCESS_TO_EXECUTION`) or TA0008 Lateral Movement (`CREDENTIAL_ACCESS_TO_LATERAL_MOVEMENT`)",
      },
      "file_executions": {
          "tactic": "TA0002 Execution",
          "upstream": "TA0006 Credential Access (`CREDENTIAL_ACCESS_TO_EXECUTION`)",
          "downstream": "TA0011 Command and Control (`EXECUTION_TO_C2_DNS`) or TA0010 Exfiltration (`EXECUTION_TO_EXFILTRATION`)",
      },
      "dns": {
          "tactic": "TA0011 Command and Control / TA0010 Exfiltration",
          "upstream": "TA0002 Execution (`EXECUTION_TO_C2_DNS`)",
          "downstream": "TA0010 Exfiltration (`network_bytes_outbound` / `rare_destination_ecg_3stage.yl2`)",
      },
      "http": {
          "tactic": "TA0007 Discovery / TA0011 Command and Control",
          "upstream": "TA0001 Initial Access (`INITIAL_ACCESS_TO_DISCOVERY`)",
          "downstream": "TA0010 Exfiltration (`C2_BEACON_TO_RARE_DESTINATION_EXFIL`)",
      },
      "network": {
          "tactic": "TA0011 Command and Control / TA0010 Exfiltration",
          "upstream": "TA0002 Execution (`EXECUTION_TO_EXFILTRATION`) or TA0005 Defense Evasion (`DEFENSE_EVASION_ALERT_TO_EXFILTRATION`)",
          "downstream": "TA0040 Impact (`resource_deletion_total`) or Rare Destination Filter (`C2_BEACON_TO_RARE_DESTINATION_EXFIL`)",
      },
      "resource": {
          "tactic": "TA0003 Persistence / TA0007 Discovery / TA0040 Impact",
          "upstream": "TA0002 Host Execution (`HOST_EXECUTION_TO_CLOUD_SA_ACCESS`)",
          "downstream": "TA0009 Collection (`CLOUD_DISCOVERY_TO_COLLECTION`)",
      },
      "workspace": {
          "tactic": "TA0009 Collection / TA0010 Exfiltration",
          "upstream": "TA0007 Cloud Discovery (`CLOUD_DISCOVERY_TO_COLLECTION`)",
          "downstream": "TA0010 Host Network Egress (`USER_WORKSPACE_HOARDING_TO_HOST_EGRESS`)",
      },
      "alert": {
          "tactic": "TA0005 Defense Evasion",
          "upstream": "TA0002 Binary Execution (`HOST_ALERT_TO_PROCESS_EXECUTION`)",
          "downstream": "TA0010 Exfiltration (`DEFENSE_EVASION_ALERT_TO_EXFILTRATION`)",
      },
  }

  @classmethod
  def get_mitre_progression(cls, target_metric: str) -> Dict[str, str]:
    """Maps a metric name to its MITRE ATT&CK tactic and upstream/downstream kill-chain progressions."""
    m = (target_metric or "").lower()
    for prefix, spec in cls.MITRE_KILLCHAIN_PROGRESSION.items():
      if prefix in m:
        return spec
    return cls.MITRE_KILLCHAIN_PROGRESSION["network"]

  @classmethod
  def build_agentic_next_steps(
      cls,
      reduced_data: Dict[str, Any],
      target_metric: str,
      statistical_model: str,
      anomaly_threshold: float = 3.0,
  ) -> str:
    """Generates outcome-driven agentic follow-up recommendations for Pillar 4 or Clean Hunt reports."""
    outcome = cls.classify_hunt_outcome(reduced_data, anomaly_threshold)
    outliers = reduced_data.get("top_outliers", [])
    top_entity = outliers[0].get("entity", "target_entity") if outliers else "target_entity"
    mitre = cls.get_mitre_progression(target_metric)

    if outcome == "ACUTE_OUTLIER":
      lines = [
          f"> * **🧭 Agentic Next Steps (Outcome Classification: `{outcome}` — State 3 → Phase 1B Pivot)** (MITRE Tactic: `{mitre['tactic']}`):",
          f">   * **[A] Cross-Sector Fusion / 360° Multi-Sector Sweep**: Pivot `{top_entity}` directly to Phase 1B (`dual_sector_fusion_3stage.yl2`, `rollup_sector_fusion_4stage.yl2`, or Omnidirectional 360° Multi-Sector Sweep) — **Upstream**: {mitre['upstream']} | **Downstream**: {mitre['downstream']} (IAM, Process, Network, Cloud CRUD, or `alert_event_name_count`).",
          f">   * **[B] Two-Phase Chained Entity Pivot (Host ↔ User / Caller IP)**: Carry `{top_entity}` across the entity boundary via `ChainedHuntRouter` (`build_cross_entity_killchain_plan`) without re-running Phase 1A discovery.",
          f">   * **[C] Novelty & Prevalence Verification / Alert Escalation**: Enrich `{top_entity}` with Entity Context Graph (`DERIVED_CONTEXT` file/domain prevalence or `WHOIS` lifecycle) or escalate `CRI >= 50` findings via `scripts/chronicle_ingest.py`.",
      ]
    elif outcome == "FLEET_WAVE":
      lines = [
          f"> * **🧭 Agentic Next Steps (Outcome Classification: `{outcome}` — State 3 → Phase 1B Pivot)** (MITRE Tactic: `{mitre['tactic']}`):",
          f">   * **[A] Suppress Rollout / Patch Wave Noise**: Re-score `{target_metric}` in Phase 1B using `FLEET_PREVALENCE_SHIELD` (`fleet_prevalence_shield.yl2`), `HYBRID_METRIC_FLEET_PREVALENCE_2STAGE`, or `DUAL_BASELINE_3STAGE` (`ΔZ = Z_personal - Z_fleet`).",
          f">   * **[B] Isolate Peer Cohort Departure**: Slice `{top_entity}` against its functional team cohort via `PART_OF_THE_WHOLE_MULTILEVEL` (`part_of_the_whole_multilevel.yl2`).",
          f">   * **[C] Filter by Enterprise Prevalence**: Apply `DERIVED_CONTEXT` rarity gating (`rolling_max <= 3`) to drop fleet-wide binaries or domains.",
      ]
    elif outcome == "SPARSE_BASELINE":
      lines = [
          f"> * **🧭 Agentic Next Steps (Outcome Classification: `{outcome}` — State 3 → Phase 1B Pivot)** (MITRE Tactic: `{mitre['tactic']}`):",
          f">   * **[A] Switch to Sparse-History / Cold-Start Math**: Re-evaluate `{top_entity}` on `{target_metric}` using `TWO_PART_HURDLE` (`two_part_hurdle.yl2`), `POISSON` (`poisson_rarity.yl2`), or `BAYESIAN_GAMMA` (`poisson_gamma_bayesian.yl2`) for $N < 7$ active days.",
          f">   * **[B] Borrow Peer / Fleet Baseline Strength**: Pivot to `EMPIRICAL_BAYES_3STAGE` or `PART_OF_THE_WHOLE_MULTILEVEL` so thin personal history is regularized by the peer cohort.",
          f">   * **[C] Verify Infant Asset / Dormant Account Lifecycle**: Run `HYBRID_METRIC_DERIVED_ASSET_AGE_2STAGE` (`hybrid_metric_derived_asset_age_2stage.yl2`) on `{top_entity}`.",
      ]
    else:
      lines = [
          f"> * **🧭 Agentic Next Steps (Outcome Classification: `{outcome}` — State 3 → Phase 1B Pivot)** (MITRE Tactic: `{mitre['tactic']}`):",
          f">   * **[A] Probe Sub-Threshold Drift / Low-and-Slow Accumulation**: Relax the significance gate to `1.5σ <= Z < {anomaly_threshold}σ` or switch `{target_metric}` to `LONGITUDINAL_CUSUM` (`longitudinal_cusum.yl2`).",
          f">   * **[B] Pivot to Orthogonal MITRE Kill-Chain Vector**: Keep current entity scope and pivot directly to Phase 1B on **Upstream** ({mitre['upstream']}) or **Downstream** ({mitre['downstream']}) (`alert_event_name_count`, `file_executions_total`, `network_bytes_outbound`, or `resource_read_total`).",
          f">   * **[C] Omnidirectional 360° Multi-Sector Sweep**: Run all 6 decoupled sector micro-queries to verify whether `{top_entity}` is nominal across every telemetry plane.",
      ]
    return "\n".join(lines)

  @classmethod
  def format_clean_hunt_report(
      cls,
      target_metric: str,
      statistical_model: str,
      executed_query: str,
      anomaly_threshold: float = 3.0,
      evaluation_mode: str = "Mode A",
  ) -> str:
    """Renders the lightweight 2-pillar Clean Hunt Summary for 0-row outcomes with agentic next steps."""
    next_steps = cls.build_agentic_next_steps(
        {"outlier_count": 0, "top_outliers": []},
        target_metric=target_metric,
        statistical_model=statistical_model,
        anomaly_threshold=anomaly_threshold,
    )
    return "\n".join([
        f"#### 1. Statistical Outlier Report: `{target_metric}` ({statistical_model}) (Nominal Baseline)",
        "",
        f"* **Result**: **0 observed events** (**0 ranked outlier entities**) exceeded the `{anomaly_threshold}σ` significance gate under **{evaluation_mode}** ($Z = 0.00\\sigma, D = 0.00\\sigma, \\text{{CRI}} = 0$, 🟢 **Nominal Fleet Baseline**).",
        "* **Baseline Horizon**: 30-Day Pre-Computed Behavioral Tables (`window: 30d`).",
        "",
        "---",
        "",
        "#### 2. Executed Multi-Stage YARA-L Query",
        "",
        "```yara",
        executed_query,
        "```",
        "",
        "> [!IMPORTANT]",
        next_steps,
    ])

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
        "> **🎯 Calibrated Risk Index (CRI, 0–100 Scale) Interpretation Guide** — $S$ denotes this report's score column: a scalar $Z$ for single-metric reports, the multi-sector threat distance $D$ for multi-sector reports. Bands match the 5 canonical CRI triage bands (`references/calibrated-risk-index-guide.md`) and the Chronicle severity ladder applied to ingested findings:",
        "> • **CRI 90–100 (🚨 Critical Outlier / `CRITICAL`)**: Extreme surge or zero-baseline breakout ($S \\ge 6.7\\sigma$). Trigger immediate incident response escalation.",
        "> • **CRI 70–89 (🔴 High Threat / `HIGH`)**: Severe multi-sigma breakout ($4.4\\sigma \\le S < 6.7\\sigma$). Prioritize for immediate SOC analyst intervention.",
        "> • **CRI 46–69 (🟠 Medium Outlier / `MEDIUM`)**: True statistical anomaly spanning the $3.0\\sigma$ alertable anchor ($2.7\\sigma \\le S < 4.4\\sigma$; $\\text{CRI}(3.0\\sigma) = 50$, $p < 0.0013$ for scalar $Z$). Findings at $\\text{CRI} \\ge 50$ are eligible for Clean Hand-Off ingestion.",
        "> • **CRI 26–45 (🟡 Low Drift / `LOW`)**: Moderate elevation below the significance boundary ($1.2\\sigma \\le S < 2.7\\sigma$). Include in longitudinal CUSUM tracking.",
        "> • **CRI 0–25 (🟢 Nominal / `INFORMATIONAL`)**: Expected day-to-day baseline variance ($S < 1.2\\sigma$). Suppress alert.",
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
        CommonMarkTriageFormatter.build_agentic_next_steps(
            reduced_data, target_metric, statistical_model, anomaly_threshold
        ),
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
