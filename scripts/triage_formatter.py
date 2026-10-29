"""CommonMark Cyber-First 6-Pillar Structured Triage Report Formatter.

Author: Greg Kushmerek
"""

from typing import Any, Dict, List, Optional

try:
  from .ueba_constants import (
      _coerce_finite_float,
      calculate_cri,
      coerce_cri_int,
      cri_from_model_score,
      format_cri,
      format_score_with_unit,
      get_cri_band_metadata,
      is_inverted_score_key,
      is_true_sigma_key,
      score_to_z_equivalent,
  )
except ImportError:
  try:
    from scripts.ueba_constants import (
        _coerce_finite_float,
        calculate_cri,
        coerce_cri_int,
        cri_from_model_score,
        format_cri,
        format_score_with_unit,
        get_cri_band_metadata,
        is_inverted_score_key,
        is_true_sigma_key,
        score_to_z_equivalent,
    )
  except ImportError:
    from ueba_constants import (  # type: ignore[no-redef]
        _coerce_finite_float,
        calculate_cri,
        coerce_cri_int,
        cri_from_model_score,
        format_cri,
        format_score_with_unit,
        get_cri_band_metadata,
        is_inverted_score_key,
        is_true_sigma_key,
        score_to_z_equivalent,
    )


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
    if isinstance(reduced_data, list):
      reduced_data = {"top_outliers": reduced_data}
    outliers = reduced_data.get("top_outliers", [])
    total_outliers = reduced_data.get("outlier_count", len(outliers))
    if total_outliers == 0 or not outliers:
      return "CLEAN_OR_SUBTHRESHOLD"

    score_key = reduced_data.get("primary_score_metric", "anomaly_score")
    scores = []
    for r in outliers:
      raw_score = r.get(
          score_key,
          r.get("z_score", r.get("threat_distance", r.get("threat_norm", r.get("anomaly_score", 0.0)))),
      )
      parsed = _coerce_finite_float(raw_score)
      if parsed is not None:
        scores.append(parsed)
    if is_inverted_score_key(score_key):
      if anomaly_threshold >= 1.0 and score_key == "cv":
        z_eqs = [z for s in scores if (z := score_to_z_equivalent(score_key, s)) is not None]
        if z_eqs and max(z_eqs) < anomaly_threshold:
          return "CLEAN_OR_SUBTHRESHOLD"
        qualifying_count = sum(1 for z in z_eqs if z >= anomaly_threshold) if z_eqs else len(outliers)
      else:
        if scores and min(scores) > anomaly_threshold:
          return "CLEAN_OR_SUBTHRESHOLD"
        qualifying_count = sum(1 for s in scores if s <= anomaly_threshold) if scores else len(outliers)
    else:
      if scores and max(scores) < anomaly_threshold:
        return "CLEAN_OR_SUBTHRESHOLD"
      qualifying_count = sum(1 for s in scores if s >= anomaly_threshold) if scores else len(outliers)
    if reduced_data.get("fleet_wave") is True or qualifying_count >= 10:
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
      "recon": {
          "tactic": "TA0043 Reconnaissance",
          "upstream": "External Enumeration (`http_error_ratio_surge_2stage.yl2`)",
          "downstream": "TA0001 Initial Access (`RECON_ENUMERATION_TO_INITIAL_ACCESS`)",
      },
      "resource_dev": {
          "tactic": "TA0042 Resource Development",
          "upstream": "TA0043 Reconnaissance (`http_queries_fail`)",
          "downstream": "TA0011 Command and Control (`RESOURCE_DEV_NRD_TO_C2_EGRESS`)",
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
    outcome = (
        reduced_data.get("outcome_override")
        if isinstance(reduced_data, dict) and reduced_data.get("outcome_override")
        else cls.classify_hunt_outcome(reduced_data, anomaly_threshold)
    )
    if isinstance(reduced_data, list):
      reduced_data = {"top_outliers": reduced_data}
    outliers = reduced_data.get("top_outliers", [])
    top_entity = outliers[0].get("entity", "target_entity") if outliers else "target_entity"
    mitre = cls.get_mitre_progression(target_metric)

    if outcome == "ACUTE_OUTLIER":
      lines = [
          f"> * **🧭 Agentic Next Steps (Outcome Classification: `{outcome}` — State 3 → Phase 1B Pivot)** (MITRE Tactic: `{mitre['tactic']}`):",
          f">   * **[1] Cross-Sector Fusion / 360° Multi-Sector Sweep**: Pivot `{top_entity}` directly to Phase 1B (`dual_sector_fusion_3stage.yl2`, `rollup_sector_fusion_4stage.yl2`, or Omnidirectional 360° Multi-Sector Sweep) — **Upstream**: {mitre['upstream']} | **Downstream**: {mitre['downstream']} (IAM, Process, Network, Cloud CRUD, or `alert_event_name_count`).",
          f">   * **[2] Two-Phase Chained Entity Pivot (Host ↔ User / Caller IP)**: Carry `{top_entity}` across the entity boundary via `ChainedHuntRouter` (`build_cross_entity_killchain_plan`) without re-running Phase 1A discovery.",
          f">   * **[3] Novelty & Prevalence Verification / Alert Escalation**: Enrich `{top_entity}` with Entity Context Graph (`DERIVED_CONTEXT` file/domain prevalence or `WHOIS` lifecycle) or escalate `CRI >= 50` findings via `scripts/chronicle_ingest.py`.",
      ]
    elif outcome == "FLEET_WAVE":
      lines = [
          f"> * **🧭 Agentic Next Steps (Outcome Classification: `{outcome}` — State 3 → Phase 1B Pivot)** (MITRE Tactic: `{mitre['tactic']}`):",
          f">   * **[1] Suppress Rollout / Patch Wave Noise**: Re-score `{target_metric}` in Phase 1B using `FLEET_PREVALENCE_SHIELD` (`fleet_prevalence_shield.yl2`), `HYBRID_METRIC_FLEET_PREVALENCE_2STAGE`, or `DUAL_BASELINE_3STAGE` (`ΔZ = Z_personal - Z_fleet`).",
          f">   * **[2] Isolate Peer Cohort Departure**: Slice `{top_entity}` against its functional team cohort via `PART_OF_THE_WHOLE_MULTILEVEL` (`part_of_the_whole_multilevel.yl2`).",
          f">   * **[3] Filter by Enterprise Prevalence**: Apply `DERIVED_CONTEXT` rarity gating (`rolling_max <= 3`) to drop fleet-wide binaries or domains.",
      ]
    elif outcome == "SPARSE_BASELINE":
      lines = [
          f"> * **🧭 Agentic Next Steps (Outcome Classification: `{outcome}` — State 3 → Phase 1B Pivot)** (MITRE Tactic: `{mitre['tactic']}`):",
          f">   * **[1] Route Immature Entities ($N < 7$ Active Days) to Hurdle or Novelty**: Re-evaluate `{top_entity}` on `{target_metric}` using `TWO_PART_HURDLE` (`two_part_hurdle.yl2`), `metrics.*` `first_seen` novelty (`PF-11` / `WS1-12`), `POISSON` (`poisson_rarity.yl2`), or `BAYESIAN_GAMMA` (`poisson_gamma_bayesian.yl2`) — never parametric Z.",
          f">   * **[2] Borrow Peer / Fleet Baseline Strength**: Pivot to `EMPIRICAL_BAYES_3STAGE` or `PART_OF_THE_WHOLE_MULTILEVEL` so thin personal history is regularized by the peer cohort.",
          f">   * **[3] Verify Infant Asset / Dormant Account Lifecycle**: Check `metrics.*` `first_seen` / `last_seen` timestamps or run `HYBRID_METRIC_DERIVED_ASSET_AGE_2STAGE` (`hybrid_metric_derived_asset_age_2stage.yl2`) on `{top_entity}`.",
      ]
    else:
      lines = [
          f"> * **🧭 Agentic Next Steps (Outcome Classification: `{outcome}` — State 3 → Phase 1B Pivot)** (MITRE Tactic: `{mitre['tactic']}`):",
          f">   * **[1] Probe Sub-Threshold Drift / Low-and-Slow Accumulation**: Relax the significance gate to `1.5σ <= Z < {anomaly_threshold}σ` or switch `{target_metric}` to `LONGITUDINAL_CUSUM` (`longitudinal_cusum.yl2`).",
          f">   * **[2] Pivot to Orthogonal MITRE Kill-Chain Vector**: Keep current entity scope and pivot directly to Phase 1B on **Upstream** ({mitre['upstream']}) or **Downstream** ({mitre['downstream']}) (`alert_event_name_count`, `file_executions_total`, `network_bytes_outbound`, or `resource_read_total`).",
          f">   * **[3] Omnidirectional 360° Multi-Sector Sweep**: Run all 6 decoupled sector micro-queries to verify whether `{top_entity}` is nominal across every telemetry plane.",
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
      ecg_join_filter_disclosure: Optional[str] = None,
      cohort_cap_warning: Optional[str] = None,
      mode_c_fade_caveat: Optional[str] = None,
  ) -> str:
    """Renders the lightweight 2-pillar Clean Hunt Summary for 0-row outcomes with agentic next steps."""
    next_steps = cls.build_agentic_next_steps(
        {"outlier_count": 0, "top_outliers": []},
        target_metric=target_metric,
        statistical_model=statistical_model,
        anomaly_threshold=anomaly_threshold,
    )
    has_ecg = bool(
        executed_query
        and any(tok in executed_query for tok in ("graph.entity", "graph.metadata", "graph.relations"))
    )
    eff_ecg_disclosure = ecg_join_filter_disclosure or (
        "Entity Context Graph stages execute as an inner join (active filter): entities, hashes, domains, or IPs "
        "with no matching graph record drop out silently (absent from the graph != benign or common; run the Day-0 "
        "companion query without graph.* for newly observed Day-0 artifacts)."
        if has_ecg
        else None
    )
    lines = [
        f"#### 1. Statistical Outlier Report: `{target_metric}` ({statistical_model}) (Nominal Baseline)",
        "",
        f"* **Result**: **0 observed events** (**0 ranked outlier entities**) exceeded the `{anomaly_threshold}σ` significance gate under **{evaluation_mode}** ($Z = 0.00\\sigma, D = 0.00\\sigma, \\text{{CRI}} = 0$, 🟢 **Nominal Fleet Baseline**).",
        "* **Baseline Horizon**: 30-Day Pre-Computed Behavioral Tables (`window: 30d`).",
    ]
    if eff_ecg_disclosure:
      lines.append(f"* **ECG Inner-Join Filter Disclosure**: {eff_ecg_disclosure}")
    if cohort_cap_warning:
      lines.append(f"* **Samuelson Small-Cohort Cap (PF-2 / WS1-09)**: {cohort_cap_warning}")
    if mode_c_fade_caveat:
      lines.append(f"* **Sustained-Attack Fade Caveat (D10 / WS1-11)**: {mode_c_fade_caveat}")
    lines.extend([
        "",
        "> [!IMPORTANT]",
        next_steps,
    ])
    return "\n".join(lines)

  @staticmethod
  def format_report(
      reduced_data: Dict[str, Any],
      target_metric: str,
      statistical_model: str,
      anomaly_threshold: float,
      executed_query: Optional[str] = None,
      audit_result: Optional[Any] = None,
      sparse_callout: Optional[str] = None,
      ecg_join_filter_disclosure: Optional[str] = None,
      ecg_novelty_notice: Optional[str] = None,
      cohort_cap_warning: Optional[str] = None,
      mode_c_fade_caveat: Optional[str] = None,
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

    if isinstance(reduced_data, list):
      reduced_data = {"top_outliers": reduced_data}
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

    has_ecg = bool(
        executed_query
        and any(tok in executed_query for tok in ("graph.entity", "graph.metadata", "graph.relations"))
    )
    eff_ecg_disclosure = ecg_join_filter_disclosure or (
        "Entity Context Graph stages execute as an inner join (active filter): entities, hashes, domains, or IPs "
        "with no matching graph record drop out silently (absent from the graph != benign or common; run the Day-0 "
        "companion query without graph.* for newly observed Day-0 artifacts)."
        if has_ecg
        else None
    )
    if eff_ecg_disclosure:
      report.extend([
          "> [!NOTE]",
          f"> **🔗 ECG Inner-Join Filter Disclosure (PF-8 / WS1-08)**: {eff_ecg_disclosure}",
          "",
      ])
    if ecg_novelty_notice:
      report.extend([
          "> [!WARNING]",
          f"> **⚠️ ECG Novelty Notice (PF-8 / WS1-08)**: {ecg_novelty_notice}",
          "",
      ])
    if cohort_cap_warning:
      report.extend([
          "> [!WARNING]",
          f"> **⚠️ Samuelson Small-Cohort Cap (PF-2 / WS1-09)**: {cohort_cap_warning}",
          "",
      ])

    report.extend([
        f"* **Outliers Detected**: **{total_outliers} entities** exceeded the configured threshold (`> {anomaly_threshold}`).",
        f"* **Active Search Window**: 24-Hour Active Evaluation Window (Today's Observations).",
        f"* **Historical Baseline Horizon**: 30-Day Pre-Computed Behavioral Context (`window: 30d`).",
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
        z_auth = float(record.get("z_auth", 0.0))
        z_proc = float(record.get("z_proc", 0.0))
        z_net = float(record.get("z_net", 0.0))
        raw_d = record.get("threat_distance", record.get("threat_norm", record.get("anomaly_score")))
        d_num = _coerce_finite_float(raw_d)
        explicit_cri = coerce_cri_int(record.get("cri", record.get("cri_score")))
        cri_int = explicit_cri if explicit_cri is not None else cri_from_model_score("threat_distance", d_num)
        default_badge, _, default_bar = get_cri_band_metadata(cri_int)
        cri_cell = format_cri(cri_int)
        cri_badge = record.get("cri_badge", default_badge)
        bar = record.get("visual_bar", default_bar)
        d_cell = format_score_with_unit("threat_distance", d_num)
        report.append(f"| `{entity}` | `{z_auth:+.1f}σ` | `{z_proc:+.1f}σ` | `{z_net:+.1f}σ` | `{d_cell}` | **`{cri_cell}`** ({cri_badge}) | `{bar}` |")
    else:
      score_col_label = "Credibility / Z-Score" if is_true_sigma_key(score_key) else "Model Score"
      report.extend([
          f"| Entity Identifier | 24h Observed | Baseline Mean (30d) | Baseline StdDev | {score_col_label} | CRI Score (0–100) | Visual Magnitude |",
          "| :---------------- | :----------- | :------------------ | :-------------- | :-------------------- | :---------------- | :--------------- |",
      ])
      for record in outliers:
        entity = record.get("entity", "unknown")
        observed = record.get("observed", record.get("observed_val", record.get("observed_24h", "-")))
        hist_avg = record.get("hist_avg", record.get("historical_avg", record.get("avg_30d", "-")))
        hist_std = record.get("hist_stddev", record.get("historical_stddev", record.get("stddev_30d", "-")))
        if score_key in record:
          eff_key = score_key
          score_val = record[score_key]
        elif "z_score" in record:
          eff_key = "z_score"
          score_val = record["z_score"]
        else:
          eff_key = record.get("score_key") or "anomaly_score"
          score_val = record.get("anomaly_score", "-")
        score_num = _coerce_finite_float(score_val)
        explicit_cri = coerce_cri_int(record.get("cri", record.get("cri_score")))
        cri_int = explicit_cri if explicit_cri is not None else cri_from_model_score(eff_key, score_num)
        default_badge, _, default_bar = get_cri_band_metadata(cri_int)
        cri_cell = format_cri(cri_int)
        cri_badge = record.get("cri_badge", default_badge)
        bar = record.get("visual_bar", default_bar)
        score_cell = record.get("score_display") if (record.get("score_display") and score_num is not None and score_key not in record) else format_score_with_unit(eff_key, score_num)
        report.append(f"| `{entity}` | `{observed}` | `{hist_avg}` | `{hist_std}` | `{score_cell}` | **`{cri_cell}`** ({cri_badge}) | `{bar}` |")

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
        *(
            [f"> * **Sustained-Attack Fade Caveat (D10 / WS1-11)**: {mode_c_fade_caveat}"]
            if mode_c_fade_caveat
            else []
        ),
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
        r"* **Calibrated Risk Index**: For $S > 0$, $\text{CRI} = \text{clamp}\left(\text{round}\left(\frac{100}{1 + \exp(-0.6 \cdot (S - 3.0))}\right),\, 0,\, 100\right)$; for $S \le 0$, $\text{CRI} = 0$ (nominal zero floor); missing or non-finite scores report `N/A`.",
        "</details>",
    ])

    return "\n".join(report)

classify_hunt_outcome = CommonMarkTriageFormatter.classify_hunt_outcome
