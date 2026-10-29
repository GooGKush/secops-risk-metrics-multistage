# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Comprehensive unit tests for the Unified Python Hybrid Engine (scripts/ueba_hybrid_engine.py)."""

import datetime
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.federated_handoff import SUPPORTED_INTENTS, SUPPORTED_PROTOCOL
from scripts.preflight_validator import (
    EntityType,
    KillChainArchetype,
    METRIC_CATALOG,
    PipelineArchitecture,
    StatisticalModel,
)
from scripts.template_router import ChainedHuntRouter
from scripts.ueba_hybrid_engine import (
    UEBAHybridEngine,
    compile_hunt_pipeline,
    dispatch_hybrid_handoff,
    get_metric_catalog_summary,
    main as cli_main,
    render_forensic_dossier,
)


class TestUEBAHybridEngineCompile(unittest.TestCase):
  """Tests compile_hunt_pipeline across models, metrics, architectures, planes, and modes."""

  def test_compile_all_17_statistical_models_ast_valid(self):
    """Every StatisticalModel enum value must compile cleanly with 0 AST or statistical errors."""
    for model in StatisticalModel:
      res = compile_hunt_pipeline(
          statistical_model=model.value,
          metrics="network_bytes_outbound",
          entity_type="ASSET",
          mode="A",
      )
      self.assertEqual(res["status"], "COMPILED", f"Failed for {model}: {res['ast_errors']}")
      self.assertTrue(res["ast_valid"], f"AST errors for {model}: {res['ast_errors']}")
      self.assertEqual(res["ast_errors"], [])
      self.assertEqual(res["statistical_violations"], [])
      self.assertIn("PRE-FLIGHT HUNTING SPECIFICATION", res["preflight_card"])
      self.assertIn("```yara", res["preflight_card_markdown"])

  def test_compile_shorthand_model_aliases(self):
    """Shorthand model names (zscore, mad, fano, poisson, cv, cusum, hurdle, cri, macd, circadian) must resolve."""
    aliases = [
        ("zscore", StatisticalModel.STANDARD_Z_SCORE.value),
        ("mad", StatisticalModel.MAD.value),
        ("fold_change", StatisticalModel.RELATIVE_DEVIATION.value),
        ("fano", StatisticalModel.VARIANCE.value),
        ("poisson", StatisticalModel.POISSON.value),
        ("cv", StatisticalModel.COEFFICIENT_OF_VARIATION.value),
        ("hourly_zscore", StatisticalModel.HOURLY_TEMPORAL_ZSCORE.value),
        ("bayesian_gamma", StatisticalModel.BAYESIAN_GAMMA.value),
        ("beta_binomial", StatisticalModel.BAYESIAN_BETA_BINOMIAL.value),
        ("cusum", StatisticalModel.LONGITUDINAL_CUSUM.value),
        ("hurdle", StatisticalModel.TWO_PART_HURDLE.value),
        ("asymmetric_z", StatisticalModel.ASYMMETRIC_DIRECTIONAL_Z.value),
        ("cri", StatisticalModel.PIECEWISE_CRI.value),
        ("patch_tuesday_shield", StatisticalModel.FLEET_PREVALENCE_SHIELD.value),
        ("adaptive_threshold", StatisticalModel.ADAPTIVE_CONTEXT_THRESHOLD.value),
        ("macd", StatisticalModel.MACD_MOMENTUM_VELOCITY.value),
        ("circadian", StatisticalModel.CIRCADIAN_VON_MISES.value),
    ]
    for alias, expected_model in aliases:
      res = compile_hunt_pipeline(
          statistical_model=alias,
          metrics="auth_attempts_total",
          entity_type="USER",
      )
      self.assertEqual(res["statistical_model"], expected_model)
      self.assertTrue(res["ast_valid"], f"Alias {alias} failed AST: {res['ast_errors']}")

  def test_ws2_05_silence_and_dropout_aliases_raise_not_supported(self):
    """WS2-05: SILENCE_DETECTION, DROP_OUT, SILENCE, and DROPOUT must raise 'not supported' instead of upper-tail Z."""
    from scripts import ueba_hybrid_engine as engine_mod
    from scripts.ueba_hybrid_engine import resolve_statistical_model

    for alias in ("SILENCE_DETECTION", "DROP_OUT", "SILENCE", "DROPOUT", "silence_detection", "drop-out"):
      with self.subTest(alias=alias, fn="resolve_statistical_model"):
        with self.assertRaises(ValueError) as ctx:
          resolve_statistical_model(alias)
        self.assertIn("not supported", str(ctx.exception).lower())

      with self.subTest(alias=alias, fn="compile_hunt_pipeline"):
        with self.assertRaises(ValueError) as ctx_compile:
          compile_hunt_pipeline(
              statistical_model=alias,
              metrics="auth_attempts_total",
              entity_type="USER",
          )
        self.assertIn("not supported", str(ctx_compile.exception).lower())

    compile_plan_fn = getattr(engine_mod, "compile_hunt_plan", None)
    self.assertIsNotNone(compile_plan_fn, "compile_hunt_plan alias must be exported")
    with self.assertRaises(ValueError) as ctx_plan:
      compile_plan_fn(statistical_model="SILENCE_DETECTION", metrics="auth_attempts_total", entity_type="USER")
    self.assertIn("not supported", str(ctx_plan.exception).lower())

  def test_ws2_05_jitter_and_beacon_aliases_handoff_to_statistical_hunter(self):
    """WS2-05: JITTER / BEACON_REGULARITY hand off to secops-statistical-hunter C2_BEACONING_JITTER (never daily CV)."""
    from scripts import ueba_hybrid_engine as engine_mod
    from scripts.ueba_hybrid_engine import resolve_statistical_model

    for alias in ("JITTER", "BEACON_REGULARITY", "BEACON", "C2_BEACONING_JITTER", "C2_JITTER", "jitter", "beacon-regularity"):
      with self.subTest(alias=alias, fn="resolve_statistical_model"):
        with self.assertRaises(ValueError) as ctx:
          resolve_statistical_model(alias)
        self.assertIn("secops-statistical-hunter", str(ctx.exception))
        self.assertIn("C2_BEACONING_JITTER", str(ctx.exception))

      with self.subTest(alias=alias, fn="compile_hunt_pipeline"):
        res = compile_hunt_pipeline(
            statistical_model=alias,
            metrics="network_flows_outbound",
            entity_type="ASSET",
            entity_value="wkst-c2-01",
        )
        self.assertEqual(res["status"], "HANDOFF_REQUIRED")
        self.assertEqual(res["target_skill"], "secops-statistical-hunter")
        self.assertEqual(res["model_routed"], "C2_BEACONING_JITTER")
        self.assertEqual(res["compiled_query"], "")
        self.assertNotIn("COEFFICIENT_OF_VARIATION", res.get("statistical_model", ""))
        self.assertIn("```json:secops-threat-hunt-handoff-v1", res["handoff_card"])
        self.assertNotIn("```yara", res["handoff_card"])
        self.assertEqual(res["handoff_payload"]["target_skill"], "secops-statistical-hunter")
        self.assertEqual(res["handoff_payload"]["intent"], "C2_BEACONING_JITTER")
        self.assertEqual(res["handoff_payload"]["target_entity"]["value"], "wkst-c2-01")

    # Also verify MICRO_RAW plane does not silently render local jitter CV when JITTER/BEACON is passed
    res_micro = compile_hunt_pipeline(
        statistical_model="JITTER",
        plane="MICRO_RAW",
        entity_type="ASSET",
        entity_value="proxy-edge-01",
    )
    self.assertEqual(res_micro["status"], "HANDOFF_REQUIRED")
    self.assertEqual(res_micro["target_skill"], "secops-statistical-hunter")
    self.assertEqual(res_micro["model_routed"], "C2_BEACONING_JITTER")

    compile_plan_fn = getattr(engine_mod, "compile_hunt_plan", None)
    self.assertIsNotNone(compile_plan_fn, "compile_hunt_plan alias must be exported")
    res_plan = compile_plan_fn(statistical_model="BEACON_REGULARITY", entity_type="ASSET", entity_value="srv-01")
    self.assertEqual(res_plan["status"], "HANDOFF_REQUIRED")
    self.assertEqual(res_plan["model_routed"], "C2_BEACONING_JITTER")

  def test_ws2_06_unknown_and_retired_models_raise_value_error(self):
    """WS2-06: Unknown models raise ValueError (no silent STANDARD_Z_SCORE fallback); retired aliases raise clear error."""
    from scripts import ueba_hybrid_engine as engine_mod
    from scripts.ueba_hybrid_engine import resolve_statistical_model

    # Empty / None still defaults cleanly to STANDARD_Z_SCORE
    self.assertEqual(resolve_statistical_model(None), StatisticalModel.STANDARD_Z_SCORE)  # type: ignore[arg-type]
    self.assertEqual(resolve_statistical_model(""), StatisticalModel.STANDARD_Z_SCORE)
    self.assertEqual(resolve_statistical_model("   "), StatisticalModel.STANDARD_Z_SCORE)

    # Quantile aliases resolve cleanly
    for q_alias in ("QUANTILE_IQR_SKEW", "bowley_skew", "tukey_fence", "tukey_skew_fence"):
      self.assertEqual(resolve_statistical_model(q_alias), StatisticalModel.QUANTILE_IQR_SKEW)

    # Unknown model strings raise ValueError everywhere
    for bad_model in ("MADE_UP_MODEL", "BOGUS_Z", "NOT_A_MODEL", "UNKNOWN_ALGO"):
      with self.subTest(bad_model=bad_model, fn="resolve_statistical_model"):
        with self.assertRaises(ValueError) as ctx:
          resolve_statistical_model(bad_model)
        self.assertIn("Unknown statistical model", str(ctx.exception))
        self.assertIn(bad_model, str(ctx.exception))

      with self.subTest(bad_model=bad_model, fn="compile_hunt_plan"):
        with self.assertRaises(ValueError) as ctx_plan:
          engine_mod.compile_hunt_plan(
              statistical_model=bad_model,
              metrics="auth_attempts_total",
              entity_type="USER",
          )
        self.assertIn("Unknown statistical model", str(ctx_plan.exception))

      with self.subTest(bad_model=bad_model, fn="compile_hunt_plan_micro_raw"):
        with self.assertRaises(ValueError):
          engine_mod.compile_hunt_plan(
              statistical_model=bad_model,
              plane="MICRO_RAW",
              entity_type="ASSET",
          )

      with self.subTest(bad_model=bad_model, fn="render_forensic_dossier"):
        with self.assertRaises(ValueError):
          render_forensic_dossier(
              rows=[],
              executed_query="",
              statistical_model=bad_model,
              skip_postflight_audit=True,
          )

    # Retired model registry raises clear "is retired; use <replacement>." error
    self.assertTrue(hasattr(engine_mod, "RETIRED_MODEL_ALIASES"))
    self.assertIsInstance(engine_mod.RETIRED_MODEL_ALIASES, dict)
    with patch.dict(engine_mod.RETIRED_MODEL_ALIASES, {"LEGACY_TEST_MODEL": "STANDARD_Z_SCORE"}, clear=False):
      with self.assertRaises(ValueError) as ctx_ret:
        resolve_statistical_model("legacy-test-model")
      self.assertEqual(
          str(ctx_ret.exception),
          "Statistical model 'LEGACY_TEST_MODEL' is retired; use STANDARD_Z_SCORE.",
      )
      with self.assertRaises(ValueError) as ctx_ret_plan:
        engine_mod.compile_hunt_plan(statistical_model="LEGACY_TEST_MODEL", entity_type="USER")
      self.assertIn("is retired; use STANDARD_Z_SCORE.", str(ctx_ret_plan.exception))

  def test_compile_all_38_catalog_metrics(self):
    """All 38 metrics in METRIC_CATALOG must compile cleanly via compile_hunt_pipeline."""
    self.assertEqual(len(METRIC_CATALOG), 38)
    for metric_name, m_def in METRIC_CATALOG.items():
      ent = m_def.supported_entity_types[0]
      res = compile_hunt_pipeline(
          statistical_model="STANDARD_Z_SCORE",
          metrics=metric_name,
          entity_type=ent.value,
      )
      self.assertTrue(
          res["ast_valid"],
          f"Metric {metric_name} ({ent.value}) failed AST validation: {res['ast_errors']}",
      )
      self.assertIn("metrics.", res["compiled_query"])

  def test_compile_advanced_pipeline_architectures(self):
    """Tests 3-stage, 4-stage, multilevel, triad, cloud scope, rare destination, and hybrid DAGs."""
    architectures = [
        ("dual_baseline", "http_queries_total", "ASSET"),
        ("empirical_bayes", "http_queries_total", "ASSET"),
        ("sector_fusion", "auth_attempts_fail,network_bytes_outbound", "ASSET"),
        ("multi_sector_fusion_4stage", "auth_attempts_fail,network_bytes_outbound", "ASSET"),
        ("triad", "network_bytes_outbound,network_bytes_inbound,network_bytes_total", "ASSET"),
        ("multilevel", "auth_attempts_total", "USER"),
        ("cloud_scope", "resource_read_total", "USER"),
        ("rare_destination", "network_bytes_outbound", "ASSET"),
        ("fusion_rare_destination", "auth_attempts_total,http_queries_total", "ASSET"),
        ("failure_ratio", "http_queries_fail", "ASSET"),
        ("c2_beacon_flow", "network_flows_outbound", "ASSET"),
        ("alert_surge", "alert_event_name_count", "ASSET"),
        ("hybrid_enrichment", "network_bytes_outbound", "ASSET"),
        ("hybrid_entropy_concentration", "network_bytes_outbound", "ASSET"),
        ("hybrid_orthogonal_space", "network_bytes_outbound", "ASSET"),
        ("hybrid_fleet_prevalence", "file_executions_total", "ASSET"),
        ("hybrid_derived_file_prevalence", "file_executions_total", "ASSET"),
        ("hybrid_derived_domain_prevalence", "http_queries_total", "ASSET"),
        ("hybrid_whois_domain_lifecycle", "http_queries_total", "ASSET"),
        ("hybrid_derived_asset_age", "auth_attempts_total", "ASSET"),
    ]
    for arch, metric_str, ent in architectures:
      res = compile_hunt_pipeline(
          architecture=arch,
          metrics=metric_str,
          entity_type=ent,
          entity_value="srv-prod-01" if ent == "ASSET" else "svc- prod@corp.iam.gserviceaccount.com",
          cohort_entities=["alice", "bob"] if arch in ("triad", "multilevel") else None,
      )
      self.assertTrue(
          res["ast_valid"],
          f"Architecture {arch} failed AST validation: {res['ast_errors']}",
      )
      self.assertEqual(res["statistical_violations"], [], f"Stat violations in {arch}")

  def test_compile_360_radar_generates_all_6_sectors(self):
    """360_radar architecture must populate sector_queries with all 6 decoupled sectors."""
    res_user = compile_hunt_pipeline(
        architecture="360_radar",
        entity_type="USER",
        entity_value="alex.smith",
    )
    self.assertTrue(res_user["ast_valid"])
    self.assertIsNotNone(res_user["sector_queries"])
    self.assertEqual(
        set(res_user["sector_queries"].keys()),
        {"auth", "cloud", "workspace", "network", "dns", "web"},
    )
    for sec_name, sq in res_user["sector_queries"].items():
      self.assertIn("alex.smith", sq, f"Entity missing from {sec_name} query")

    res_host = compile_hunt_pipeline(
        architecture="360_radar",
        entity_type="ASSET",
        entity_value="wkst-fin-09",
    )
    self.assertEqual(
        set(res_host["sector_queries"].keys()),
        {"auth", "alerts", "endpoint", "network", "dns", "web"},
    )

  def test_compile_killchain_and_chained_hunt_paths(self):
    """All 8 KillChainArchetype values and all 4 ChainedHuntRouter paths must compile cleanly."""
    for kc in KillChainArchetype:
      res = compile_hunt_pipeline(killchain_archetype=kc.value)
      self.assertTrue(res["ast_valid"], f"Killchain {kc} failed: {res['ast_errors']}")
      self.assertIn(kc.value, res["compiled_query"])

    for path_name in ChainedHuntRouter.CROSS_ENTITY_PATHS:
      res = compile_hunt_pipeline(chained_path=path_name, entity_value="wkst-01")
      self.assertTrue(res["ast_valid"], f"Chained path {path_name} failed: {res['ast_errors']}")
      self.assertIsNotNone(res["chained_plan"])
      self.assertIn("phase1_query", res["chained_plan"])
      self.assertIn("phase2_query", res["chained_plan"])

  def test_compile_micro_raw_plane(self):
    """MICRO_RAW plane must compile valid multi-stage raw UDM queries for zscore, cv, and fano."""
    for raw_model in ("zscore", "cv", "fano"):
      res = compile_hunt_pipeline(
          statistical_model=raw_model,
          plane="MICRO_RAW",
          entity_type="ASSET",
          entity_value="proxy-edge-01",
      )
      self.assertEqual(res["plane"], "MICRO_RAW")
      self.assertTrue(res["ast_valid"], f"MICRO_RAW {raw_model} failed AST: {res['ast_errors']}")
      self.assertIn("proxy-edge-01", res["compiled_query"])

  def test_compile_modes_a_b_c_d_and_ecg_72h_anchor(self):
    """Tests time window computation across Modes A, B, C, D and ECG 72h anchor."""
    ref_time = datetime.datetime(2026, 10, 17, 15, 30, 0, tzinfo=datetime.timezone.utc)

    # Mode A standard metric -> today 00:00:00Z
    res_a = compile_hunt_pipeline(
        statistical_model="zscore",
        metrics="auth_attempts_total",
        entity_type="USER",
        mode="A",
        reference_time=ref_time,
    )
    self.assertEqual(res_a["start_time"], "2026-10-17T00:00:00Z")
    self.assertEqual(res_a["end_time"], "2026-10-17T15:30:00Z")
    self.assertEqual(res_a["probe_start_time"], "2026-10-17T15:20:00Z")
    self.assertFalse(res_a["search_window"]["ecg_72h_anchor_applied"])

    # Mode A with ECG (`graph.`) -> -2d at 00:00:00Z (72h anchor)
    res_ecg = compile_hunt_pipeline(
        architecture="hybrid_derived_file_prevalence",
        metrics="file_executions_total",
        entity_type="ASSET",
        mode="A",
        reference_time=ref_time,
    )
    self.assertTrue(res_ecg["search_window"]["ecg_72h_anchor_applied"])
    self.assertEqual(res_ecg["start_time"], "2026-10-15T00:00:00Z")

    # Mode B 7-day fixed-baseline timeline
    res_b = compile_hunt_pipeline(
        statistical_model="zscore",
        metrics="network_bytes_outbound",
        entity_type="ASSET",
        mode="B",
        window_days=7,
        reference_time=ref_time,
    )
    self.assertEqual(res_b["mode"], "B")
    self.assertEqual(res_b["window_days"], 7)
    self.assertEqual(res_b["start_time"], "2026-10-11T00:00:00Z")
    self.assertEqual(res_b["search_window"]["baseline_start_date"], "2026-09-11")
    self.assertEqual(res_b["search_window"]["baseline_end_date"], "2026-10-10")

    # Mode C 5-day rolling shards
    res_c = compile_hunt_pipeline(
        statistical_model="zscore",
        metrics="auth_attempts_fail",
        entity_type="USER",
        mode="C",
        window_days=5,
        reference_time=ref_time,
    )
    self.assertEqual(res_c["mode"], "C")
    self.assertEqual(len(res_c["shards"]), 5)
    self.assertEqual(res_c["shards"][0]["day"], "2026-10-13")
    self.assertEqual(res_c["shards"][-1]["day"], "2026-10-17")

    # Mode D Fleet Rollup
    res_d = compile_hunt_pipeline(
        statistical_model="zscore",
        metrics="auth_attempts_total",
        entity_type="USER",
        mode="D",
        reference_time=ref_time,
    )
    self.assertEqual(res_d["mode"], "D")
    self.assertIn("match:\n  $user\n", res_d["compiled_query"])

  def test_entity_and_custom_filter_injection(self):
    """Entity value and custom UDM filter must be injected into Stage 1 without breaking AST."""
    res = compile_hunt_pipeline(
        statistical_model="zscore",
        metrics="auth_attempts_fail",
        entity_type="USER",
        entity_value="jdoe@corp.example.com",
        custom_filter='$e.principal.ip != "127.0.0.1"',
        sensitivity="HIGH_PRECISION",
    )
    self.assertTrue(res["ast_valid"], f"AST errors: {res['ast_errors']}")
    self.assertEqual(res["anomaly_threshold"], 4.0)
    self.assertIn('$user = "jdoe@corp.example.com"', res["compiled_query"])
    self.assertIn('principal.ip != "127.0.0.1"', res["compiled_query"])
    self.assertNotIn("$e.principal.ip", res["compiled_query"])


class TestUEBAHybridEngineHandoff(unittest.TestCase):
  """Tests dispatch_hybrid_handoff across all 15 intents, macro context, and Turn-1 demarcation."""

  def test_dispatch_all_supported_handoff_intents(self):
    """Every intent in SUPPORTED_INTENTS must receive HANDOFF_ACK_ACCEPTED and a compiled query."""
    for intent in SUPPORTED_INTENTS:
      res = dispatch_hybrid_handoff(
          intent=intent,
          entity_value="site-rev-proxy.lan",
          entity_type="HOSTNAME",
          lookback="24h",
          sensitivity="BALANCED",
      )
      self.assertEqual(res["protocol"], SUPPORTED_PROTOCOL)
      self.assertEqual(res["status"], "HANDOFF_ACK_ACCEPTED")
      self.assertEqual(res["action"], "STEP_OUT_CONFIRMED")
      self.assertTrue(len(res["compiled_query"]) > 0, f"Empty compiled query for {intent}")
      self.assertIn("```json:secops-threat-hunt-handoff-v1", res["handoff_card_markdown"])

  def test_dispatch_with_macro_context_enrichment(self):
    """Macro context from Phase 1 must be embedded into payload parameters and justification."""
    res = dispatch_hybrid_handoff(
        intent="C2_BEACONING_JITTER",
        entity_value="wkst-eng-04",
        entity_type="HOSTNAME",
        macro_context={
            "metric": "network_bytes_outbound",
            "z_score": 9.45,
            "cri": 98,
            "observed": 850000000,
        },
    )
    self.assertEqual(res["status"], "HANDOFF_ACK_ACCEPTED")
    self.assertIn("macro_context", res["payload"]["statistical_model"]["parameters"])
    self.assertEqual(
        res["payload"]["statistical_model"]["parameters"]["macro_context"]["z_score"],
        9.45,
    )
    self.assertIn("network_bytes_outbound", res["payload"]["justification"])
    self.assertIn("Z=9.45", res["payload"]["justification"])

  def test_turn1_demarcation_only_enforces_zero_code_invariant(self):
    """Turn 1 consultative demarcation must never emit a ```yara block."""
    res = dispatch_hybrid_handoff(
        intent="SCHEDULED_EXFILTRATION_TIMING",
        entity_value="site-rev-proxy",
        entity_type="HOSTNAME",
        turn1_demarcation_only=True,
    )
    self.assertEqual(res["status"], "PENDING_DISPATCH")
    self.assertEqual(res["action"], "CONSULTATIVE_DEMARCATION")
    self.assertEqual(res["compiled_query"], "")
    self.assertIn("```json:secops-threat-hunt-handoff-v1", res["handoff_card_markdown"])
    self.assertNotIn("```yara", res["handoff_card_markdown"])


class TestUEBAHybridEngineDossier(unittest.TestCase):
  """Tests render_forensic_dossier across Acute Outliers, Zero-Row Clean Hunts, Fleet Waves, and Sparse Baselines."""

  def setUp(self):
    compiled = compile_hunt_pipeline(
        statistical_model="STANDARD_Z_SCORE",
        metrics="auth_attempts_fail",
        entity_type="USER",
    )
    self.sample_query = compiled["compiled_query"]

  def test_render_populated_acute_outlier_dossier_and_html_export(self):
    """Populated outlier rows must render all 6 sections, CRI badges, SVG/HTML charts, and file artifacts."""
    rows = [
        {
            "entity": "alex.smith",
            "observed": 420,
            "hist_avg": 12.0,
            "hist_stddev": 4.0,
            "z_score": 102.0,
            "active_days": 29,
        },
        {
            "entity": "bob.jones",
            "observed": 48,
            "hist_avg": 10.0,
            "hist_stddev": 8.0,
            "z_score": 4.75,
            "active_days": 25,
        },
    ]
    with tempfile.TemporaryDirectory() as tmpdir:
      html_path = Path(tmpdir) / "outlier_report.html"
      res = render_forensic_dossier(
          rows=rows,
          executed_query=self.sample_query,
          statistical_model="STANDARD_Z_SCORE",
          metric_name="auth_attempts_fail",
          entity_type="USER",
          mode="A",
          output_html_path=html_path,
      )
      self.assertEqual(res["status"], "RENDERED")
      self.assertFalse(res["is_zero_row"])
      self.assertEqual(res["outcome_classification"], "ACUTE_OUTLIER")
      self.assertEqual(res["outlier_count"], 2)
      self.assertEqual(res["outliers"][0]["cri"], 100)
      self.assertEqual(res["outliers"][0]["cri_badge"], "CRITICAL")

      md = res["dossier_markdown"]
      self.assertIn("#### 1. Statistical Outlier Report", md)
      self.assertNotIn("Executed Multi-Stage YARA-L Query", md)
      self.assertIn("#### 2. Ranked Outlier Summary & Provenance Stamp", md)
      self.assertIn("#### 3. Forensic Vector Breakdown & Impact Analysis", md)
      self.assertIn("#### 4. Chronicle UI Manual Pivot (Triage Reference Only)", md)
      self.assertIn("#### 5. Collapsible Technical Appendix", md)
      self.assertIn("**[1]", md)
      self.assertIn("**[2]", md)
      self.assertIn("**[3]", md)
      self.assertIn("<agent-embed", md)
      self.assertIn("<svg", res["chart_svg"])
      self.assertTrue(html_path.exists())
      self.assertTrue(html_path.with_suffix(".svg").exists())

  def test_render_zero_row_clean_hunt_recovery(self):
    """Empty rows must trigger Zero-Row Recovery with Nominal Fleet Baseline and CRI=0."""
    res = render_forensic_dossier(
        rows=[],
        executed_query=self.sample_query,
        statistical_model="STANDARD_Z_SCORE",
        metric_name="auth_attempts_fail",
        entity_type="USER",
        mode="A",
    )
    self.assertEqual(res["status"], "RENDERED")
    self.assertTrue(res["is_zero_row"])
    self.assertEqual(res["outcome_classification"], "CLEAN_OR_SUBTHRESHOLD")
    self.assertEqual(res["outlier_count"], 0)
    self.assertIn("0 observed events", res["dossier_markdown"])
    self.assertIn("0 ranked outlier entities", res["dossier_markdown"])
    self.assertIn("Nominal Fleet Baseline", res["dossier_markdown"])
    self.assertIn("**[1]", res["dossier_markdown"])
    self.assertIn("**[2]", res["dossier_markdown"])
    self.assertIn("**[3]", res["dossier_markdown"])

  def test_render_fleet_wave_and_sparse_baseline_outcomes(self):
    """10+ entities must classify as FLEET_WAVE; active_days < 7 must classify as SPARSE_BASELINE."""
    fleet_rows = [
        {"entity": f"host-{i:02d}", "observed": 100, "hist_avg": 10, "hist_stddev": 5, "z_score": 18.0, "active_days": 20}
        for i in range(12)
    ]
    res_wave = render_forensic_dossier(
        rows=fleet_rows,
        executed_query=self.sample_query,
        metric_name="file_executions_total",
        entity_type="ASSET",
    )
    self.assertEqual(res_wave["outcome_classification"], "FLEET_WAVE")
    self.assertIn("Suppress Rollout / Patch Wave Noise", res_wave["dossier_markdown"])

    sparse_rows = [
        {"entity": "new_hire_user", "observed": 50, "hist_avg": 2, "hist_stddev": 1, "z_score": 48.0, "active_days": 3}
    ]
    res_sparse = render_forensic_dossier(
        rows=sparse_rows,
        executed_query=self.sample_query,
        metric_name="auth_attempts_total",
        entity_type="USER",
    )
    self.assertEqual(res_sparse["outcome_classification"], "SPARSE_BASELINE")
    self.assertIn("Sparse Baseline Caution", res_sparse["dossier_markdown"])

  def test_render_with_360_radar_scores_and_mode_c_shards(self):
    """WS4 / D6-G1..G3: 360° radar integration requires raw udm_search sector payloads and prints provenance."""
    shards = [
        ("2026-10-15", [{"user": "alex.smith", "observed_val": 25, "historical_avg": 10, "historical_stddev": 2, "z_score": 7.5}]),
        ("2026-10-16", [{"user": "alex.smith", "observed_val": 40, "historical_avg": 10, "historical_stddev": 2, "z_score": 15.0}]),
    ]
    raw_sector_payloads = {
        "auth": {
            "stats": {
                "results": [
                    {"column": "user", "values": [{"value": {"stringVal": "alex.smith"}}]},
                    {"column": "observed", "values": [{"value": {"int64Val": "23"}}]},
                    {"column": "baseline", "values": [{"value": {"doubleVal": 10.0}}]},
                    {"column": "dispersion", "values": [{"value": {"doubleVal": 2.0}}]},
                    {"column": "z", "values": [{"value": {"doubleVal": 6.5}}]},
                ]
            }
        },
        "cloud": {
            "stats": {
                "results": [
                    {"column": "user", "values": [{"value": {"stringVal": "alex.smith"}}]},
                    {"column": "observed", "values": [{"value": {"int64Val": "52"}}]},
                    {"column": "baseline", "values": [{"value": {"doubleVal": 10.0}}]},
                    {"column": "dispersion", "values": [{"value": {"doubleVal": 10.0}}]},
                    {"column": "z", "values": [{"value": {"doubleVal": 4.2}}]},
                ]
            }
        },
        "workspace": {},
        "network": {},
        "dns": {},
        "web": {},
    }
    res = render_forensic_dossier(
        rows=shards,
        executed_query=self.sample_query,
        metric_name="auth_attempts_total",
        entity_type="USER",
        mode="C",
        radar_sector_payloads=raw_sector_payloads,
    )
    self.assertFalse(res["is_zero_row"])
    self.assertIsNotNone(res["radar_payload"])
    self.assertGreater(res["radar_payload"]["composite_risk_distance"], 7.0)
    self.assertIn("provenance", res["radar_payload"])
    prov = res["radar_payload"]["provenance"]
    self.assertEqual(prov["helper_version"], "2.3.0")
    self.assertEqual(len(prov["payload_sha256"]), 64)
    self.assertEqual(len(prov["query_sha256"]), 64)
    self.assertIn("360° Multi-Sector Behavioral Risk Radar Summary", res["dossier_markdown"])
    self.assertIn("Multi-Day Timeline Breakdown", res["dossier_markdown"])
    self.assertIn(prov["payload_sha256"], res["dossier_markdown"])
    self.assertIn(prov["query_sha256"], res["dossier_markdown"])

    # Also verify backward-compatible radar_scores parameter accepts raw sector payload dicts
    res_compat = render_forensic_dossier(
        rows=shards,
        executed_query=self.sample_query,
        metric_name="auth_attempts_total",
        entity_type="USER",
        mode="C",
        radar_scores=raw_sector_payloads,
    )
    self.assertGreater(res_compat["radar_payload"]["composite_risk_distance"], 7.0)

  def test_render_forensic_dossier_rejects_g1_typed_radar_scores(self):
    """WS4 / D6-G1: render_forensic_dossier rejects string or float-dict radar_scores and raw event dumps."""
    sample_rows = [
        {"entity": "alex.smith", "observed": 25, "hist_avg": 10, "hist_stddev": 2, "z_score": 7.5}
    ]
    with self.assertRaises(ValueError) as str_ctx:
      render_forensic_dossier(
          rows=sample_rows,
          executed_query=self.sample_query,
          metric_name="auth_attempts_total",
          entity_type="USER",
          radar_scores="auth:6.5,cloud:4.2,workspace:1.1,network:0.5,dns:0.2,web:0.8",
      )
    self.assertIn("G1", str(str_ctx.exception))

    with self.assertRaises(ValueError) as dict_ctx:
      render_forensic_dossier(
          rows=sample_rows,
          executed_query=self.sample_query,
          metric_name="auth_attempts_total",
          entity_type="USER",
          radar_scores={"auth": 6.5, "cloud": 4.2},
      )
    self.assertIn("G1", str(dict_ctx.exception))

    with self.assertRaises(ValueError) as dump_ctx:
      render_forensic_dossier(
          rows=sample_rows,
          executed_query=self.sample_query,
          metric_name="auth_attempts_total",
          entity_type="USER",
          radar_sector_payloads={"auth": {"events": [{"metadata": {"id": "evt-1"}}]}},
      )
    self.assertIn("RAW_LOG_DUMP_DETECTED", str(dump_ctx.exception))

  def test_postflight_audit_blocks_raw_log_dump(self):
    """Passing raw UDM events without stats must trigger RAW_LOG_DUMP_DETECTED."""
    raw_dump = {"events": [{"metadata": {"id": "evt-1"}}]}
    res = render_forensic_dossier(
        rows=raw_dump,
        executed_query=self.sample_query,
        metric_name="auth_attempts_fail",
        entity_type="USER",
    )
    self.assertEqual(res["status"], "POSTFLIGHT_AUDIT_BLOCKED")
    self.assertEqual(res["outcome_classification"], "AUDIT_BLOCKED")


class TestUEBAHybridEngineCLIAndCatalog(unittest.TestCase):
  """Tests get_metric_catalog_summary, UEBAHybridEngine facade, and CLI subcommands."""

  def test_catalog_summary_and_facade(self):
    summary = UEBAHybridEngine.get_metric_catalog_summary()
    self.assertEqual(summary["total_metrics"], 38)
    self.assertEqual(len(summary["statistical_models"]), 18)
    self.assertEqual(len(summary["handoff_intents"]), len(SUPPORTED_INTENTS))

    dns_only = get_metric_catalog_summary(sector="dns", entity_type="ASSET")
    self.assertGreaterEqual(dns_only["total_metrics"], 4)

  def test_cli_subcommands(self):
    # 1. compile subcommand
    buf = io.StringIO()
    with patch("sys.stdout", buf):
      rc = cli_main(["compile", "--model", "mad", "--metrics", "network_bytes_outbound", "--entity-type", "ASSET", "--format", "json"])
    self.assertEqual(rc, 0)
    parsed = json.loads(buf.getvalue())
    self.assertEqual(parsed["statistical_model"], StatisticalModel.MAD.value)
    self.assertTrue(parsed["ast_valid"])

    # 2. handoff subcommand
    buf = io.StringIO()
    with patch("sys.stdout", buf):
      rc = cli_main(["handoff", "--intent", "C2_BEACONING_JITTER", "--entity", "srv-01", "--turn1-only", "--format", "card"])
    self.assertEqual(rc, 0)
    self.assertIn("secops-threat-hunt-handoff-v1", buf.getvalue())

    # 3. render subcommand
    buf = io.StringIO()
    with patch("sys.stdout", buf):
      rc = cli_main(["render", "--rows", "[]", "--metric", "auth_attempts_total", "--format", "markdown"])
    self.assertEqual(rc, 0)
    self.assertIn("Nominal Fleet Baseline", buf.getvalue())

    # 4. catalog subcommand
    buf = io.StringIO()
    with patch("sys.stdout", buf):
      rc = cli_main(["catalog", "--sector", "auth"])
    self.assertEqual(rc, 0)
    cat_data = json.loads(buf.getvalue())
    self.assertIn("auth_attempts_total", cat_data["metrics"])


  def test_compile_cusum_and_mad_mode_b_window_alignment(self):
    """Verifies LONGITUDINAL_CUSUM multi-day gate and MAD Mode B scoring window alignment."""
    res_cusum = compile_hunt_pipeline(
        statistical_model="LONGITUDINAL_CUSUM",
        metrics="network_bytes_outbound",
        entity_type="ASSET",
        mode="A",
    )
    self.assertTrue(res_cusum["ast_valid"])
    self.assertIn("stage stage2_daily_drift", res_cusum["compiled_query"])
    self.assertIn("$drift_days >= 2", res_cusum["compiled_query"])

    ref_time = datetime.datetime(2026, 10, 17, 12, 0, 0, tzinfo=datetime.timezone.utc)
    res_mad_b = compile_hunt_pipeline(
        statistical_model="MAD",
        metrics="auth_attempts_total",
        entity_type="USER",
        mode="B",
        window_days=5,
        reference_time=ref_time,
    )
    self.assertTrue(res_mad_b["ast_valid"])
    self.assertIn("$in_scoring_window = 1", res_mad_b["compiled_query"])


if __name__ == "__main__":

  unittest.main()
