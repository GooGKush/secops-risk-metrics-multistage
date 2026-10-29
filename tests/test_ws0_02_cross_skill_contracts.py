# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""WS0-02: Cross-Skill Contract Test Suite for the Bilateral UEBA Harness.

This test file is maintained byte-for-byte identically across both
`secops-risk-metrics-multistage` and `secops-statistical-hunter`. It verifies
all five cross-skill integration contracts simultaneously without mutating
global `sys.path` or colliding `scripts.*` namespaces:
  1. Handoff Payload -> Entity-Bound Compiled Query (WS8-01, WS8-04)
  2. Identical CRI Function, Bands & Score Semantics (WS7-01, WS7-02, D5)
  3. Frozen Write-Back Payload Characterization (WS8-03, D7)
  4. Byte-for-Byte Identical Canonical Routing Table & Zero Ping-Pong (WS8-02)
  5. Identical Fusion, Maturity & Write-Back Thresholds (WS2-08, D8)
"""

from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import importlib
import importlib.util
import json
import math
from pathlib import Path
import re
import sys
import tempfile
from types import ModuleType
from typing import Any, Dict, Iterator, Optional, Tuple
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent

MACRO_SKILL_NAME = "secops-risk-metrics-multistage"
MICRO_SKILL_NAME = "secops-statistical-hunter"

ROUTING_START_TAG = "<!-- CANONICAL_SKILL_ROUTING_TABLE_START -->"
ROUTING_END_TAG = "<!-- CANONICAL_SKILL_ROUTING_TABLE_END -->"

EXPECTED_MACRO_PRODUCT_EVENT_TYPES: Tuple[str, ...] = (
    "VOLUMETRIC_BASELINE_ANOMALY",
    "BURST_CLUSTER_ANOMALY",
    "DISCRETE_RARITY_ANOMALY",
    "BAYESIAN_SHRINKAGE_ANOMALY",
    "PEER_COHORT_BREAKOUT_ANOMALY",
    "FLEET_NORMALIZED_DELTA_Z",
    "MULTI_SECTOR_THREAT_FUSION",
    "LONGITUDINAL_CUSUM_DRIFT",
    "ENTITY_GRAPH_RARITY_OUTLIER",
    "BEHAVIORAL_RISK_RADAR_360",
)

EXPECTED_MICRO_PRODUCT_EVENT_TYPES: Tuple[str, ...] = (
    "VOLUMETRIC_BASELINE_ANOMALY",
    "INLINE_MAD_OUTLIER",
    "POISSON_BURST_CLUSTERING",
    "POISSON_DEVIANCE_RARITY",
    "C2_BEACONING_JITTER",
    "TUKEY_IQR_FENCE_ANOMALY",
    "BAYESIAN_SHRINKAGE_ANOMALY",
    "TWO_PART_HURDLE_AWAKENING",
    "MULTI_SECTOR_THREAT_FUSION",
    "HYBRID_ENTROPY_CONCENTRATION",
    "FEDERATED_MACRO_MICRO_CORRELATION",
)

_EPHEMERAL_SCRIPT_MODULES = (
    "scripts",
    "ueba_constants",
    "federated_handoff",
    "chronicle_ingest",
    "clean_handoff",
    "multistage_query_builder",
    "radar_collector",
    "template_router",
    "ueba_hybrid_engine",
    "preflight_validator",
    "malachite_catalog",
    "chart_generator",
    "statistical_validator",
    "timeline_assembler",
    "triage_formatter",
)


def _detect_local_skill_name(repo_root: Path) -> str:
  skill_md = (repo_root / "SKILL.md").read_text(encoding="utf-8")
  if f"name: {MACRO_SKILL_NAME}" in skill_md:
    return MACRO_SKILL_NAME
  if f"name: {MICRO_SKILL_NAME}" in skill_md:
    return MICRO_SKILL_NAME
  raise RuntimeError(f"Unable to identify skill name from {repo_root / 'SKILL.md'}")


def _resolve_sibling_root(repo_root: Path, local_skill: str, sibling_name: str) -> Optional[Path]:
  candidates = []
  prefix = f"{local_skill}-"
  if repo_root.name.startswith(prefix):
    ws_suffix = repo_root.name[len(prefix) :]
    if ws_suffix:
      candidates.append(repo_root.parent / f"{sibling_name}-{ws_suffix}")
  candidates.append(repo_root.parent / sibling_name)
  candidates.append(repo_root.parent.parent / sibling_name)

  for cand in candidates:
    if (cand / "SKILL.md").exists() and (cand / "scripts").is_dir():
      return cand
  return None


def _resolve_macro_and_micro_roots() -> Tuple[Optional[Path], Optional[Path]]:
  local_skill = _detect_local_skill_name(REPO_ROOT)
  if local_skill == MACRO_SKILL_NAME:
    sibling = _resolve_sibling_root(REPO_ROOT, MACRO_SKILL_NAME, MICRO_SKILL_NAME)
    return REPO_ROOT, sibling
  sibling = _resolve_sibling_root(REPO_ROOT, MICRO_SKILL_NAME, MACRO_SKILL_NAME)
  return sibling, REPO_ROOT


@contextmanager
def _isolated_skill_import_context(skill_root: Path) -> Iterator[None]:
  """Temporarily isolates sys.path and scripts.* in sys.modules for cross-repo loading."""
  orig_path = list(sys.path)
  saved_modules: Dict[str, ModuleType] = {}
  for mod_name in list(sys.modules.keys()):
    if (
        mod_name == "scripts"
        or mod_name.startswith("scripts.")
        or mod_name in _EPHEMERAL_SCRIPT_MODULES
    ):
      saved_modules[mod_name] = sys.modules.pop(mod_name)

  sys.path.insert(0, str(skill_root / "scripts"))
  sys.path.insert(0, str(skill_root))
  try:
    yield
  finally:
    for mod_name in list(sys.modules.keys()):
      if (
          mod_name == "scripts"
          or mod_name.startswith("scripts.")
          or mod_name in _EPHEMERAL_SCRIPT_MODULES
      ):
        sys.modules.pop(mod_name, None)
    sys.modules.update(saved_modules)
    sys.path[:] = orig_path


def _load_skill_module(alias: str, skill_root: Path, rel_path: str) -> ModuleType:
  target = skill_root / rel_path
  with _isolated_skill_import_context(skill_root):
    if rel_path.startswith("scripts/"):
      importlib.import_module("scripts")
      spec_name = f"scripts.{alias}"
    else:
      spec_name = alias
    spec = importlib.util.spec_from_file_location(spec_name, str(target))
    if spec is None or spec.loader is None:
      raise ImportError(f"Could not create ModuleSpec for {target}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec_name] = module
    sys.modules[alias] = module
    spec.loader.exec_module(module)
    return module


def _sha256_bytes(data: bytes) -> str:
  return hashlib.sha256(data).hexdigest()


def _extract_canonical_routing_table(md_text: str) -> str:
  pattern = re.compile(
      re.escape(ROUTING_START_TAG) + r".*?" + re.escape(ROUTING_END_TAG),
      re.DOTALL,
  )
  matches = pattern.findall(md_text)
  if len(matches) != 1:
    raise AssertionError(
        f"Expected exactly 1 canonical routing table block, found {len(matches)}"
    )
  return matches[0]


def _extract_macro_canonical_schemas(macro_root: Path) -> Dict[str, Dict[str, Any]]:
  schema_doc = (macro_root / "references" / "clean-handoff-udm-schema.md").read_text(
      encoding="utf-8"
  )
  pattern = re.compile(
      r"###\s+\d+\.\s+`([A-Z0-9_]+)`[^\n]*\n(?:(?!```json).)*?```json\n(.*?)\n```",
      re.DOTALL,
  )
  extracted: Dict[str, Dict[str, Any]] = {}
  for match in pattern.finditer(schema_doc):
    extracted[match.group(1)] = json.loads(match.group(2))
  return extracted


def verify_constants_and_threshold_sync(
    macro_bytes: bytes,
    micro_bytes: bytes,
    macro_thresholds: Dict[str, Any],
    micro_thresholds: Dict[str, Any],
) -> None:
  """Raises AssertionError if ueba_constants.py bytes or threshold maps drift."""
  if _sha256_bytes(macro_bytes) != _sha256_bytes(micro_bytes):
    raise AssertionError(
        "SHA-256 mismatch between macro and micro scripts/ueba_constants.py"
    )
  if macro_thresholds != micro_thresholds:
    raise AssertionError(
        f"Threshold drift detected: {macro_thresholds} != {micro_thresholds}"
    )


class TestWS002CrossSkillContracts(unittest.TestCase):
  """Verifies all 5 cross-skill contracts across macro and micro UEBA skills."""

  macro_root: Optional[Path] = None
  micro_root: Optional[Path] = None
  macro_constants: Any = None
  micro_constants: Any = None
  macro_handoff: Any = None
  macro_hybrid: Any = None
  macro_radar: Any = None
  macro_router: Any = None
  macro_ingest: Any = None
  micro_mqb: Any = None
  micro_clean_handoff: Any = None

  @classmethod
  def setUpClass(cls) -> None:
    super().setUpClass()
    cls.macro_root, cls.micro_root = _resolve_macro_and_micro_roots()
    if cls.macro_root is None or cls.micro_root is None:
      return

    cls.macro_constants = _load_skill_module(
        "_macro_ueba_constants", cls.macro_root, "scripts/ueba_constants.py"
    )
    cls.micro_constants = _load_skill_module(
        "_micro_ueba_constants", cls.micro_root, "scripts/ueba_constants.py"
    )
    cls.macro_handoff = _load_skill_module(
        "_macro_federated_handoff", cls.macro_root, "scripts/federated_handoff.py"
    )
    cls.macro_hybrid = _load_skill_module(
        "_macro_ueba_hybrid_engine", cls.macro_root, "scripts/ueba_hybrid_engine.py"
    )
    cls.macro_radar = _load_skill_module(
        "_macro_radar_collector", cls.macro_root, "scripts/radar_collector.py"
    )
    cls.macro_router = _load_skill_module(
        "_macro_template_router", cls.macro_root, "scripts/template_router.py"
    )
    cls.macro_ingest = _load_skill_module(
        "_macro_chronicle_ingest", cls.macro_root, "scripts/chronicle_ingest.py"
    )
    cls.micro_mqb = _load_skill_module(
        "_micro_mqb", cls.micro_root, "scripts/multistage_query_builder.py"
    )
    cls.micro_clean_handoff = _load_skill_module(
        "_micro_clean_handoff", cls.micro_root, "scripts/clean_handoff.py"
    )

  @classmethod
  def tearDownClass(cls) -> None:
    for alias in (
        "_macro_ueba_constants",
        "_micro_ueba_constants",
        "_macro_federated_handoff",
        "_macro_ueba_hybrid_engine",
        "_macro_radar_collector",
        "_macro_template_router",
        "_macro_chronicle_ingest",
        "_micro_mqb",
        "_micro_clean_handoff",
    ):
      sys.modules.pop(alias, None)
    super().tearDownClass()

  def setUp(self) -> None:
    super().setUp()
    if self.macro_root is None or self.micro_root is None:
      self.skipTest("Sibling UEBA skill repository is not checked out alongside this repo.")

  def test_contract_0_test_suite_file_is_byte_identical_across_repos(self) -> None:
    """Ensures tests/test_ws0_02_cross_skill_contracts.py itself has not drifted and sibling discovery covers all layouts."""
    assert self.macro_root is not None and self.micro_root is not None
    macro_test = self.macro_root / "tests" / "test_ws0_02_cross_skill_contracts.py"
    micro_test = self.micro_root / "tests" / "test_ws0_02_cross_skill_contracts.py"
    if macro_test.exists() and micro_test.exists():
      self.assertEqual(
          _sha256_bytes(macro_test.read_bytes()),
          _sha256_bytes(micro_test.read_bytes()),
          "tests/test_ws0_02_cross_skill_contracts.py must remain byte-for-byte identical in both repos",
      )

    # Verify sibling discovery works in both canonical ~/projects/secops-* and .worktrees/*-WS layouts
    with tempfile.TemporaryDirectory() as tmp:
      projects = Path(tmp)
      canon_macro = projects / MACRO_SKILL_NAME
      canon_micro = projects / MICRO_SKILL_NAME
      for root in (canon_macro, canon_micro):
        (root / "scripts").mkdir(parents=True)
        (root / "SKILL.md").write_text(f"name: {root.name}\n", encoding="utf-8")
      self.assertEqual(
          _resolve_sibling_root(canon_macro, MACRO_SKILL_NAME, MICRO_SKILL_NAME),
          canon_micro,
      )
      self.assertEqual(
          _resolve_sibling_root(canon_micro, MICRO_SKILL_NAME, MACRO_SKILL_NAME),
          canon_macro,
      )

      wt_macro = projects / ".worktrees" / f"{MACRO_SKILL_NAME}-WS0"
      wt_micro = projects / ".worktrees" / f"{MICRO_SKILL_NAME}-WS0"
      (wt_macro / "scripts").mkdir(parents=True)
      (wt_macro / "SKILL.md").write_text(f"name: {MACRO_SKILL_NAME}\n", encoding="utf-8")
      # Before sibling worktree exists, falls back to canonical repo in parent.parent
      self.assertEqual(
          _resolve_sibling_root(wt_macro, MACRO_SKILL_NAME, MICRO_SKILL_NAME),
          canon_micro,
      )
      # Once matching -WS0 sibling worktree exists, prefers matching worktree
      (wt_micro / "scripts").mkdir(parents=True)
      (wt_micro / "SKILL.md").write_text(f"name: {MICRO_SKILL_NAME}\n", encoding="utf-8")
      self.assertEqual(
          _resolve_sibling_root(wt_macro, MACRO_SKILL_NAME, MICRO_SKILL_NAME),
          wt_micro,
      )

  def test_contract_1_handoff_payload_to_entity_bound_compiled_query(self) -> None:
    """Contract 1 (WS8-01, WS8-04): Macro handoff payloads compile into entity-bound Micro queries."""
    assert self.macro_root is not None and self.micro_root is not None
    core_intents = [
        "SCHEDULED_EXFILTRATION_TIMING",
        "EXFILTRATION_IQR_OUTLIER",
        "PRIVILEGED_LATERAL_EXPANSION",
        "RAW_TELEMETRY_ENRICHMENT",
        "DUAL_PLANE_CORRELATION",
    ]
    all_intents = list(
        dict.fromkeys(core_intents + list(self.macro_handoff.SUPPORTED_INTENTS))
    )
    entity_matrix = [
        ("HOSTNAME", "wkstn-prod-042"),
        ("USER", "charles.hardy"),
        ("IP", "10.128.0.15"),
    ]

    for intent in all_intents:
      for entity_type, entity_val in entity_matrix:
        with self.subTest(intent=intent, entity_type=entity_type):
          payload = self.macro_handoff.build_handoff_payload(
              intent=intent,
              entity_type=entity_type,
              entity_value=entity_val,
              lookback="24h",
              sensitivity="BALANCED",
          )
          self.assertEqual(payload["protocol"], "secops-threat-hunt-handoff-v1")
          self.assertEqual(payload["target_entity"]["value"], entity_val)

          res = self.micro_mqb.HandoffEndpoint.ingest(payload)
          self.assertEqual(
              res.get("status"),
              "HANDOFF_ACK_ACCEPTED",
              f"Handoff rejected for ({intent}, {entity_type}): {res.get('errors')}",
          )
          compiled_query = res["compiled_query"]
          self.assertIn(entity_val, compiled_query)

          gate = self.micro_mqb.QueryIntegrityGate.verify_pre_dispatch(
              compiled_query,
              expected_entity=entity_val,
          )
          self.assertIs(
              gate["valid"],
              True,
              f"QueryIntegrityGate failed for ({intent}, {entity_type}): {gate['errors']}",
          )
          self.assertEqual(gate["errors"], [])

          if intent == "EXFILTRATION_IQR_OUTLIER":
            self.assertEqual(res["model_routed"], "IQR_TUKEY_SKEW_FENCES")
            self.assertNotEqual(res["model_routed"], "C2_BEACONING_JITTER")
            self.assertIn("NETWORK_CONNECTION", compiled_query)
            self.assertIn("sum(network.sent_bytes)", compiled_query)
            self.assertNotIn("max_cv", payload["statistical_model"]["parameters"])
            self.assertNotIn("max_cv", compiled_query)
            self.assertNotIn("0.20", compiled_query)

    # Also verify full subprocess round-trip via ueba_hybrid_engine.dispatch_hybrid_handoff
    hybrid_res = self.macro_hybrid.dispatch_hybrid_handoff(
        intent="EXFILTRATION_IQR_OUTLIER",
        entity_value="srv-db-export-01.corp",
        entity_type="HOSTNAME",
        lookback="24h",
        sensitivity="BALANCED",
        stats_hunter_dir=self.micro_root,
    )
    self.assertEqual(hybrid_res["status"], "HANDOFF_ACK_ACCEPTED")
    self.assertEqual(hybrid_res["model_routed"], "IQR_TUKEY_SKEW_FENCES")
    self.assertIn("srv-db-export-01.corp", hybrid_res["compiled_query"])
    self.assertIn("NETWORK_CONNECTION", hybrid_res["compiled_query"])
    self.assertIn("sum(network.sent_bytes)", hybrid_res["compiled_query"])

  def test_contract_2_identical_cri_bands_and_score_semantics(self) -> None:
    """Contract 2 (WS7-01, WS7-02, D5): Byte-identical ueba_constants.py, CRI, bands, and score semantics."""
    assert self.macro_root is not None and self.micro_root is not None
    macro_bytes = (self.macro_root / "scripts" / "ueba_constants.py").read_bytes()
    micro_bytes = (self.micro_root / "scripts" / "ueba_constants.py").read_bytes()

    macro_thresh_snapshot = {
        "anomaly": self.macro_constants.DEFAULT_ANOMALY_THRESHOLD,
        "fusion_sq": self.macro_constants.DEFAULT_FUSION_THRESHOLD_SQ,
        "writeback_cri": self.macro_constants.WRITEBACK_CRI_THRESHOLD,
    }
    micro_thresh_snapshot = {
        "anomaly": self.micro_constants.DEFAULT_ANOMALY_THRESHOLD,
        "fusion_sq": self.micro_constants.DEFAULT_FUSION_THRESHOLD_SQ,
        "writeback_cri": self.micro_constants.WRITEBACK_CRI_THRESHOLD,
    }

    verify_constants_and_threshold_sync(
        macro_bytes, micro_bytes, macro_thresh_snapshot, micro_thresh_snapshot
    )

    # Negative drift checks: mutating 1 byte or 1 threshold MUST fail validation
    mutated_bytes = micro_bytes[:-1] + (b"#" if micro_bytes[-1:] != b"#" else b"\n")
    with self.assertRaises(AssertionError):
      verify_constants_and_threshold_sync(
          macro_bytes, mutated_bytes, macro_thresh_snapshot, micro_thresh_snapshot
      )
    mutated_thresholds = dict(micro_thresh_snapshot, anomaly=3.1)
    with self.assertRaises(AssertionError):
      verify_constants_and_threshold_sync(
          macro_bytes, micro_bytes, macro_thresh_snapshot, mutated_thresholds
      )

    # Verify CRI_BANDS (26/46/70/90 cutoffs)
    expected_bands = (
        (0, 25, "INFORMATIONAL", "Nominal", "🟢"),
        (26, 45, "LOW", "Low Drift", "🟡"),
        (46, 69, "MEDIUM", "Medium Outlier", "🟠"),
        (70, 89, "HIGH", "High Threat", "🔴"),
        (90, 100, "CRITICAL", "Critical Outlier", "🚨"),
    )
    self.assertEqual(self.macro_constants.CRI_BANDS, expected_bands)
    self.assertEqual(self.micro_constants.CRI_BANDS, expected_bands)

    for cutoff_low, expected_code in (
        (25, "INFORMATIONAL"),
        (26, "LOW"),
        (45, "LOW"),
        (46, "MEDIUM"),
        (69, "MEDIUM"),
        (70, "HIGH"),
        (89, "HIGH"),
        (90, "CRITICAL"),
    ):
      self.assertEqual(self.macro_constants.get_cri_band_info(cutoff_low)[0], expected_code)
      self.assertEqual(self.micro_constants.get_cri_band_info(cutoff_low)[0], expected_code)

    # Verify identical calculate_cri across all required probe values
    probe_scores = [None, float("nan"), -5.0, 0.0, 1.0, 2.0, 2.99, 3.0, 3.5, 4.5, 6.7, 10.0]
    for probe in probe_scores:
      macro_cri = self.macro_constants.calculate_cri(probe)
      micro_cri = self.micro_constants.calculate_cri(probe)
      self.assertEqual(macro_cri, micro_cri, f"CRI mismatch for score={probe!r}")

    self.assertIsNone(self.macro_constants.calculate_cri(None))
    self.assertIsNone(self.macro_constants.calculate_cri(float("nan")))
    self.assertEqual(self.macro_constants.calculate_cri(-5.0), 0)
    self.assertEqual(self.macro_constants.calculate_cri(0.0), 0)
    self.assertEqual(self.macro_constants.calculate_cri(3.0), 50)

    # Verify identical SCORE_SEMANTICS_REGISTRY keys, threshold_3sigma_equiv, and is_true_sigma
    macro_reg = self.macro_constants.SCORE_SEMANTICS_REGISTRY
    micro_reg = self.micro_constants.SCORE_SEMANTICS_REGISTRY
    self.assertEqual(set(macro_reg.keys()), set(micro_reg.keys()))

    for key, macro_sem in macro_reg.items():
      micro_sem = micro_reg[key]
      self.assertEqual(tuple(macro_sem), tuple(micro_sem), f"Semantics drift for {key}")
      self.assertEqual(
          macro_sem.is_true_sigma,
          micro_sem.is_true_sigma,
          f"is_true_sigma drift for {key}",
      )
      macro_z_eq = self.macro_constants.score_to_z_equivalent(key, macro_sem.threshold)
      micro_z_eq = self.micro_constants.score_to_z_equivalent(key, micro_sem.threshold)
      self.assertEqual(macro_z_eq, micro_z_eq, f"threshold_3sigma_equiv drift for {key}")
      if macro_sem.kind not in ("boolean_flag", "precomputed_cri"):
        self.assertAlmostEqual(
            macro_z_eq,
            3.0,
            places=6,
            msg=f"Expected Z_equiv == 3.0 at threshold for {key}, got {macro_z_eq}",
        )

  def test_contract_3_frozen_writeback_payload_characterization(self) -> None:
    """Contract 3 (WS8-03, D7): Pins frozen write-back envelopes, product names, event types, and field types."""
    assert self.macro_root is not None and self.micro_root is not None

    # 3A. Macro: secops-risk-metrics-multistage/scripts/chronicle_ingest.py + canonical schemas
    macro_schemas = _extract_macro_canonical_schemas(self.macro_root)
    self.assertEqual(tuple(macro_schemas.keys()), EXPECTED_MACRO_PRODUCT_EVENT_TYPES)
    self.assertIn("BEHAVIORAL_RISK_RADAR_360", macro_schemas)

    for pet, envelope in macro_schemas.items():
      self.assertIn("udm", envelope)
      udm = envelope["udm"]
      self.assertEqual(self.macro_ingest.validate_events([udm]), [])
      meta = udm["metadata"]
      self.assertEqual(meta["product_name"], "SecOps Risk Metrics Hunter")
      self.assertEqual(meta["vendor_name"], "Google SecOps")
      self.assertEqual(meta["event_type"], "GENERIC_EVENT")
      self.assertEqual(meta["product_event_type"], pet)
      self.assertIs(type(meta["event_timestamp"]), str)

      for sr in udm["security_result"]:
        self.assertIs(type(sr["risk_score"]), int)
        self.assertIs(type(sr["severity"]), str)
        self.assertIs(type(sr["summary"]), str)

    radar_udm = macro_schemas["BEHAVIORAL_RISK_RADAR_360"]["udm"]
    import_events_body = self.macro_ingest.build_import_events_body([radar_udm])
    self.assertEqual(import_events_body, {"inlineSource": {"events": [{"udm": radar_udm}]}})
    self.assertEqual(radar_udm["security_result"][0]["rule_type"], "COMPOSITE_360")
    self.assertEqual(radar_udm["security_result"][1]["rule_type"], "SECTOR_VECTOR")
    self.assertIs(type(radar_udm["security_result"][1]["confidence_score"]), float)

    macro_logs_payload = self.macro_ingest.build_import_logs_payload([radar_udm])
    self.assertEqual(macro_logs_payload["log_type"], "UDM")
    decoded_macro_udm = json.loads(
        base64.b64decode(macro_logs_payload["inline_source"]["logs"][0]["data"]).decode("utf-8")
    )
    self.assertEqual(decoded_macro_udm["metadata"]["product_name"], "SecOps Risk Metrics Hunter")

    # 3B. Micro: secops-statistical-hunter/scripts/clean_handoff.py
    self.assertEqual(
        tuple(self.micro_clean_handoff.CANONICAL_PRODUCT_EVENT_TYPES),
        EXPECTED_MICRO_PRODUCT_EVENT_TYPES,
    )
    for pet in EXPECTED_MICRO_PRODUCT_EVENT_TYPES:
      ev = self.micro_clean_handoff.build_synthetic_udm_event(
          product_event_type=pet,
          entity_id="charles.hardy",
          entity_type="USER",
          statistical_model="Modified Z-Score (MAD)",
          z_score=5.25,
          cri_score=79,
          observed_value=640,
          historical_mean=110.0,
          historical_stddev=80.0,
          summary="Cross-skill D7 write-back characterization check.",
          hunt_campaign_id="hunt-ws002",
          event_timestamp="2026-10-29T12:00:00Z",
      )
      self.assertEqual(set(ev.keys()), {"udm"})
      self.assertEqual(self.micro_clean_handoff.validate_clean_handoff_udm(ev), [])
      udm = ev["udm"]
      self.assertEqual(udm["metadata"]["product_name"], "SecOps Statistical Hunter")
      self.assertEqual(udm["metadata"]["vendor_name"], "Google SecOps")
      self.assertEqual(udm["metadata"]["product_event_type"], pet)
      self.assertEqual(
          udm["target"]["resource"]["resource_type"], "RESOURCE_TYPE_UNSPECIFIED"
      )
      sr0 = udm["security_result"][0]
      self.assertIs(type(sr0["risk_score"]), int)
      self.assertIs(type(sr0["confidence_score"]), float)
      self.assertIs(type(sr0["severity"]), str)

    sample_batch = self.micro_clean_handoff.build_multi_event_batch(
        [
            {
                "product_event_type": "C2_BEACONING_JITTER",
                "entity_id": "wkstn-prod-042",
                "entity_type": "HOSTNAME",
                "statistical_model": "CV Jitter",
                "z_score": 4.5,
                "cri_score": 71,
                "observed_value": 0.08,
                "historical_mean": 0.50,
                "historical_stddev": 0.12,
                "summary": "Periodic beacon detected.",
                "event_timestamp": "2026-10-29T12:00:00Z",
            }
        ],
        hunt_campaign_id="hunt-ws002-batch",
    )
    import_args = self.micro_clean_handoff.prepare_chronicle_import_logs_args(
        batch=sample_batch,
        customer_id="8cbac5ae-8267-4da7-b405-cdbc6fa3f1d5",
        project_id="gus-sdl",
        region="us",
        forwarder_id="fwd-ws002",
    )
    mcp_args = import_args["mcp_import_logs_args"]
    self.assertEqual(mcp_args["log_type"], "UDM")
    self.assertEqual(mcp_args["forwarderId"], "fwd-ws002")
    self.assertIsInstance(mcp_args["logs"], list)
    unwrapped = json.loads(mcp_args["logs"][0])
    self.assertEqual(unwrapped, {"events": [{"event": sample_batch[0]["udm"]}]})

  def test_contract_4_byte_identical_canonical_routing_table_and_zero_ping_pong(self) -> None:
    """Contract 4 (WS8-02): SHA-256 identity of canonical routing table across all 3 locations and zero ping-pong."""
    assert self.macro_root is not None and self.micro_root is not None
    macro_table = _extract_canonical_routing_table(
        (self.macro_root / "SKILL.md").read_text(encoding="utf-8")
    )
    micro_table = _extract_canonical_routing_table(
        (self.micro_root / "SKILL.md").read_text(encoding="utf-8")
    )
    builder_table = self.micro_mqb.CANONICAL_ROUTING_TABLE_MD

    h_macro = _sha256_bytes(macro_table.encode("utf-8"))
    h_micro = _sha256_bytes(micro_table.encode("utf-8"))
    h_builder = _sha256_bytes(builder_table.encode("utf-8"))
    self.assertEqual(h_macro, h_micro, "Routing table drifted between macro and micro SKILL.md")
    self.assertEqual(h_macro, h_builder, "Routing table drifted from CANONICAL_ROUTING_TABLE_MD")

    check_route = self.micro_mqb.check_routing_recommendation
    precedence_1_micro_prompts = [
        "Use UEBA to detect C2 beaconing jitter",
        "Detect off-hours circadian login anomalies by hour of day using UEBA",
        "Run MAD on raw DNS query string length",
        "Detect obfuscated PowerShell command lines with Shannon character entropy",
        "Use UEBA to detect Markov 2-gram rare parent-child process transitions over 30 days",
        "Hunt intraday EWMA burst velocity using UEBA",
    ]
    for prompt in precedence_1_micro_prompts:
      self.assertIsNone(
          check_route(prompt),
          f"Precedence-1 micro prompt must stay in statistical-hunter without ping-pong: {prompt}",
      )

    macro_templates_on_disk = {
        p.name for p in (self.macro_root / "templates" / "pipelines").glob("*.yl2")
    }
    precedence_2_macro_prompts = [
        ("Run 30-day login baseline for charles.hardy", "standard_z_score_2stage.yl2"),
        ("Compare user against IT department peer cohort", "dual_baseline_delta_z_3stage.yl2"),
        ("Run 360 entity health check and risk score", "radar_360_decoupled_sector.yl2"),
        ("Detect 14-day longitudinal CUSUM exfiltration drift", "longitudinal_cusum_series_3stage.yl2"),
        ("Run 30-day MAD baseline on metrics.network_bytes_outbound", "mad_robust_z_4stage.yl2"),
        ("Evaluate 30-day metrics.auth_attempts_total first_seen novelty", "first_seen_novelty_2stage.yl2"),
    ]
    for prompt, expected_pipeline in precedence_2_macro_prompts:
      rec = check_route(prompt)
      self.assertIsNotNone(rec, f"Expected Precedence-2 macro delegation for: {prompt}")
      self.assertEqual(rec["target_skill"], MACRO_SKILL_NAME)
      self.assertEqual(rec["recommended_pipeline"], expected_pipeline)
      self.assertIn(rec["recommended_pipeline"], macro_templates_on_disk)

  def test_contract_5_identical_fusion_maturity_and_writeback_thresholds(self) -> None:
    """Contract 5 (WS2-08, D8): Pins identical Z, fusion, radar, write-back, loopback, and maturity thresholds."""
    mc_macro = self.macro_constants
    mc_micro = self.micro_constants

    # 1. Default Z threshold == 3.0
    macro_z = getattr(mc_macro, "DEFAULT_Z_THRESHOLD", mc_macro.DEFAULT_ANOMALY_THRESHOLD)
    micro_z = getattr(mc_micro, "DEFAULT_Z_THRESHOLD", mc_micro.DEFAULT_ANOMALY_THRESHOLD)
    self.assertEqual(macro_z, 3.0)
    self.assertEqual(micro_z, 3.0)
    self.assertEqual(mc_macro.SENSITIVITY_THRESHOLD_MAP["BALANCED"]["anomaly_threshold"], 3.0)
    self.assertEqual(mc_micro.SENSITIVITY_THRESHOLD_MAP["BALANCED"]["anomaly_threshold"], 3.0)
    self.assertEqual(self.macro_router.DEFAULT_ANOMALY_THRESHOLD, 3.0)
    self.assertEqual(self.micro_mqb.DEFAULT_ANOMALY_THRESHOLD, 3.0)

    # 2. Default Fusion threshold == 3.5 & squared == 12.25
    self.assertEqual(mc_macro.DEFAULT_FUSION_THRESHOLD_SQ, 12.25)
    self.assertEqual(mc_micro.DEFAULT_FUSION_THRESHOLD_SQ, 12.25)
    macro_fusion = getattr(
        mc_macro, "DEFAULT_FUSION_THRESHOLD", math.sqrt(mc_macro.DEFAULT_FUSION_THRESHOLD_SQ)
    )
    micro_fusion = getattr(
        mc_micro, "DEFAULT_FUSION_THRESHOLD", math.sqrt(mc_micro.DEFAULT_FUSION_THRESHOLD_SQ)
    )
    self.assertEqual(macro_fusion, 3.5)
    self.assertEqual(micro_fusion, 3.5)
    self.assertEqual(mc_macro.SENSITIVITY_THRESHOLD_MAP["BALANCED"]["fusion_threshold_sq"], 12.25)
    self.assertEqual(mc_micro.SENSITIVITY_THRESHOLD_MAP["BALANCED"]["fusion_threshold_sq"], 12.25)
    self.assertEqual(self.macro_router.DEFAULT_FUSION_THRESHOLD_SQ, 12.25)
    self.assertEqual(self.micro_mqb.DEFAULT_FUSION_THRESHOLD_SQ, 12.25)

    # 3. Radar fusion & composite D thresholds (3.0 vs 3.5)
    self.assertEqual(mc_macro.RADAR_FUSION_DISTANCE_THRESHOLD, 3.0)
    self.assertEqual(mc_micro.RADAR_FUSION_DISTANCE_THRESHOLD, 3.0)
    self.assertEqual(self.macro_radar.RADAR_FUSION_DISTANCE_THRESHOLD, 3.0)
    self.assertEqual(self.micro_mqb.RADAR_FUSION_DISTANCE_THRESHOLD, 3.0)

    self.assertEqual(mc_macro.RADAR_COMPOSITE_D_THRESHOLD, 3.5)
    self.assertEqual(mc_micro.RADAR_COMPOSITE_D_THRESHOLD, 3.5)
    self.assertEqual(self.macro_radar.RADAR_COMPOSITE_D_THRESHOLD, 3.5)
    self.assertEqual(self.micro_mqb.RADAR_COMPOSITE_D_THRESHOLD, 3.5)

    # 4. Write-back CRI threshold == 50
    self.assertEqual(mc_macro.WRITEBACK_CRI_THRESHOLD, 50)
    self.assertEqual(mc_micro.WRITEBACK_CRI_THRESHOLD, 50)
    self.assertEqual(self.macro_hybrid.WRITEBACK_CRI_THRESHOLD, 50)
    self.assertEqual(self.micro_mqb.WRITEBACK_CRI_THRESHOLD, 50)

    # 5. Loopback composite sum(Z^2) == 25.0 & min distinct hits == 2
    self.assertEqual(mc_macro.LOOPBACK_COMPOSITE_SUM_Z_SQ_THRESHOLD, 25.0)
    self.assertEqual(mc_micro.LOOPBACK_COMPOSITE_SUM_Z_SQ_THRESHOLD, 25.0)
    self.assertEqual(self.macro_hybrid.LOOPBACK_COMPOSITE_SUM_Z_SQ_THRESHOLD, 25.0)
    self.assertEqual(self.micro_mqb.LOOPBACK_COMPOSITE_SUM_Z_SQ_THRESHOLD, 25.0)

    self.assertEqual(mc_macro.LOOPBACK_MIN_DISTINCT_HITS, 2)
    self.assertEqual(mc_micro.LOOPBACK_MIN_DISTINCT_HITS, 2)
    self.assertEqual(self.macro_hybrid.LOOPBACK_MIN_DISTINCT_HITS, 2)
    self.assertEqual(self.micro_mqb.LOOPBACK_MIN_DISTINCT_HITS, 2)

    # 6. Default baseline maturity floor == 7 days
    self.assertEqual(mc_macro.DEFAULT_MIN_BASELINE_DAYS, 7)
    self.assertEqual(mc_micro.DEFAULT_MIN_BASELINE_DAYS, 7)
    self.assertEqual(self.macro_hybrid.DEFAULT_MIN_BASELINE_DAYS, 7)
    self.assertEqual(self.macro_radar.DEFAULT_MIN_BASELINE_DAYS, 7)
    self.assertEqual(self.macro_router.DEFAULT_MIN_BASELINE_DAYS, 7)
    self.assertEqual(self.micro_mqb.DEFAULT_MIN_BASELINE_DAYS, 7)


if __name__ == "__main__":
  unittest.main()
