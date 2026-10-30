"""WS4-SERIOUS-EXTRACTORS regression tests for domain pipelines and Stage-1 extractors."""

from pathlib import Path
import re
import unittest

from scripts import malachite_catalog as mc
from scripts.preflight_validator import (
    EntityType,
    MalachiteASTValidator,
    PipelineArchitecture,
    StatisticalModel,
)
from scripts.statistical_validator import StatisticalAntipatternAuditor
from scripts.template_router import ChainedHuntRouter, MultiStageTemplateRouter

SKILL_ROOT = Path(__file__).resolve().parent.parent


class TestWS4SeriousExtractors(unittest.TestCase):

  def setUp(self):
    self.router = MultiStageTemplateRouter()

  def test_ws4_cloud_repository_scope_principals_4crud_origin_and_branch_maturity(self):
    q = self.router.build_cloud_repository_scope_query()
    self.assertEqual(MalachiteASTValidator.validate_query(q), [])
    self.assertEqual(StatisticalAntipatternAuditor.audit_query(q), [])

    # Principal regex covers GCP SA, AWS IAM/STS (incl. cn/us-gov), Azure UUIDs, and human UPNs/emails
    m_re = re.search(r"\$sa\s*=\s*/([^/]+)/\s*nocase", q)
    self.assertIsNotNone(m_re, "Expected broadened cloud principal regex in fleet mode")
    py_re = re.compile(m_re.group(1), re.I)
    for valid_principal in (
        "svc-bq@prod-project.iam.gserviceaccount.com",
        "arn:aws:iam::123456789012:role/AdminRole",
        "arn:aws-us-gov:sts::123456789012:assumed-role/Ops/session",
        "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "alice.hunter@corp.example.com",
        "devops@contoso.onmicrosoft.com",
    ):
      self.assertRegex(valid_principal, py_re)

    # Machine/local OS accounts are explicitly excluded
    self.assertIn(r"not re.regex($sa, `(?i)^(system|local service|network service|.*\$$)`)", q)

    # Human email principal passed explicitly via service_account passes auditor with 0 violations
    q_human = self.router.build_cloud_repository_scope_query(service_account="alice@corp.example.com")
    self.assertIn('$sa = "alice@corp.example.com"', q_human)
    self.assertEqual(MalachiteASTValidator.validate_query(q_human), [])
    self.assertEqual(StatisticalAntipatternAuditor.audit_query(q_human), [])

    # All 4 CRUD branches carry num_metric_periods maturity checks on BOTH destination and origin IP
    for crud_metric in (
        "resource_read_total",
        "resource_written_total",
        "resource_deletion_total",
        "resource_creation_total",
    ):
      # At least 2 num_metric_periods calls per CRUD family: 1 for destination resource, 1 for caller origin IP
      calls = re.findall(
          rf"metrics\.{crud_metric}\([^)]*agg:\s*num_metric_periods",
          q,
          flags=re.S,
      )
      self.assertGreaterEqual(
          len(calls),
          2,
          f"Expected both destination and origin IP num_metric_periods for {crud_metric}",
      )

    # Creation surge (+50 sigma) when 1 <= read_days < 7 and create_days >= 7 must NOT be dropped by root condition
    self.assertNotIn("$dest_days >= 7 or $dest_days = 0", q)
    self.assertIn("$create_z = if($create_days >= 7 and $create_raw > 0.0, $create_raw, 0.0)", q)

  def test_ws4_derived_and_rare_destination_maturity_tuning_and_child_sha256(self):
    # 1. Derived File Prevalence: child target.process.file.sha256 with fallback, maturity gate, tunable prevalence
    q_file = self.router.build_hybrid_derived_file_prevalence_query(
        anomaly_threshold=4.2,
        min_baseline_days=10,
        max_fleet_prevalence=5,
    )
    self.assertEqual(MalachiteASTValidator.validate_query(q_file), [])
    self.assertIn("strings.coalesce(target.process.file.sha256, principal.process.file.sha256)", q_file)
    self.assertIn("$active_baseline_days >= 10", q_file)
    self.assertIn("rolling_max <= 5", q_file)
    self.assertIn("$fleet_prevalence <= 5", q_file)
    self.assertIn("first_seen", q_file)  # documents WS1-12 first_seen novelty path for Day-0 binaries

    # 2. Derived Domain Prevalence: maturity gate, tunable prevalence, reverse-DNS/mDNS filter
    q_dom = self.router.build_hybrid_derived_domain_prevalence_query(
        anomaly_threshold=3.8,
        min_baseline_days=9,
        max_fleet_prevalence=6,
    )
    self.assertEqual(MalachiteASTValidator.validate_query(q_dom), [])
    self.assertIn("$active_baseline_days >= 9", q_dom)
    self.assertIn("rolling_max <= 6", q_dom)
    self.assertIn("$fleet_prevalence <= 6", q_dom)
    self.assertIn(r"(?i)\.(in-addr\.arpa|ip6\.arpa|local)$", q_dom)

    # 3. Fleet Prevalence: tunable max_fleet_prevalence and max_fleet_adopters
    q_fleet = self.router.build_hybrid_fleet_prevalence_query(
        anomaly_threshold=3.5,
        min_baseline_days=8,
        max_fleet_prevalence=7,
        max_fleet_adopters=4,
    )
    self.assertEqual(MalachiteASTValidator.validate_query(q_fleet), [])
    self.assertIn("rolling_max <= 7", q_fleet)
    self.assertIn("$fleet_adopters <= 4", q_fleet)
    self.assertIn("$active_baseline_days >= 8", q_fleet)

    # 4. HTTP UA Prevalence & HTTP Target Surge: tunable thresholds + maturity gates + no "& BEACONING" claim
    q_ua = self.router.build_pipeline_query(
        PipelineArchitecture.HYBRID_METRIC_HTTP_UA_PREVALENCE_2STAGE,
        anomaly_threshold=3.2,
        min_baseline_days=8,
        max_fleet_adopters=4,
    )
    self.assertEqual(MalachiteASTValidator.validate_query(q_ua), [])
    self.assertIn("$active_baseline_days >= 8", q_ua)
    self.assertIn("$personal_z >= 3.2", q_ua)
    self.assertIn("$fleet_adopters <= 4", q_ua)

    q_ts = self.router.build_pipeline_query(
        PipelineArchitecture.HTTP_TARGET_SURGE_2STAGE,
        anomaly_threshold=3.5,
        min_baseline_days=9,
        max_fleet_prevalence=5,
    )
    self.assertEqual(MalachiteASTValidator.validate_query(q_ts), [])
    self.assertNotIn("BEACONING PIPELINE", q_ts.upper())
    self.assertIn("$active_baseline_days >= 9", q_ts)
    self.assertIn("$target_z >= 3.5", q_ts)
    self.assertIn("$connecting_fleet_hosts <= 5", q_ts)
    self.assertIn(r"(?i)\.(in-addr\.arpa|ip6\.arpa|local)$", q_ts)

    # 5. Rare Destination ECG & Fusion Rare Destination: maturity gates, reverse-DNS/mDNS filter, sector-Z scope note
    q_rare = self.router.build_rare_destination_ecg_query(
        target_metric="network_bytes_outbound",
        anomaly_threshold=3.5,
        min_baseline_days=7,
        max_fleet_prevalence=4,
    )
    self.assertEqual(MalachiteASTValidator.validate_query(q_rare), [])
    self.assertIn("rolling_max <= 4", q_rare)
    self.assertIn(r"not re.regex($dest, `(?i)\.(in-addr\.arpa|ip6\.arpa|local)$`)", q_rare)
    self.assertIn("agg: num_metric_periods", q_rare)
    self.assertIn("host-wide sector", q_rare.lower())

    q_frare = self.router.build_fusion_rare_destination_query(
        min_baseline_days=7,
        max_fleet_prevalence=4,
    )
    self.assertEqual(MalachiteASTValidator.validate_query(q_frare), [])
    self.assertIn("rolling_max <= 4", q_frare)
    self.assertGreaterEqual(len(re.findall(r"agg:\s*num_metric_periods", q_frare)), 2)
    self.assertIn(r"not re.regex($dest, `(?i)\.(in-addr\.arpa|ip6\.arpa|local)$`)", q_frare)

  def test_ws4_destination_diversity_concentration_rename_and_calibrated_gates(self):
    q = self.router.build_hybrid_entropy_concentration_query(
        target_metric="network_bytes_outbound",
        entity_type=EntityType.ASSET,
        anomaly_threshold=3.0,
    )
    self.assertEqual(MalachiteASTValidator.validate_query(q), [])
    self.assertIn("DESTINATION DIVERSITY & CONCENTRATION SCREEN", q.upper())
    self.assertNotIn("ENTROPY & CONCENTRATION PIPELINE", q.upper())
    self.assertNotIn("HHI", q)
    # Calibrated default micro gates so a routine host with 5-10 events isn't flagged automatically
    self.assertIn("$raw_events >= 25", q)
    self.assertIn("$diversity_ratio <= 0.05", q)
    self.assertIn("$concentration_ratio >= 0.85", q)
    self.assertIn("$active_baseline_days >= 7", q)

  def test_ws4_data_table_bridge_canonical_entity_column(self):
    tpl = (SKILL_ROOT / "templates" / "pipelines" / "hybrid_data_table_bridge_2stage.yl2").read_text(encoding="utf-8")
    self.assertIn("%ueba_hunt_bridge.entity", tpl)
    self.assertNotIn("%ueba_hunt_bridge.hostname", tpl)
    self.assertEqual(MalachiteASTValidator.validate_query(tpl), [])

    q_user = ChainedHuntRouter.build_data_table_bridge_query(
        entity_type=EntityType.USER,
        target_metric="workspace_total_download_actions",
    )
    self.assertIn("in %ueba_hunt_bridge.entity", q_user)
    self.assertEqual(MalachiteASTValidator.validate_query(q_user), [])

  def test_ws4_stage1_extractors_per_branch_1e15_clamp_and_gmail_case_insensitivity(self):
    # 1. network_bytes_total & workspace_network_bytes_total clamp BOTH branches individually before summing
    for metric_name in ("network_bytes_total", "workspace_network_bytes_total"):
      ext = (SKILL_ROOT / "templates" / "stage1_extractors" / f"{metric_name}.yl2").read_text(encoding="utf-8")
      sem = mc.baseline_semantics(metric_name)
      self.assertIn(
          "sum(if(network.sent_bytes > 0 and network.sent_bytes < 1000000000000000, 1.0, 0.0) * network.sent_bytes)",
          ext,
      )
      self.assertIn(
          "sum(if(network.received_bytes > 0 and network.received_bytes < 1000000000000000, 1.0, 0.0) * network.received_bytes)",
          ext,
      )
      self.assertEqual(ext.count("1000000000000000") >= 4, True, metric_name)
      self.assertIn("1000000000000000", sem.observed_agg)

    # 2. dns_bytes_outbound & workspace_network_bytes_outbound clamp sent_bytes < 1e15
    for metric_name in ("dns_bytes_outbound", "workspace_network_bytes_outbound"):
      ext = (SKILL_ROOT / "templates" / "stage1_extractors" / f"{metric_name}.yl2").read_text(encoding="utf-8")
      sem = mc.baseline_semantics(metric_name)
      self.assertIn("network.sent_bytes < 1000000000000000", ext, metric_name)
      self.assertIn("network.sent_bytes < 1000000000000000", sem.observed_filter, metric_name)

    # 3. All 3 Workspace Gmail extractors match Gmail case-insensitively and check sent_bytes > 0 for emails_sent
    for metric_name in (
        "workspace_emails_sent_total",
        "workspace_network_bytes_outbound",
        "workspace_network_bytes_total",
    ):
      ext = (SKILL_ROOT / "templates" / "stage1_extractors" / f"{metric_name}.yl2").read_text(encoding="utf-8")
      sem = mc.baseline_semantics(metric_name)
      self.assertIn("re.regex(metadata.product_name, `(?i)^gmail$`)", ext, metric_name)
      self.assertNotIn('metadata.product_name = "GMAIL"', ext, metric_name)
      self.assertIn("re.regex(metadata.product_name, `(?i)^gmail$`)", sem.observed_filter, metric_name)

    emails_ext = (SKILL_ROOT / "templates" / "stage1_extractors" / "workspace_emails_sent_total.yl2").read_text(
        encoding="utf-8"
    )
    self.assertIn("network.sent_bytes > 0", emails_ext)

    # Render full queries for all 5 updated metrics to confirm MalachiteASTValidator passes cleanly
    for m, et in (
        ("network_bytes_total", EntityType.ASSET),
        ("dns_bytes_outbound", EntityType.ASSET),
        ("workspace_emails_sent_total", EntityType.USER),
        ("workspace_network_bytes_outbound", EntityType.USER),
        ("workspace_network_bytes_total", EntityType.USER),
    ):
      q = self.router.build_query(m, et, StatisticalModel.STANDARD_Z_SCORE)
      self.assertEqual(MalachiteASTValidator.validate_query(q), [], m)


if __name__ == "__main__":
  unittest.main()
