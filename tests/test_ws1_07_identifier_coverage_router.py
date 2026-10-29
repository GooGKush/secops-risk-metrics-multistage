"""Regression & unit tests for WS1-07 (D4, Macro Side): Identifier Coverage Probe & Router Choice."""

from __future__ import annotations

import unittest

import scripts.template_router as tr
from scripts.preflight_validator import (
    EntityType,
    MalachiteASTValidator,
    PipelineArchitecture,
    StatisticalModel,
)
from scripts.template_router import MultiStageTemplateRouter
from scripts.ueba_hybrid_engine import UEBAHybridEngine


class TestWS107IdentifierCoverageRouter(unittest.TestCase):
  """Verifies D4 Turn-1 identifier coverage probe, router field selection, and ASSET bridge rule."""

  def setUp(self) -> None:
    self.router = MultiStageTemplateRouter()
    self.engine = UEBAHybridEngine()
    # V-live / PF-9 gus-sdl network coverage profile: < 1% hostname, ~99.96% IP.
    self.gus_sdl_sparse_hostname_payload = {
        "stats": {
            "results": [
                {"column": "total_events", "values": [{"value": {"int64Val": "11004"}}]},
                {"column": "hostname_events", "values": [{"value": {"int64Val": "4"}}]},
                {"column": "distinct_hostnames", "values": [{"value": {"int64Val": "2"}}]},
                {"column": "distinct_ips", "values": [{"value": {"int64Val": "148"}}]},
            ]
        }
    }
    self.edr_rich_hostname_payload = {
        "stats": {
            "results": [
                {"column": "total_events", "values": [{"value": {"int64Val": "10000"}}]},
                {"column": "hostname_events", "values": [{"value": {"int64Val": "9400"}}]},
                {"column": "distinct_hostnames", "values": [{"value": {"int64Val": "310"}}]},
                {"column": "distinct_ips", "values": [{"value": {"int64Val": "325"}}]},
            ]
        }
    }

  def test_coverage_probe_generator_validates_for_dns_http_and_network(self) -> None:
    self.assertTrue(hasattr(tr, "build_identifier_coverage_probe"))
    for metric in ("dns_queries_total", "http_queries_total", "network_bytes_outbound"):
      probe_q = tr.build_identifier_coverage_probe(metric, entity_type=EntityType.ASSET)
      self.assertEqual(MalachiteASTValidator.validate_query(probe_q), [], msg=metric)
      self.assertIn("principal.asset.hostname", probe_q)
      self.assertIn("principal.asset.ip", probe_q)

  def test_select_identifier_from_coverage_picks_ip_on_gus_sdl_and_hostname_when_populated(self) -> None:
    self.assertTrue(hasattr(tr, "select_identifier_from_coverage"))
    for metric in ("dns_queries_total", "http_queries_total", "network_bytes_outbound"):
      chosen_ip = tr.select_identifier_from_coverage(
          self.gus_sdl_sparse_hostname_payload,
          target_metric=metric,
          entity_type=EntityType.ASSET,
      )
      self.assertEqual(chosen_ip, "principal.asset.ip", msg=metric)

      chosen_host = tr.select_identifier_from_coverage(
          self.edr_rich_hostname_payload,
          target_metric=metric,
          entity_type=EntityType.ASSET,
      )
      self.assertEqual(chosen_host, "principal.asset.hostname", msg=metric)

    # Also supports raw udm_search events payload where only principal.asset.ip is populated
    raw_events_payload = {
        "events": [
            {"udm": {"principal": {"asset": {"ip": ["10.10.4.21"]}}}},
            {"udm": {"principal": {"asset": {"ip": ["10.10.4.22"]}}}},
        ]
    }
    self.assertEqual(
        tr.select_identifier_from_coverage(
            raw_events_payload,
            target_metric="dns_queries_total",
            entity_type=EntityType.ASSET,
        ),
        "principal.asset.ip",
    )

  def test_router_and_engine_rebind_dns_http_and_ecg_templates_from_coverage_payload(self) -> None:
    # 1. Stage1 + Stage2 DNS & HTTP queries auto-switch to principal.asset.ip
    for metric in ("dns_queries_total", "dns_queries_fail", "http_queries_total", "http_queries_fail"):
      q = self.router.build_query(
          target_metric=metric,
          entity_type=EntityType.ASSET,
          statistical_model=StatisticalModel.STANDARD_Z_SCORE,
          identifier_coverage_payload=self.gus_sdl_sparse_hostname_payload,
      )
      self.assertEqual(MalachiteASTValidator.validate_query(q), [], msg=metric)
      self.assertIn("principal.asset.ip", q)
      self.assertNotIn("principal.asset.hostname", q)

    # 2. Domain prevalence & WHOIS & rare-destination ECG pipelines rebind cleanly to principal.asset.ip
    for pipe in (
        PipelineArchitecture.HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE,
        PipelineArchitecture.HYBRID_METRIC_WHOIS_DOMAIN_LIFECYCLE_2STAGE,
        PipelineArchitecture.RARE_DESTINATION_ECG_3STAGE,
        PipelineArchitecture.HTTP_ERROR_RATIO_SURGE_2STAGE,
    ):
      pq = self.router.build_pipeline_query(
          pipe,
          target_metric="http_queries_fail" if pipe == PipelineArchitecture.HTTP_ERROR_RATIO_SURGE_2STAGE else "http_queries_total",
          entity_type=EntityType.ASSET,
          identifier_coverage_payload=self.gus_sdl_sparse_hostname_payload,
      )
      self.assertEqual(MalachiteASTValidator.validate_query(pq), [], msg=pipe.value)
      self.assertIn("principal.asset.ip", pq, msg=pipe.value)
      self.assertNotIn("principal.asset.hostname =", pq, msg=pipe.value)

    # 3. Engine compile_hunt_pipeline threads identifier_coverage_payload end-to-end
    compiled = self.engine.compile_hunt_pipeline(
        statistical_model="STANDARD_Z_SCORE",
        metrics=["dns_queries_total"],
        entity_type="ASSET",
        identifier_coverage_payload=self.gus_sdl_sparse_hostname_payload,
    )
    self.assertEqual(compiled["status"], "COMPILED")
    self.assertEqual(compiled["target_field"], "principal.asset.ip")
    self.assertIn("principal.asset.ip", compiled["compiled_query"])

  def test_cross_identifier_host_to_ip_join_requires_asset_context_bridge(self) -> None:
    # Direct cross-identifier join without ASSET context must be rejected
    unbridged_query = (
        "// Goal: Invalid direct hostname-to-IP join\n"
        "stage s_host {\n"
        '    metadata.event_type = "PROCESS_LAUNCH"\n'
        "    principal.asset.hostname = $entity\n"
        '    $entity != ""\n'
        "  match:\n"
        "    $entity by 1d\n"
        "  outcome:\n"
        "    $c1 = count(metadata.id)\n"
        "}\n"
        "stage s_ip {\n"
        '    (network.dns.questions.name != "" or network.dns.answers.name != "" or network.dns.id != 0)\n'
        "    principal.asset.ip = $entity\n"
        '    $entity != ""\n'
        "  match:\n"
        "    $entity by 1d\n"
        "  outcome:\n"
        "    $c2 = count(metadata.id)\n"
        "}\n"
        "$entity = $s_host.entity\n"
        "$entity = $s_ip.entity\n"
        "match:\n"
        "  $entity by 1d\n"
        "outcome:\n"
        "  $tot = max($s_host.c1) + max($s_ip.c2)\n"
        "order:\n"
        "  $tot desc\n"
    )
    errs = MalachiteASTValidator.validate_query(unbridged_query)
    self.assertTrue(
        any("UNBRIDGED_CROSS_IDENTIFIER_JOIN" in e for e in errs),
        f"Expected UNBRIDGED_CROSS_IDENTIFIER_JOIN error, got: {errs}",
    )

    # Bridged join via ASSET context compiles and passes AST validation cleanly
    self.assertTrue(hasattr(self.router, "build_bridged_host_ip_fusion_query"))
    bridged_q = self.router.build_bridged_host_ip_fusion_query(
        hostname_metric="auth_attempts_total",
        ip_metric="dns_queries_total",
    )
    self.assertEqual(MalachiteASTValidator.validate_query(bridged_q), [])
    self.assertIn('"ASSET"', bridged_q)
    self.assertIn("entity.asset.hostname", bridged_q)
    self.assertIn("entity.asset.ip", bridged_q)


if __name__ == "__main__":
  unittest.main()
