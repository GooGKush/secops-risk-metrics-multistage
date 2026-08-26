# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Smoke tests for Global Context (GCTI, Safe Browsing, WHOIS) + Risk Metrics multi-stage queries."""

import re
import unittest


class GlobalContextMultiStageSyntaxTest(unittest.TestCase):
  """Validates grammar and AST requirements for Global Context + Risk Metrics multi-stage queries."""

  def test_query_1_whois_nrd_egress_surge(self):
    query = """
    stage stage_nrd_egress {
        $net.metadata.event_type = "NETWORK_CONNECTION"
        $net.target.hostname = $domain
        $net.principal.asset.hostname = $host
        $domain != ""
        $host != ""

        $whois.graph.entity.domain.name = $domain
        $whois.graph.metadata.entity_type = "DOMAIN_NAME"
        $whois.graph.metadata.vendor_name = "WHOIS"
        $whois.graph.metadata.product_name = "WHOISXMLAPI Simple Whois"
        $whois.graph.metadata.source_type = "GLOBAL_CONTEXT"
        $whois.graph.entity.domain.creation_time.seconds > 0
        2592000 > timestamp.current_seconds() - $whois.graph.entity.domain.creation_time.seconds

      match:
        $host

      outcome:
        $nrd_bytes_obs = sum($net.network.sent_bytes)
        $nrd_domain_count = count_distinct($domain)

        $net_mu = max(metrics.network_bytes_outbound(
            period: 1d, window: 30d, metric: value_sum, agg: avg,
            principal.asset.hostname: $host
        ))
        $net_sigma = max(metrics.network_bytes_outbound(
            period: 1d, window: 30d, metric: value_sum, agg: stddev,
            principal.asset.hostname: $host
        ))
    }

    $host = $stage_nrd_egress.host

    match:
      $host

    outcome:
      $observed_bytes = max($stage_nrd_egress.nrd_bytes_obs)
      $distinct_nrds = max($stage_nrd_egress.nrd_domain_count)
      $avg_bytes = max($stage_nrd_egress.net_mu)
      $std_bytes = max($stage_nrd_egress.net_sigma)

      $z_egress = ($observed_bytes - $avg_bytes) / ($std_bytes + 1.0)
      $threat_score = $z_egress * $z_egress

    order:
      $threat_score desc
    """
    self.assertIn('$whois.graph.metadata.source_type = "GLOBAL_CONTEXT"', query)
    self.assertIn("metrics.network_bytes_outbound", query)
    self.assertNotIn("condition:", query)

  def test_query_2_whois_expired_domain_hijacking(self):
    query = """
    stage stage_expired_domain_access {
        $access.metadata.event_type = "NETWORK_HTTP"
        $access.target.hostname = $domain
        $access.principal.asset.hostname = $host
        $domain != ""
        $host != ""

        $whois.graph.entity.domain.name = $domain
        $whois.graph.metadata.entity_type = "DOMAIN_NAME"
        $whois.graph.metadata.vendor_name = "WHOIS"
        $whois.graph.metadata.product_name = "WHOISXMLAPI Simple Whois"
        $whois.graph.metadata.source_type = "GLOBAL_CONTEXT"
        $whois.graph.entity.domain.expiration_time.seconds < $access.metadata.event_timestamp.seconds

      match:
        $host

      outcome:
        $expired_http_obs = count($access.metadata.id)

        $http_mu = max(metrics.http_queries_total(
            period: 1d, window: 30d, metric: event_count_sum, agg: avg,
            principal.asset.hostname: $host
        ))
        $http_sigma = max(metrics.http_queries_total(
            period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
            principal.asset.hostname: $host
        ))
    }

    $host = $stage_expired_domain_access.host

    match:
      $host

    outcome:
      $obs_queries = max($stage_expired_domain_access.expired_http_obs)
      $avg_queries = max($stage_expired_domain_access.http_mu)
      $std_queries = max($stage_expired_domain_access.http_sigma)

      $z_http = ($obs_queries - $avg_queries) / ($std_queries + 1.0)

    order:
      $z_http desc
    """
    self.assertIn('$whois.graph.metadata.source_type = "GLOBAL_CONTEXT"', query)
    self.assertIn("metrics.http_queries_total", query)
    self.assertNotIn("condition:", query)

  def test_query_3_gcti_rat_process_burst(self):
    query = """
    stage stage_gcti_rat_execution {
        $process.metadata.event_type = "PROCESS_LAUNCH"
        $process.target.process.file.sha256 = $rat_hash
        $process.principal.asset.hostname = $host
        $rat_hash != ""
        $host != ""

        $gcti.graph.entity.file.sha256 = $rat_hash
        $gcti.graph.metadata.entity_type = "FILE"
        $gcti.graph.metadata.vendor_name = "Google Cloud Threat Intelligence"
        $gcti.graph.metadata.product_name = "GCTI Feed"
        $gcti.graph.metadata.threat.threat_feed_name = "Remote Access Tools"
        $gcti.graph.metadata.source_type = "GLOBAL_CONTEXT"

      match:
        $host

      outcome:
        $rat_launch_obs = count($process.metadata.id)

        $proc_mu = max(metrics.file_executions_total(
            period: 1d, window: 30d, metric: event_count_sum, agg: avg,
            principal.asset.hostname: $host
        ))
        $proc_sigma = max(metrics.file_executions_total(
            period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
            principal.asset.hostname: $host
        ))
    }

    $host = $stage_gcti_rat_execution.host

    match:
      $host

    outcome:
      $rat_count = max($stage_gcti_rat_execution.rat_launch_obs)
      $avg_procs = max($stage_gcti_rat_execution.proc_mu)
      $std_procs = max($stage_gcti_rat_execution.proc_sigma)

      $z_rat = ($rat_count - $avg_procs) / ($std_procs + 1.0)
      $threat_score = $z_rat * 2.0

    order:
      $threat_score desc
    """
    self.assertIn('$gcti.graph.metadata.threat.threat_feed_name = "Remote Access Tools"', query)
    self.assertIn("metrics.file_executions_total", query)
    self.assertNotIn("condition:", query)

  def test_query_4_safebrowsing_dwell_and_egress_fusion(self):
    query = """
    stage stage_safebrowsing_dwell {
        $proc.metadata.event_type = "PROCESS_LAUNCH"
        $proc.target.process.file.sha256 = $sha256
        $proc.principal.asset.hostname = $host
        $sha256 != ""
        $host != ""

        $safebrowse.graph.entity.file.sha256 = $sha256
        $safebrowse.graph.metadata.entity_type = "FILE"
        $safebrowse.graph.metadata.product_name = "Google Safe Browsing"
        $safebrowse.graph.metadata.source_type = "GLOBAL_CONTEXT"

        $seen.graph.entity.file.sha256 = $sha256
        $seen.graph.metadata.entity_type = "FILE"
        $seen.graph.metadata.source_type = "DERIVED_CONTEXT"
        $seen.graph.entity.file.last_seen_time.seconds > 0
        604800 <= $seen.graph.entity.file.last_seen_time.seconds - $seen.graph.entity.file.first_seen_time.seconds

      match:
        $host

      outcome:
        $dwell_malware_count = count($proc.metadata.id)
    }

    stage stage_host_net_egress {
        metadata.event_type = "NETWORK_CONNECTION"
        principal.asset.hostname = $host
        $host != ""

      match:
        $host

      outcome:
        $net_bytes = sum(network.sent_bytes)
        $net_mu = max(metrics.network_bytes_outbound(
            period: 1d, window: 30d, metric: value_sum, agg: avg,
            principal.asset.hostname: $host
        ))
        $net_sigma = max(metrics.network_bytes_outbound(
            period: 1d, window: 30d, metric: value_sum, agg: stddev,
            principal.asset.hostname: $host
        ))
    }

    $host = $stage_safebrowsing_dwell.host
    $host = $stage_host_net_egress.host

    match:
      $host

    outcome:
      $malware_events = max($stage_safebrowsing_dwell.dwell_malware_count)
      $observed_bytes = max($stage_host_net_egress.net_bytes)
      $avg_bytes = max($stage_host_net_egress.net_mu)
      $std_bytes = max($stage_host_net_egress.net_sigma)

      $z_egress = ($observed_bytes - $avg_bytes) / ($std_bytes + 1.0)
      $fused_threat = $z_egress + ($malware_events * 3.0)

    order:
      $fused_threat desc
    """
    self.assertIn('$safebrowse.graph.metadata.product_name = "Google Safe Browsing"', query)
    self.assertIn('$seen.graph.metadata.source_type = "DERIVED_CONTEXT"', query)
    self.assertIn("metrics.network_bytes_outbound", query)
    self.assertNotIn("condition:", query)

  def test_query_5_gcti_tor_exit_nodes(self):
    query = """
    stage stage_tor_connections {
        $net.metadata.event_type = "NETWORK_CONNECTION"
        $net.target.ip = $ip
        $net.principal.asset.hostname = $host
        $ip != ""
        $host != ""

        $gcti.graph.entity.artifact.ip = $ip
        $gcti.graph.metadata.entity_type = "IP_ADDRESS"
        $gcti.graph.metadata.threat.threat_feed_name = "Tor Exit Nodes"
        $gcti.graph.metadata.product_name = "GCTI Feed"
        $gcti.graph.metadata.source_type = "GLOBAL_CONTEXT"

      match:
        $host

      outcome:
        $tor_flow_obs = count($net.metadata.id)
        $tor_bytes_obs = sum($net.network.sent_bytes)

        $flow_mu = max(metrics.network_flows_outbound(
            period: 1d, window: 30d, metric: event_count_sum, agg: avg,
            principal.asset.hostname: $host
        ))
        $flow_sigma = max(metrics.network_flows_outbound(
            period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
            principal.asset.hostname: $host
        ))
    }

    $host = $stage_tor_connections.host

    match:
      $host

    outcome:
      $tor_flows = max($stage_tor_connections.tor_flow_obs)
      $tor_bytes = max($stage_tor_connections.tor_bytes_obs)
      $avg_flows = max($stage_tor_connections.flow_mu)
      $std_flows = max($stage_tor_connections.flow_sigma)

      $z_flows = ($tor_flows - $avg_flows) / ($std_flows + 1.0)

    order:
      $z_flows desc
    """
    self.assertIn('$gcti.graph.metadata.threat.threat_feed_name = "Tor Exit Nodes"', query)
    self.assertIn("metrics.network_flows_outbound", query)
    self.assertNotIn("condition:", query)

  def test_validator_catches_multiple_ecg_events_in_single_stage(self):
    """MalachiteASTValidator must reject queries with >1 Entity Context Graph events in a single stage."""
    from scripts.preflight_validator import MalachiteASTValidator

    invalid_query = """
    // ARCHITECTURE: Multi-ECG in single stage
    stage stage_invalid {
        $proc.metadata.event_type = "PROCESS_LAUNCH"
        $proc.target.process.file.sha256 = $sha256
        $proc.principal.asset.hostname = $host

        $safebrowse.graph.entity.file.sha256 = $sha256
        $safebrowse.graph.metadata.source_type = "GLOBAL_CONTEXT"

        $seen.graph.entity.file.sha256 = $sha256
        $seen.graph.metadata.source_type = "DERIVED_CONTEXT"

      match:
        $host
      outcome:
        $c = count($proc.metadata.id)
    }
    $host = $stage_invalid.host
    match: $host
    outcome: $c = max($stage_invalid.c)
    """
    errors = MalachiteASTValidator.validate_query(invalid_query)
    self.assertTrue(any("ECG_LIMIT_EXCEEDED" in err for err in errors), f"Expected ECG_LIMIT_EXCEEDED error, got: {errors}")

  def test_validator_catches_part_of_the_whole_antipattern(self):
    """MalachiteASTValidator must reject evaluating metrics.* inside a stage with GLOBAL_CONTEXT filters."""
    from scripts.preflight_validator import MalachiteASTValidator

    crammed_threat_query = """
    // ARCHITECTURE: Part of the whole antipattern
    stage stage_bad {
        $net.metadata.event_type = "NETWORK_CONNECTION"
        $net.target.hostname = $domain
        $net.principal.asset.hostname = $host

        $whois.graph.entity.domain.name = $domain
        $whois.graph.metadata.source_type = "GLOBAL_CONTEXT"

      match:
        $host
      outcome:
        $net_mu = max(metrics.network_bytes_outbound(
            period: 1d, window: 30d, metric: value_sum, agg: avg,
            principal.asset.hostname: $host
        ))
    }
    $host = $stage_bad.host
    match: $host
    outcome: $mu = max($stage_bad.net_mu)
    """
    errors = MalachiteASTValidator.validate_query(crammed_threat_query)
    self.assertTrue(any("Part-of-the-Whole" in err for err in errors), f"Expected Part-of-the-Whole error, got: {errors}")

  def test_validator_passes_decoupled_3stage_architecture(self):
    """MalachiteASTValidator must approve clean decoupled 3-stage threat fusion queries."""
    from scripts.preflight_validator import MalachiteASTValidator

    decoupled_query = """
    // ARCHITECTURE: Decoupled Multi-Stage Threat Fusion
    stage stage_total_egress {
        metadata.event_type = "NETWORK_CONNECTION"
        principal.asset.hostname = $host
        $host != ""
      match:
        $host
      outcome:
        $total_bytes_obs = sum(network.sent_bytes)
        $net_mu = max(metrics.network_bytes_outbound(
            period: 1d, window: 30d, metric: value_sum, agg: avg,
            principal.asset.hostname: $host
        ))
    }
    stage stage_nrd_threat_hits {
        $net.metadata.event_type = "NETWORK_CONNECTION"
        $net.target.hostname = $domain
        $net.principal.asset.hostname = $host
        $whois.graph.entity.domain.name = $domain
        $whois.graph.metadata.source_type = "GLOBAL_CONTEXT"
      match:
        $host
      outcome:
        $nrd_threat_events = count($net.metadata.id)
    }
    $host = $stage_total_egress.host
    $host = $stage_nrd_threat_hits.host
    match:
      $host
    outcome:
      $obs_total = max($stage_total_egress.total_bytes_obs)
      $mu_total = max($stage_total_egress.net_mu)
      $threat_hits = max($stage_nrd_threat_hits.nrd_threat_events)
    order:
      $obs_total desc
    """
    errors = MalachiteASTValidator.validate_query(decoupled_query)
    self.assertEqual(len(errors), 0, f"Expected 0 errors for decoupled query, got: {errors}")


if __name__ == '__main__':
  unittest.main()

