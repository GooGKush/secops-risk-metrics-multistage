"""Static contracts for the rare-destination (Entity Graph filter) templates and their docs."""

import pathlib
import re
import unittest

SKILL_ROOT = pathlib.Path(__file__).resolve().parent.parent
PIPELINES = SKILL_ROOT / "templates" / "pipelines"
TODAY_FILTER = 'timestamp.get_date(metadata.event_timestamp.seconds) = "<<today_date>>"'
EVENT_FIELD = re.compile(r"(?<![$\w.])(?:metadata|principal|target|network)\.")

# Slot values that compiled and returned rows live on GUS-SDL (2026-10-01, window D-2 00:00Z..now).
HTTP_FILTER = ('(network.http.method != "" or network.http.user_agent != "" or '
               'network.http.response_code != 0 or network.http.referral_url != "")')
DOMAIN_ECG = {
    "{{ecg_entity_type}}": '"DOMAIN_NAME"',
    "{{ecg_key_path}}": "entity.domain.name",
    "{{ecg_prevalence_path}}": "entity.domain.prevalence",
    "{{max_fleet_prevalence}}": "3",
    "{{today_date}}": "2026-10-01",
}


def _stages(code: str):
  code = re.sub(r"//[^\n]*", "", code)
  code = re.sub(r"\{\{(\w+)\}\}", r"<<\1>>", code)  # slot braces would end the stage body early
  return re.findall(r"stage\s+(\w+)\s*\{([^}]+)\}", code)


def _predicates(body: str) -> str:
  return re.split(r"^\s*(?:match|outcome)\s*:", body, maxsplit=1, flags=re.MULTILINE)[0]


class TestRareDestinationTemplates(unittest.TestCase):

  TEMPLATES = ("rare_destination_ecg_3stage.yl2", "fusion_rare_destination_3stage.yl2")

  def test_freshness_filter_on_event_stages_only(self):
    for name in self.TEMPLATES:
      with self.subTest(template=name):
        stages = _stages((PIPELINES / name).read_text(encoding="utf-8"))
        self.assertEqual(len(stages), 3)
        for stage, body in stages:
          preds = _predicates(body)
          is_graph = ".graph." in preds
          self.assertEqual(TODAY_FILTER in preds, not is_graph, f"{name}:{stage}")
          if not is_graph:
            self.assertTrue(EVENT_FIELD.search(preds), f"{name}:{stage} should be an event stage")

  def test_at_most_two_event_stages(self):
    """Compiler limit: SourceCount['udm'] <= 2; graph stages do not count."""
    for name in self.TEMPLATES:
      with self.subTest(template=name):
        stages = _stages((PIPELINES / name).read_text(encoding="utf-8"))
        event_stages = [s for s, body in stages if ".graph." not in _predicates(body)]
        self.assertLessEqual(len(event_stages), 2)

  def test_graph_stage_is_prevalence_filter(self):
    for name in self.TEMPLATES:
      with self.subTest(template=name):
        text = (PIPELINES / name).read_text(encoding="utf-8")
        self.assertIn('$g.graph.metadata.source_type = "DERIVED_CONTEXT"', text)
        self.assertIn("$g.graph.{{ecg_prevalence_path}}.day_count = 10", text)
        self.assertIn("$g.graph.{{ecg_prevalence_path}}.rolling_max > 0", text)
        self.assertIn("Rule 5", text)
        self.assertIn("FILTER ONLY", text)

  def test_dns_destination_uses_questions_name(self):
    text = (PIPELINES / "rare_destination_ecg_3stage.yl2").read_text(encoding="utf-8")
    self.assertIn("dest_field = network.dns.questions.name", text)
    self.assertIn("IP_ADDRESS", text)
    self.assertIn("entity.artifact.prevalence", text)

  def test_http_rare_destination_renders_validated_query(self):
    text = (PIPELINES / "rare_destination_ecg_3stage.yl2").read_text(encoding="utf-8")
    slots = dict(DOMAIN_ECG)
    slots.update({
        "{{sector_filter}}": "network.sent_bytes > 0\n    network.sent_bytes < 1000000000000000",
        "{{sector_observation_agg}}": "sum(network.sent_bytes)",
        "{{sector_metric_func_avg}}": "metrics.network_bytes_outbound(period: 1d, window: 30d, metric: value_sum, agg: avg, principal.asset.ip: $host)",
        "{{sector_metric_func_stddev}}": "metrics.network_bytes_outbound(period: 1d, window: 30d, metric: value_sum, agg: stddev, principal.asset.ip: $host)",
        "{{host_field}}": "principal.asset.ip",
        "{{contact_filter}}": HTTP_FILTER,
        "{{dest_field}}": "target.hostname",
    })
    for k, v in slots.items():
      text = text.replace(k, v)
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("//"))
    self.assertNotIn("{{", code)
    self.assertIn('$g.graph.metadata.entity_type = "DOMAIN_NAME"', code)
    self.assertIn("$g.graph.entity.domain.name = $dest", code)
    self.assertIn("target.hostname = $dest", code)
    self.assertIn('timestamp.get_date(metadata.event_timestamp.seconds) = "2026-10-01"', code)
    self.assertNotIn("event_timestamp.seconds >=", code)


class TestCrossVectorDocs(unittest.TestCase):

  def test_catalog_has_entity_graph_section_and_rules(self):
    text = (SKILL_ROOT / "references" / "metric-sector-catalog.md").read_text(encoding="utf-8")
    self.assertIn("## Entity Graph filters (`DERIVED_CONTEXT`)", text)
    self.assertIn("At most two UDM event stages per query", text)
    self.assertIn("Identifier coverage (probe first)", text)
    self.assertIn("### Choosing the template for a cross-vector request", text)
    self.assertIn("rare_destination_ecg_3stage.yl2", text)
    self.assertIn("fusion_rare_destination_3stage.yl2", text)

  def test_consultative_worksheet_points_at_catalog_pairs(self):
    text = (SKILL_ROOT / "references" / "consultative-worksheet.md").read_text(encoding="utf-8")
    self.assertIn("### Cross-Vector Pairing", text)
    self.assertIn("references/metric-sector-catalog.md", text)
    for tpl in ("dual_sector_fusion_3stage.yl2", "rollup_sector_fusion_4stage.yl2",
                "rare_destination_ecg_3stage.yl2", "fusion_rare_destination_3stage.yl2"):
      self.assertIn(tpl, text)

  def test_peer_group_path_documented(self):
    guide = (SKILL_ROOT / "references" / "multi-stage-metrics-guide.md").read_text(encoding="utf-8")
    self.assertIn("$z_team_vs_enterprise", guide)
    self.assertIn("AD TEAM LOOKUP", guide)
    self.assertIn("graph.entity.user.department", guide)
    self.assertIn("graph.relations.entity.group.group_display_name", guide)
    self.assertIn("ask the analyst for the roster and yield", guide)
    skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
    self.assertIn("AD TEAM LOOKUP (multi-stage-metrics-guide.md), else ask for the roster", skill)
    self.assertIn("incl. AD TEAM LOOKUP, run first", skill)
    self.assertLessEqual(len(skill.encode("utf-8")), 20480)

  def test_part_whole_templates_resolve_unnamed_team_from_ad(self):
    for name in ("part_of_the_whole_multilevel.yl2", "part_of_the_whole_triad_multilevel.yl2"):
      text = (SKILL_ROOT / "templates" / "pipelines" / name).read_text(encoding="utf-8")
      self.assertIn("AD TEAM LOOKUP", text, name)
      self.assertIn("supplied in a later turn", text, name)
      self.assertNotIn("ask the analyst for the roster\n//   and yield", text, name)

  def test_entity_graph_guide_lists_ip_address(self):
    text = (SKILL_ROOT / "references" / "entity-context-graph-guide.md").read_text(encoding="utf-8")
    self.assertIn("**`IP_ADDRESS`**", text)
    self.assertIn("$ip.graph.entity.artifact.prevalence.rolling_max <= 3", text)


if __name__ == "__main__":
  unittest.main()
