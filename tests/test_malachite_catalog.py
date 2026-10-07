"""Tests for the config.textproto-derived metric catalog and everything built on it.

These tests pin the rules taken from the Malachite compiler configuration
(`data/malachite/`), the baseline semantics (`data/metric_baseline_semantics.json`),
and their propagation into templates, the router, the validator, the radar
collector and the reference docs. If one fails after a data re-sync, fix the
content, not the test.

Author: Greg Kushmerek
"""

import pathlib
import re
import unittest

from scripts import generate_metric_sector_catalog as gen
from scripts import malachite_catalog as mc
from scripts.preflight_validator import (
    EntityType,
    MALACHITE_MANDATORY_FILTERS,
    METRIC_CATALOG,
    MalachiteASTValidator,
    PipelineArchitecture,
    PreFlightValidator,
    StatisticalModel,
)
from scripts.radar_collector import EntityRadarCollector
from scripts.template_router import MultiStageTemplateRouter

SKILL_ROOT = pathlib.Path(__file__).resolve().parent.parent
GOOGLE3_WORKSPACE = pathlib.Path("/google/src/cloud/kushmerek/sync_secops_risk_metrics/google3")
FUSABLE = sorted(m for m in mc.known_metrics() if not mc.is_composite_only(m))


class TestCatalogParsing(unittest.TestCase):

  def test_all_38_metrics_parsed(self):
    self.assertEqual(len(mc.known_metrics()), 38)
    self.assertEqual(set(METRIC_CATALOG), mc.known_metrics())

  def test_every_metric_has_semantics(self):
    for m in mc.known_metrics():
      sem = mc.baseline_semantics(m)
      self.assertTrue(sem.observed_filter, m)
      self.assertIn(sem.metric_arg, ("event_count_sum", "value_sum"), m)
      # value_sum is only legal on *bytes* metrics.
      self.assertEqual(sem.metric_arg == "value_sum", "bytes" in m, m)

  def test_parser_handles_namespace_and_prefix(self):
    text = (
        'query_info {\n  metric_name: "demo"\n  dimensions: PRINCIPAL_USER\n  dimensions: VENDOR_NAME\n}\n'
        '# comment\nquery_info { metric_name: "demo" dimensions: PRINCIPAL_DEVICE }\n'
    )
    parsed = mc.parse_config_query_infos(text)
    self.assertIn(("demo", ("PRINCIPAL_USER", "VENDOR_NAME")), [(m, tuple(sorted(d))) for m, d in parsed])
    self.assertTrue(mc.is_namespace_filter("principal.namespace"))
    self.assertFalse(mc.is_namespace_filter("principal.user.userid"))


class TestExactSetRule(unittest.TestCase):
  """The compiler requires the filter dimensions to equal one valid set exactly."""

  def test_auth_principal_host_plus_target_host_rejected(self):
    # Listed in the product doc; rejected by the compiler (b/568045587).
    self.assertIsNotNone(
        mc.validate_filter_fields("auth_attempts_fail", ["principal.asset.hostname", "target.asset.hostname"]))

  def test_auth_principal_host_plus_target_user_accepted(self):
    self.assertIsNone(
        mc.validate_filter_fields("auth_attempts_fail", ["principal.asset.hostname", "target.user.userid"]))

  def test_network_target_user_rejected_principal_user_accepted(self):
    self.assertIsNotNone(mc.validate_filter_fields("network_bytes_outbound", ["target.user.userid"]))
    self.assertIsNone(mc.validate_filter_fields("network_bytes_outbound", ["principal.user.userid"]))

  def test_every_identifier_leaf_works_for_entity_dimensions(self):
    for m in FUSABLE:
      for dim in mc.entity_only_dimensions(m):
        for fld in mc.dimension_fields()[dim]:
          self.assertIsNone(mc.validate_filter_fields(m, [fld]), f"{m} {fld}")

  def test_composite_only_metrics(self):
    composite = {m for m in mc.known_metrics() if mc.is_composite_only(m)}
    self.assertEqual(composite, {
        m for m in mc.known_metrics()
        if m.startswith(("file_executions_", "resource_")) or m == "alert_event_name_count"
    })
    # resource_* have no host-only binding at all.
    for m in composite:
      if m.startswith("resource_"):
        self.assertFalse(any(s == frozenset({"PRINCIPAL_DEVICE"}) for s in mc.metric_dimension_sets()[m]))

  def test_metric_catalog_default_fields_are_valid(self):
    for m, d in METRIC_CATALOG.items():
      for et, fld in d.dimension_fields.items():
        if mc.is_composite_only(m):
          dim = mc.field_to_dimension().get(fld)
          self.assertTrue(any(dim in s for s in mc.metric_dimension_sets()[m]), f"{m} {et} {fld}")
        else:
          self.assertIsNone(mc.validate_filter_fields(m, [fld]), f"{m} {et} {fld}")

  def test_catalog_entity_type_corrections(self):
    self.assertEqual(METRIC_CATALOG["alert_event_name_count"].supported_entity_types, [EntityType.ASSET])
    self.assertNotIn(EntityType.EMAIL, METRIC_CATALOG["workspace_emails_sent_total"].supported_entity_types)

  def test_mandatory_filters_are_in_every_valid_set(self):
    for m, required in MALACHITE_MANDATORY_FILTERS.items():
      for fld in required:
        dim = mc.field_to_dimension()[fld]
        for s in mc.metric_dimension_sets()[m]:
          self.assertIn(dim, s, f"{m}: {fld} ({dim}) missing from a valid set {sorted(s)}")


class TestResolveIdentifierField(unittest.TestCase):

  def test_default_and_leaf_and_full_path(self):
    r = PreFlightValidator.resolve_identifier_field
    self.assertEqual(r("network_bytes_outbound", EntityType.USER, None), "principal.user.userid")
    self.assertEqual(r("network_bytes_outbound", EntityType.USER, "email_addresses"), "principal.user.email_addresses")
    self.assertEqual(r("auth_attempts_fail", EntityType.USER, "target.user.windows_sid"), "target.user.windows_sid")

  def test_rejections(self):
    r = PreFlightValidator.resolve_identifier_field
    with self.assertRaises(ValueError):
      r("network_bytes_outbound", EntityType.USER, "target.user.userid")  # not a valid set
    with self.assertRaises(ValueError):
      r("network_bytes_outbound", EntityType.USER, "principal.asset.hostname")  # wrong entity class
    with self.assertRaises(ValueError):
      r("network_bytes_outbound", EntityType.USER, "not_a_leaf")


class TestFusionPairs(unittest.TestCase):

  def setUp(self):
    self.router = MultiStageTemplateRouter()

  def test_rules(self):
    S = mc.SectorSpec
    ok = mc.check_fusion_pair(S("dns_queries_fail", "principal.asset.hostname"), S("http_queries_total", "principal.asset.hostname"))
    self.assertTrue(ok.ok, ok.errors)
    self.assertEqual(ok.advisories, [])
    # principal vs target does not matter
    self.assertTrue(mc.check_fusion_pair(S("auth_attempts_fail", "target.user.userid"), S("network_bytes_outbound", "principal.user.userid")).ok)
    # user <-> host is never allowed
    self.assertFalse(mc.check_fusion_pair(S("auth_attempts_fail", "target.user.userid"), S("network_bytes_outbound", "principal.asset.hostname")).ok)
    # identifier kind must match
    self.assertFalse(mc.check_fusion_pair(S("auth_attempts_fail", "target.user.userid"), S("network_bytes_outbound", "principal.user.email_addresses")).ok)
    # composite-only metrics join as a roll-up sector (process execution + DNS by host)
    rollup = mc.check_fusion_pair(S("file_executions_total", "principal.asset.hostname"), S("dns_queries_total", "principal.asset.hostname"))
    self.assertTrue(rollup.ok, rollup.errors)
    self.assertTrue(any("rolls file_executions_total up" in a for a in rollup.advisories))
    # ...but at most one roll-up sector, and only on an entity dimension that has a roll-up set
    self.assertFalse(mc.check_fusion_pair(S("file_executions_total", "principal.asset.hostname"), S("alert_event_name_count", "principal.asset.hostname")).ok)
    self.assertFalse(mc.check_fusion_pair(S("file_executions_total", "target.user.userid"), S("auth_attempts_total", "target.user.userid")).ok)
    self.assertFalse(mc.check_fusion_pair(S("alert_event_name_count", "principal.user.userid"), S("dns_queries_total", "principal.user.userid")).ok)
    # a roll-up sector still obeys user <-> host
    self.assertFalse(mc.check_fusion_pair(S("resource_read_total", "principal.user.userid"), S("dns_queries_total", "principal.asset.hostname")).ok)
    # same metric twice
    self.assertFalse(mc.check_fusion_pair(S("dns_queries_total", "principal.asset.hostname"), S("dns_queries_total", "principal.asset.hostname")).ok)
    # invalid single set
    self.assertFalse(mc.check_fusion_pair(S("network_bytes_outbound", "target.user.userid"), S("auth_attempts_fail", "target.user.userid")).ok)

  def test_same_family_and_repeated_field_advisories(self):
    S = mc.SectorSpec
    fam = mc.check_fusion_pair(S("auth_attempts_fail", "target.user.userid"), S("auth_attempts_total", "target.user.userid"))
    self.assertTrue(fam.ok)
    self.assertTrue(any("both auth metrics" in a for a in fam.advisories))
    rep = mc.check_fusion_pair(S("http_queries_total", "principal.user.email_addresses"), S("network_bytes_outbound", "principal.user.email_addresses"))
    self.assertTrue(rep.ok, rep.errors)
    self.assertTrue(any("repeated" in a for a in rep.advisories))

  def test_rendered_pair_carries_each_sector_semantics(self):
    S = mc.SectorSpec
    q = self.router.build_sector_fusion_query(
        S("dns_queries_fail", "principal.asset.hostname"), S("http_queries_total", "principal.asset.hostname"), four_stage=True)
    self.assertEqual(mc.observed_filter_gaps(q), [])
    self.assertIn("metrics.dns_queries_fail(", q)
    self.assertIn("metrics.http_queries_total(", q)
    self.assertNotIn("auth_attempts", q)
    self.assertNotIn("network_bytes", q)
    q = self.router.build_sector_fusion_query(
        S("auth_attempts_fail", "target.user.userid"), S("auth_attempts_total", "target.user.userid"))
    self.assertIn("// ADVISORY:", q)

  def test_every_same_identifier_pair_renders_clean(self):
    """All fusable metric pairs sharing a default identifier render with no errors or gaps."""
    by_kind = {}
    for m in FUSABLE:
      for dim in mc.entity_only_dimensions(m):
        leaf = mc.DEFAULT_USER_IDENTIFIER if dim in mc.USER_DIMENSIONS else mc.DEFAULT_DEVICE_IDENTIFIER
        fld = next(f for f in mc.dimension_fields()[dim] if f.endswith("." + leaf))
        by_kind.setdefault(leaf, {}).setdefault(m, fld)
    rendered = 0
    for leaf, fields in by_kind.items():
      metrics = sorted(fields)
      for i, a in enumerate(metrics):
        for b in metrics[i + 1:]:
          q = self.router.build_sector_fusion_query(mc.SectorSpec(a, fields[a]), mc.SectorSpec(b, fields[b]))
          self.assertEqual(mc.observed_filter_gaps(q), [], f"{a}+{b}")
          rendered += 1
    self.assertGreater(rendered, 100)


class TestRollupSectors(unittest.TestCase):
  """Composite-only metrics join fusions as a roll-up sector (detail stage per key -> roll-up per entity)."""

  COMPOSITE = sorted(m for m in mc.known_metrics() if mc.is_composite_only(m))
  # Same-identifier entity-keyed partners for sector B, by entity class.
  PARTNER = {"user": ("dns_queries_total", "principal.user.userid"),
             "device": ("dns_queries_total", "principal.asset.hostname")}

  def setUp(self):
    self.router = MultiStageTemplateRouter()

  def _default_field(self, dim):
    leaf = mc.DEFAULT_USER_IDENTIFIER if dim in mc.USER_DIMENSIONS else mc.DEFAULT_DEVICE_IDENTIFIER
    return next(f for f in mc.dimension_fields()[dim] if f.endswith("." + leaf))

  def test_every_composite_metric_has_a_valid_rollup(self):
    for m in self.COMPOSITE:
      dims = [d for d in sorted(mc.ENTITY_DIMENSIONS) if mc.rollup_dimension_sets(m, d)]
      self.assertTrue(dims, m)
      for d in dims:
        for st in mc.rollup_dimension_sets(m, d):
          plan = mc.rollup_plan(m, self._default_field(d), sorted(st - {d}))
          self.assertIsNone(mc.validate_filter_fields(m, [plan.entity_field, *plan.companion_fields]), (m, sorted(st)))

  def test_every_composite_metric_renders_as_rollup_sector(self):
    rendered = 0
    for m in self.COMPOSITE:
      for d in sorted(mc.ENTITY_DIMENSIONS):
        if not mc.rollup_dimension_sets(m, d):
          continue
        fld = self._default_field(d)
        kind = "user" if d in mc.USER_DIMENSIONS else "device"
        partner = mc.SectorSpec(*self.PARTNER[kind])
        plan = mc.rollup_plan(m, fld)
        for four_stage in (False, True):
          # composite passed as sector B still lands in the roll-up slot
          q = self.router.build_sector_fusion_query(partner, mc.SectorSpec(m, fld), four_stage=four_stage)
          code = re.sub(r"//[^\n]*", "", q)
          self.assertEqual(MalachiteASTValidator.validate_query(q), [], (m, fld, four_stage))
          self.assertEqual(mc.observed_filter_gaps(q), [], (m, fld))
          self.assertNotIn("{{", code)
          self.assertIn("stage sector_a_detail", q)
          self.assertIn(f"metrics.{m}(", q)
          self.assertIn(plan.metric_filters(), q)
          self.assertIn(f"match:\n    {plan.match_keys()} by 1d", q)
          self.assertIn("// ADVISORY: Sector A rolls", q)
          self.assertEqual("stage fleet_sector_norm" in q, four_stage)
          rendered += 1
    self.assertGreaterEqual(rendered, 2 * len(self.COMPOSITE))

  def test_process_plus_dns_by_host(self):
    """The case that prompted roll-ups: process execution + DNS for one host."""
    q = self.router.build_sector_fusion_query(
        mc.SectorSpec("file_executions_total", "principal.asset.hostname"),
        mc.SectorSpec("dns_queries_fail", "principal.asset.hostname"))
    self.assertIn("principal.asset.hostname: principal.asset.hostname, metadata.event_type: metadata.event_type, "
                  "principal.process.file.sha256: principal.process.file.sha256", q)
    self.assertIn("$a_keys = count_distinct($sector_a_detail.principal_process_file_hash)", q)
    self.assertIn("$z_a = max($sector_a_detail.d_z)", q)
    self.assertIn("$a_novel_keys = sum($sector_a_detail.d_novel)", q)

  def test_rollup_templates_are_generic(self):
    for name in ("rollup_sector_fusion_4stage.yl2", "rollup_sector_fusion_5stage.yl2"):
      content = (SKILL_ROOT / "templates" / "pipelines" / name).read_text(encoding="utf-8")
      code = re.sub(r"//[^\n]*", "", content)
      for slot in ("{{sector_a_event_filter}}", "{{sector_a_companion_bindings}}", "{{sector_a_match_keys}}",
                   "{{sector_a_metric_filters}}", "{{sector_a_detail_key}}", "{{sector_b_entity_field}}",
                   "{{min_baseline_days}}"):
        self.assertIn(slot, code, (name, slot))
      for hardcoded in ("file_executions", "resource_", "alert_event", "PROCESS_LAUNCH", "sha256"):
        self.assertNotIn(hardcoded, code, (name, hardcoded))
      # comment lines carry no fillable slots except the header labels
      for line in content.splitlines():
        if line.lstrip().startswith("//"):
          for slot in re.findall(r"\{\{(\w+)\}\}", line):
            self.assertIn(slot, ("sector_a_label", "sector_b_label", "min_baseline_days"), (name, line))

  def test_catalog_documents_rollup_for_every_composite_metric(self):
    text = (SKILL_ROOT / "references" / "metric-sector-catalog.md").read_text(encoding="utf-8")
    self.assertIn("rollup_sector_fusion_4stage.yl2", text)
    self.assertNotIn("Composite-only metrics cannot be sectors", text)
    for m in self.COMPOSITE:
      row = text.split(f"### `metrics.{m}`", 1)[1].split("### `metrics.", 1)[0]
      self.assertIn("Roll-up sector sets", row, m)
      self.assertIn("Metric filters:", row, m)
    for name in ("dual_sector_fusion_3stage.yl2", "multi_sector_fusion_4stage.yl2"):
      content = (SKILL_ROOT / "templates" / "pipelines" / name).read_text(encoding="utf-8")
      self.assertIn("rollup_sector_fusion_4stage.yl2", content)
      self.assertNotIn("cannot be sectors", content)
      self.assertNotIn("MultiStageTemplateRouter", content)


class TestObservedFiltersEverywhere(unittest.TestCase):
  """Every stage that calls metrics.X must select the events X's baseline counts."""

  def test_extractors_carry_semantics(self):
    for m in mc.known_metrics():
      text = (SKILL_ROOT / "templates" / "stage1_extractors" / f"{m}.yl2").read_text()
      sem = mc.baseline_semantics(m)
      for line in sem.observed_filter:
        self.assertIn(line, text, m)
      # `$v = field` in the event section plus `sum($v)` in the outcome equals `sum(field)`.
      resolved = text
      for var, fld in re.findall(r"^\s*\$(\w+) = ([a-z_][\w.]*)\s*$", text, re.M):
        resolved = resolved.replace(f"(${var})", f"({fld})")
      self.assertIn(sem.observed_agg, resolved, m)

  def test_no_gaps_in_repo_content(self):
    roots = ["templates", "scripts", "references", "SKILL.md", "README.md"]
    offenders = []
    for root in roots:
      p = SKILL_ROOT / root
      files = [p] if p.is_file() else [f for f in p.rglob("*") if f.suffix in (".yl2", ".py", ".md")]
      for f in files:
        for g in mc.observed_filter_gaps(f.read_text(errors="ignore")):
          offenders.append(f"{f.relative_to(SKILL_ROOT)}:{g.line} {g.stage} {g.metrics} missing {g.missing}")
    self.assertEqual(offenders, [])

  def test_radar_sector_queries(self):
    for queries in (EntityRadarCollector.USER_SECTOR_QUERIES, EntityRadarCollector.ASSET_SECTOR_QUERIES):
      for sector, tpl in queries.items():
        q = tpl % {"entity_id": "x"}
        self.assertEqual(mc.observed_filter_gaps(q), [], sector)
        self.assertNotIn('security_result.action = "BLOCK"', q, sector)
        self.assertNotIn("SCAN_UNCATEGORIZED", q, sector)
        # Root stages may only read stage outputs through $stage.var.
        root = q.rsplit("}", 1)[-1]
        self.assertFalse(re.search(r"max\(\$(?!\w+\.)\w+\)", root), f"{sector}: root reads a bare stage variable")

  def test_router_renders(self):
    router = MultiStageTemplateRouter()
    for m, d in METRIC_CATALOG.items():
      for et in d.supported_entity_types:
        q = router.build_query(m, et, StatisticalModel.STANDARD_Z_SCORE)
        self.assertEqual(mc.observed_filter_gaps(q), [], f"{m} {et}")
    for pt in PipelineArchitecture:
      if pt == PipelineArchitecture.LOCAL_2STAGE:
        continue
      for et in (EntityType.ASSET, EntityType.USER):
        q = router.build_pipeline_query(pt, entity_type=et)
        self.assertEqual(mc.observed_filter_gaps(q), [], f"{pt.value} {et}")

  def test_identifier_rebinding(self):
    router = MultiStageTemplateRouter()
    q = router.build_query("network_bytes_outbound", EntityType.USER, StatisticalModel.STANDARD_Z_SCORE,
                           identifier_field="email_addresses")
    self.assertIn("principal.user.email_addresses", q)
    self.assertNotIn("principal.asset.hostname", q)
    self.assertEqual(MalachiteASTValidator.validate_query(q), [])


class TestValidatorRules(unittest.TestCase):

  def _stage(self, filters):
    args = ",\n          ".join(filters)
    return f"""// Goal: test
stage s1 {{
    metadata.event_type = "USER_LOGIN"
    principal.asset.hostname = $h
  match:
    $h by 1d
  outcome:
    $mu = max(metrics.auth_attempts_fail(
          period: 1d, window: 30d, metric: event_count_sum, agg: avg,
          {args}
    ))
}}
$h = $s1.h
match:
  $h by 1d
outcome:
  $z = max($s1.mu)
"""

  def test_unsupported_dimension_set_flagged(self):
    bad = self._stage(["principal.asset.hostname: $h", 'target.asset.hostname: "x"'])
    self.assertTrue(any("UNSUPPORTED_DIMENSION_SET" in e for e in MalachiteASTValidator.validate_query(bad)))
    good = self._stage(["principal.asset.hostname: $h", 'target.user.userid: "x"'])
    self.assertFalse(any("UNSUPPORTED_DIMENSION_SET" in e for e in MalachiteASTValidator.validate_query(good)))

  def test_anti_pattern_6_allows_baseline_event_type_pairs(self):
    q = f"""// Goal: test
stage s1 {{
    {mc.baseline_semantics("resource_read_total").observed_filter[0]}
    principal.user.userid = $u
    metadata.vendor_name = $v
    metadata.product_name = $p
  match:
    $u, $v, $p by 1d
  outcome:
    $mu = max(metrics.resource_read_total(period: 1d, window: 30d, metric: event_count_sum, agg: avg,
          principal.user.userid: $u, metadata.vendor_name: $v, metadata.product_name: $p))
}}
$u = $s1.u
match:
  $u by 1d
outcome:
  $z = max($s1.mu)
"""
    self.assertFalse(any("ANTI-PATTERN 6 " in e for e in MalachiteASTValidator.validate_query(q)))

  def test_triad_reports_mixed_families_first(self):
    with self.assertRaises(ValueError) as ctx:
      PreFlightValidator.audit_triad(["auth_attempts_total", "network_bytes_outbound"], EntityType.USER)
    self.assertIn("Heterogeneous event types", str(ctx.exception))


class TestGeneratedArtifacts(unittest.TestCase):

  def test_metric_sector_catalog_is_current(self):
    current = (SKILL_ROOT / "references" / "metric-sector-catalog.md").read_text(encoding="utf-8")
    self.assertEqual(current, gen.render(),
                     "references/metric-sector-catalog.md is stale; run python3 -m scripts.generate_metric_sector_catalog")

  def test_catalog_lists_every_metric(self):
    text = gen.render()
    for m in mc.known_metrics():
      self.assertIn(f"### `metrics.{m}`", text)

  @unittest.skipUnless(GOOGLE3_WORKSPACE.is_dir(), "google3 workspace not mounted")
  def test_vendored_data_matches_google3(self):
    from scripts import sync_malachite_catalog as sync
    self.assertEqual(sync.check(GOOGLE3_WORKSPACE), [])


class TestSiblingTriads(unittest.TestCase):
  """Triads: one stage, one entity field, shared filter, conditional-sum observed values."""

  def test_canonical_triads_are_valid(self):
    for label, metrics in mc.CANONICAL_TRIADS:
      with self.subTest(triad=label):
        self.assertEqual(len(metrics), 3)
        self.assertEqual(len({mc.metric_family(m) for m in metrics}), 1, "a triad never mixes families")
        self.assertTrue(all(m.endswith("_total") for m in metrics[:1]), "m1 is the family total")
        self.assertFalse(any(mc.is_composite_only(m) for m in metrics))
        self.assertTrue(mc.triad_entity_dimensions(metrics), "needs one entity dimension valid for all three")

  def test_no_composite_or_mixed_triads(self):
    members = {m for _, ms in mc.CANONICAL_TRIADS for m in ms}
    self.assertFalse(any(m.startswith(("file_executions_", "resource_", "alert_")) for m in members))
    self.assertNotIn("dns_bytes_outbound", members)

  def test_auth_triad_partitions_login_events(self):
    stage, obs = mc.triad_event_selection(("auth_attempts_total", "auth_attempts_fail", "auth_attempts_success"))
    self.assertEqual(stage, ['metadata.event_type = "USER_LOGIN"'])
    self.assertEqual(obs["auth_attempts_total"], "count(metadata.id)")
    self.assertEqual(obs["auth_attempts_fail"], 'sum(if(security_result.action = "ALLOW", 0, 1))')
    self.assertEqual(obs["auth_attempts_success"], 'sum(if(security_result.action = "ALLOW", 1, 0))')

  def test_network_triads_use_the_total_filter(self):
    for fam in ("bytes", "flows"):
      with self.subTest(family=fam):
        total = f"network_{fam}_total"
        metrics = (total, f"network_{fam}_outbound", f"network_{fam}_inbound")
        stage, obs = mc.triad_event_selection(metrics)
        self.assertEqual(stage, list(mc.baseline_semantics(total).observed_filter))
        self.assertEqual(obs[total], mc.baseline_semantics(total).observed_agg)
    _, flows = mc.triad_event_selection(("network_flows_total", "network_flows_outbound", "network_flows_inbound"))
    self.assertTrue(flows["network_flows_outbound"].startswith("sum(if(network.sent_bytes > 0"))

  def test_router_and_catalog_share_one_implementation(self):
    metrics = ("http_queries_total", "http_queries_fail", "http_queries_success")
    self.assertEqual(MultiStageTemplateRouter._triad_event_selection(metrics), mc.triad_event_selection(metrics))

  def test_catalog_documents_every_triad(self):
    text = gen.render()
    self.assertIn("## Sibling triads (`part_of_the_whole_triad_multilevel.yl2`)", text)
    for label, metrics in mc.CANONICAL_TRIADS:
      section = text.split(f"### {label} triad", 1)[1].split("### ", 1)[0]
      stage, obs = mc.triad_event_selection(metrics)
      for ln in stage:
        self.assertIn(ln, section)
      for m in metrics:
        self.assertIn(obs[m], section)

  def test_guide_triad_section_matches_template(self):
    guide = (SKILL_ROOT / "references" / "multi-stage-metrics-guide.md").read_text(encoding="utf-8")
    section = guide.split("### 4. Intra-Event Metric Triad Breakouts", 1)[1].split("### ", 1)[0]
    self.assertNotIn("Endpoint Process Triad", section)
    self.assertNotIn("dns_bytes_outbound", section)
    self.assertNotIn("max(0, Z", section, "the template's triad norm is two-sided")
    self.assertIn("metric-sector-catalog.md", section)
    tpl = (SKILL_ROOT / "templates" / "pipelines" / "part_of_the_whole_triad_multilevel.yl2").read_text(encoding="utf-8")
    self.assertIn("$d_vs_team_sq = ($z1_vs_team * $z1_vs_team)", tpl)
    self.assertIn("Sibling triads", tpl)
    self.assertIn("Peer group is optional (default = fleet only)", section)

  def test_triad_defaults_to_fleet_and_team_blocks_are_optional(self):
    tpl = (SKILL_ROOT / "templates" / "pipelines" / "part_of_the_whole_triad_multilevel.yl2").read_text(encoding="utf-8")
    opens = [ln for ln in tpl.splitlines() if ln.strip().startswith("// >>> TEAM COHORT")]
    closes = [ln for ln in tpl.splitlines() if ln.strip().startswith("// <<< TEAM COHORT")]
    self.assertEqual(len(opens), 3)
    self.assertEqual(len(closes), 3)
    self.assertIn("$d_vs_fleet_sq = ($z1_vs_enterprise * $z1_vs_enterprise)", tpl)
    self.assertTrue(tpl.rstrip().endswith("order:\n  $d_vs_fleet_sq desc"))
    # Every team reference sits inside a marked block, so deleting the blocks leaves no dangling refs.
    from scripts.template_router import _apply_team_cohort_blocks
    fleet_only = _apply_team_cohort_blocks(tpl, keep=False)
    body = "\n".join(ln for ln in fleet_only.splitlines() if not ln.lstrip().startswith("//"))
    self.assertNotIn("team", body)
    self.assertNotIn("{{cohort_filter}}", fleet_only)
    self.assertIn("TEAM COHORT", gen.render().split("## Sibling triads", 1)[1].split("### ", 1)[0])


class TestIdentifierSwapComments(unittest.TestCase):
  """Every Stage 1 extractor tells the agent which identifier fields it may swap in."""

  def test_every_extractor_lists_its_valid_dimensions(self):
    for path in sorted((SKILL_ROOT / "templates" / "stage1_extractors").glob("*.yl2")):
      metric = path.stem
      with self.subTest(metric=metric):
        text = path.read_text(encoding="utf-8")
        header = "\n".join(ln for ln in text.splitlines() if ln.startswith("//"))
        self.assertIn("// Identifier swap:", header)
        self.assertNotIn("{{", header)
        self.assertNotIn("metrics.", header, "comment must not look like a metric reference")
        if mc.is_composite_only(metric):
          self.assertIn("keep every companion field", header)
        else:
          listed = set(re.findall(r"//   - ([A-Z_]+) \(", header))
          self.assertEqual(listed, set(mc.entity_only_dimensions(metric)))

  def test_router_drops_note_after_binding(self):
    q = MultiStageTemplateRouter().build_query("auth_attempts_fail", EntityType.USER, StatisticalModel.STANDARD_Z_SCORE)
    self.assertNotIn("// Identifier swap:", q)
    self.assertIn("stage stage1_extract {", q)


class TestFusionGuidanceNotDuplicated(unittest.TestCase):

  def test_guide_defers_pairing_rules_to_catalog(self):
    guide = (SKILL_ROOT / "references" / "multi-stage-metrics-guide.md").read_text(encoding="utf-8")
    self.assertIn("apply the **Fusion pairing rules** at the top of that file", guide)
    self.assertNotIn("over-counts", guide)
    self.assertIn("4 named stages + root is supported but does not always work", guide)
    self.assertNotIn("IAM + Net", guide)

  def test_skill_md_points_to_catalog_rollup_and_triads(self):
    skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
    for token in ("references/metric-sector-catalog.md", "rollup_sector_fusion_4stage.yl2",
                  "part_of_the_whole_triad_multilevel.yl2", "hybrid_metric_*.yl2"):
      self.assertIn(token, skill)
    self.assertLessEqual(len(skill.encode("utf-8")), 20480)

  def test_five_stage_rollup_warns_about_reliability(self):
    tpl = (SKILL_ROOT / "templates" / "pipelines" / "rollup_sector_fusion_5stage.yl2").read_text(encoding="utf-8")
    self.assertIn("fall back to rollup_sector_fusion_4stage.yl2", tpl)


if __name__ == "__main__":
  unittest.main()
