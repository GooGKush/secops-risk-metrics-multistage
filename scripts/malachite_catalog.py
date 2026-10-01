"""Malachite UEBA metric catalog derived from the compiler's own configuration.

Everything in this module is generated from data files vendored under
`data/` (see `data/malachite/README.md` for provenance):

* `data/malachite/config_dimensions.textproto` - reduced copy of
  `googlex/security/malachite/analytics/configs/config.textproto`. Each
  `query_info` block is one *valid dimension set* for a metric.
* `data/malachite/dimension_field_mapping.textproto` - verbatim copy of
  `googlex/security/malachite/rules/yl2/compiler/ueba/dimension_field_mapping.textproto`.
  Maps each dimension to the UDM fields that can stand in for it.
* `data/metric_baseline_semantics.json` - our own extraction of what each
  metric's baseline SQL counts (event selection, value, metric argument).

The compiler (`ueba_validator.go`, `validateUEBAMetricNameAndMetricDimension`)
maps every filter field in a `metrics.*()` call to its dimension and requires
the resulting *set* of dimensions to exactly equal one of the metric's valid
dimension sets. Namespace filters (any path component named `namespace`) are
partitioned out first. `validate_filter_fields` reproduces that rule.

Author: Greg Kushmerek
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Dict, FrozenSet, Iterable, List, Optional, Sequence, Set, Tuple

SKILL_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = SKILL_ROOT / "data"
MALACHITE_DATA_DIR = DATA_DIR / "malachite"
CONFIG_DIMENSIONS_PATH = MALACHITE_DATA_DIR / "config_dimensions.textproto"
DIMENSION_FIELD_MAPPING_PATH = MALACHITE_DATA_DIR / "dimension_field_mapping.textproto"
BASELINE_SEMANTICS_PATH = DATA_DIR / "metric_baseline_semantics.json"

UDM_PREFIX = "event.idm.read_only_udm."
NAMESPACE_COMPONENT = "namespace"

# Dimensions that identify a *who* (user) or a *what* (device). Only these can
# act as the join key between sectors in a fusion pipeline.
USER_DIMENSIONS: FrozenSet[str] = frozenset({"PRINCIPAL_USER", "TARGET_USER"})
DEVICE_DIMENSIONS: FrozenSet[str] = frozenset({"PRINCIPAL_DEVICE", "TARGET_DEVICE"})
ENTITY_DIMENSIONS: FrozenSet[str] = USER_DIMENSIONS | DEVICE_DIMENSIONS

# Identifier leaves that are repeated fields in UDM. Binding one of these to a
# placeholder yields one row per value (fan-out) instead of one row per event.
REPEATED_IDENTIFIER_LEAVES: FrozenSet[str] = frozenset({"email_addresses", "ip", "mac"})

DEFAULT_USER_IDENTIFIER = "userid"
DEFAULT_DEVICE_IDENTIFIER = "hostname"

# Metric family, used only to warn about non-orthogonal fusion pairs.
_FAMILY_PREFIXES: Tuple[Tuple[str, str], ...] = (
    ("workspace_", "workspace"),
    ("auth_attempts_", "auth"),
    ("dns_", "dns"),
    ("http_queries_", "http"),
    ("network_bytes_", "network"),
    ("network_flows_", "network"),
    ("file_executions_", "process"),
    ("resource_", "cloud_resource"),
    ("alert_", "alert"),
)


# ---------------------------------------------------------------------------
# Textproto parsing (the two files have a fixed, flat shape; no protobuf dep).
# ---------------------------------------------------------------------------


def _iter_code_lines(text: str) -> Iterable[str]:
  for raw in text.splitlines():
    line = raw.strip()
    if not line or line.startswith("#"):
      continue
    yield line


def parse_config_query_infos(text: str) -> List[Tuple[str, Tuple[str, ...]]]:
  """Returns (METRIC_NAME, (DIMENSION, ...)) for every query_info block.

  Accepts both the full google3 config.textproto and the reduced vendored copy:
  fields other than metric_name / dimensions are ignored. Blocks may span lines or
  sit on one line; values may be bare enums or quoted.
  """
  code = "\n".join(_iter_code_lines(text))
  tokens = re.findall(r'"(?:[^"\\]|\\.)*"|[{}]|[^\s{}:]+:?|:', code)
  out: List[Tuple[str, Tuple[str, ...]]] = []
  depth = 0
  in_block = False
  metric: Optional[str] = None
  dims: List[str] = []
  i = 0
  while i < len(tokens):
    tok = tokens[i]
    if tok == "{":
      depth += 1
      if depth == 1 and i > 0 and tokens[i - 1].rstrip(":") == "query_info":
        in_block, metric, dims = True, None, []
    elif tok == "}":
      if depth == 1 and in_block:
        if metric is None:
          raise ValueError("query_info block without metric_name")
        out.append((metric, tuple(dims)))
        in_block = False
      depth -= 1
    elif in_block and depth == 1 and tok in ("metric_name:", "dimensions:") and i + 1 < len(tokens):
      val = tokens[i + 1].strip('"')
      if tok == "metric_name:":
        metric = val
      else:
        dims.append(val)
      i += 1
    i += 1
  if in_block or depth != 0:
    raise ValueError("unterminated query_info block")
  return out


def parse_dimension_field_mapping(text: str) -> Dict[str, Tuple[str, ...]]:
  """Returns DIMENSION -> (udm field without 'event.idm.read_only_udm.', ...)."""
  out: Dict[str, Tuple[str, ...]] = {}
  in_block = False
  dim: Optional[str] = None
  fields: List[str] = []
  for line in _iter_code_lines(text):
    if re.match(r"^mappings\s*:?\s*\{$", line):
      in_block, dim, fields = True, None, []
      continue
    if not in_block:
      continue
    if line == "}":
      if dim is None:
        raise ValueError("mappings block without dimension")
      out[dim] = tuple(fields)
      in_block = False
      continue
    m = re.match(r"^dimension\s*:\s*([A-Z0-9_]+)$", line)
    if m:
      dim = m.group(1)
      continue
    m = re.match(r'^udm_fields\s*:\s*"([^"]+)"$', line)
    if m:
      f = m.group(1)
      fields.append(f[len(UDM_PREFIX):] if f.startswith(UDM_PREFIX) else f)
  if in_block:
    raise ValueError("unterminated mappings block")
  return out


def render_reduced_config(query_infos: Sequence[Tuple[str, Tuple[str, ...]]], header: str) -> str:
  """Renders the reduced (metric_name + dimensions only) config textproto."""
  lines = [header.rstrip(), ""]
  for metric, dims in query_infos:
    lines.append("query_info {")
    lines.append(f"  metric_name: {metric}")
    for d in dims:
      lines.append(f"  dimensions: {d}")
    lines.append("}")
  return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Loaded catalog.
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def dimension_fields() -> Dict[str, Tuple[str, ...]]:
  """DIMENSION -> UDM fields that stand in for it (vendored mapping)."""
  return parse_dimension_field_mapping(DIMENSION_FIELD_MAPPING_PATH.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def field_to_dimension() -> Dict[str, str]:
  out: Dict[str, str] = {}
  for dim, fields in dimension_fields().items():
    for f in fields:
      out[f] = dim
  return out


@lru_cache(maxsize=1)
def metric_dimension_sets() -> Dict[str, Tuple[FrozenSet[str], ...]]:
  """metric_name (lower case) -> valid dimension sets, in config order."""
  out: Dict[str, List[FrozenSet[str]]] = {}
  for metric, dims in parse_config_query_infos(CONFIG_DIMENSIONS_PATH.read_text(encoding="utf-8")):
    out.setdefault(metric.lower(), []).append(frozenset(dims))
  return {k: tuple(v) for k, v in out.items()}


def known_metrics() -> Set[str]:
  return set(metric_dimension_sets())


def is_namespace_filter(udm_field: str) -> bool:
  return any(part.lower() == NAMESPACE_COMPONENT for part in udm_field.split("."))


def supported_filter_fields(metric: str) -> Set[str]:
  """Union of every UDM field usable as a filter for `metric` (any valid set)."""
  dims = set().union(*metric_dimension_sets().get(metric.lower(), (frozenset(),)))
  mapping = dimension_fields()
  return {f for d in dims for f in mapping.get(d, ())}


def dimensions_for_fields(fields: Iterable[str]) -> Tuple[Set[str], List[str]]:
  """Maps filter fields to dimensions. Returns (dimension set, unknown fields)."""
  f2d = field_to_dimension()
  dims: Set[str] = set()
  unknown: List[str] = []
  for f in fields:
    if is_namespace_filter(f):
      continue
    d = f2d.get(f)
    if d is None:
      unknown.append(f)
    else:
      dims.add(d)
  return dims, unknown


def validate_filter_fields(metric: str, fields: Iterable[str]) -> Optional[str]:
  """Reproduces the compiler's exact-set rule. Returns an error string or None."""
  m = metric.lower()
  sets = metric_dimension_sets()
  if m not in sets:
    return f"unknown metric '{metric}'"
  fields = list(fields)
  dims, unknown = dimensions_for_fields(fields)
  if unknown:
    return f"unsupported filters for metric {m}: {sorted(unknown)} map to no dimension"
  if frozenset(dims) in sets[m]:
    return None
  return (
      f"unsupported filters for metric {m}: fields {sorted(set(fields))} map to dimension set "
      f"{sorted(dims)}, which is not one of the {len(sets[m])} valid sets in config.textproto"
  )


def valid_dimension_sets_text(metric: str) -> List[str]:
  return [" + ".join(sorted(s)) for s in metric_dimension_sets().get(metric.lower(), ())]


# ---------------------------------------------------------------------------
# Entity / identifier model.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EntityBinding:
  """A metric's entity key: a dimension plus the identifier field bound for it."""

  dimension: str
  field: str

  @property
  def entity_class(self) -> str:
    return "user" if self.dimension in USER_DIMENSIONS else "device"

  @property
  def identifier(self) -> str:
    return self.field.rsplit(".", 1)[-1]

  @property
  def join_kind(self) -> Tuple[str, str]:
    """Two bindings can be joined only when their join kinds are equal."""
    return (self.entity_class, self.identifier)

  @property
  def is_repeated(self) -> bool:
    return self.identifier in REPEATED_IDENTIFIER_LEAVES


def entity_binding_for_field(udm_field: str) -> EntityBinding:
  dim = field_to_dimension().get(udm_field)
  if dim not in ENTITY_DIMENSIONS:
    raise ValueError(
        f"'{udm_field}' is not a user or device identifier field; valid identifier fields are "
        f"{sorted(f for d in ENTITY_DIMENSIONS for f in dimension_fields()[d])}"
    )
  return EntityBinding(dimension=dim, field=udm_field)


def entity_only_dimensions(metric: str) -> List[str]:
  """User/device dimensions that form a valid single-dimension set for `metric`."""
  out = []
  for s in metric_dimension_sets().get(metric.lower(), ()):
    if len(s) == 1:
      (d,) = tuple(s)
      if d in ENTITY_DIMENSIONS:
        out.append(d)
  return out


def is_composite_only(metric: str) -> bool:
  """True when no single user/device dimension is a valid set on its own."""
  return not entity_only_dimensions(metric)


def with_identifier(udm_field: str, identifier: str) -> str:
  """Swaps the identifier leaf: ('target.user.userid', 'email_addresses') -> 'target.user.email_addresses'."""
  binding = entity_binding_for_field(udm_field)
  candidate = udm_field.rsplit(".", 1)[0] + "." + identifier
  if candidate not in dimension_fields()[binding.dimension]:
    raise ValueError(
        f"'{identifier}' is not an identifier of {binding.dimension}; choose one of "
        f"{[f.rsplit('.', 1)[-1] for f in dimension_fields()[binding.dimension]]}"
    )
  return candidate


def metric_family(metric: str) -> str:
  for prefix, fam in _FAMILY_PREFIXES:
    if metric.startswith(prefix):
      return fam
  return metric


# ---------------------------------------------------------------------------
# Baseline semantics (our own extraction of the baseline SQL).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MetricSemantics:
  metric: str
  observed_filter: Tuple[str, ...]
  observed_agg: str
  metric_arg: str
  event_types: Tuple[str, ...]
  baseline_sql_where: str
  notes: Tuple[str, ...] = field(default_factory=tuple)

  def event_filter_block(self, indent: str = "    ") -> str:
    return "\n".join(indent + line for line in self.observed_filter)

  @property
  def event_label(self) -> str:
    return " or ".join(self.event_types) if self.event_types else "any event type (no event_type filter in baseline)"


@lru_cache(maxsize=1)
def _semantics_doc() -> Dict:
  return json.loads(BASELINE_SEMANTICS_PATH.read_text(encoding="utf-8"))


def baseline_semantics(metric: str) -> MetricSemantics:
  doc = _semantics_doc()["metrics"]
  m = metric.lower()
  if m not in doc:
    raise ValueError(f"No baseline semantics recorded for metric '{metric}'")
  e = doc[m]
  return MetricSemantics(
      metric=m,
      observed_filter=tuple(e["observed_filter"]),
      observed_agg=e["observed_agg"],
      metric_arg=e["metric_arg"],
      event_types=tuple(e.get("event_types", ())),
      baseline_sql_where=e["baseline_sql_where"],
      notes=tuple(e.get("notes", ())),
  )


def semantics_provenance() -> Dict:
  return dict(_semantics_doc()["provenance"])


# ---------------------------------------------------------------------------
# Sibling-metric triads (part_of_the_whole_triad_multilevel.yl2).
# ---------------------------------------------------------------------------

# Sibling triads in template slot order (m1, m2, m3). Every metric keeps an entity-only set, so one
# stage can bind a single entity field for all three. Composite-only families (process, cloud
# resource) cannot form a triad: the triad stage matches on the entity alone.
CANONICAL_TRIADS: Tuple[Tuple[str, Tuple[str, str, str]], ...] = (
    ("Auth", ("auth_attempts_total", "auth_attempts_fail", "auth_attempts_success")),
    ("DNS", ("dns_queries_total", "dns_queries_fail", "dns_queries_success")),
    ("HTTP", ("http_queries_total", "http_queries_fail", "http_queries_success")),
    ("Network bytes", ("network_bytes_total", "network_bytes_outbound", "network_bytes_inbound")),
    ("Network flows", ("network_flows_total", "network_flows_outbound", "network_flows_inbound")),
)


def triad_entity_dimensions(metrics: Sequence[str]) -> List[str]:
  """Entity dimensions valid alone for every metric (the triad stage binds one field for all)."""
  common = set(entity_only_dimensions(metrics[0]))
  for m in metrics[1:]:
    common &= set(entity_only_dimensions(m))
  return sorted(common)


def triad_event_selection(metrics: Sequence[str]) -> Tuple[List[str], Dict[str, str]]:
  """Shared stage filter + per-metric observed value for sibling metrics evaluated in one stage.

  The stage keeps the filter lines common to all metrics. When the triad contains its family's
  `_total` metric, the total's filter is the stage filter: each sibling's baseline is a subset of the
  total's (fail/success split it, outbound/inbound are its two OR branches). Otherwise, if every
  metric adds its own lines, their OR is appended so the stage still selects the union. Count
  metrics whose filter has extra lines are observed with a conditional sum over those lines.
  """
  sems = {m: baseline_semantics(m) for m in metrics}
  totals = [m for m in metrics if m.endswith("_total")]
  if totals and len({metric_family(m) for m in metrics}) == 1:
    common = list(sems[totals[0]].observed_filter)
  else:
    common = [ln for ln in sems[metrics[0]].observed_filter if all(ln in sems[m].observed_filter for m in metrics)]
  extras = {m: [ln for ln in sems[m].observed_filter if ln not in common] for m in metrics}
  stage_filter = list(common)
  if all(extras[m] for m in metrics):
    stage_filter.append("(" + " or ".join("(" + " and ".join(extras[m]) + ")" for m in metrics) + ")")
  observed = {}
  for m in metrics:
    sem, extra = sems[m], extras[m]
    if not extra or sem.metric_arg == "value_sum":
      # Value metrics: rows outside the metric's own filter contribute 0 bytes (or are >= 1e15 outliers).
      observed[m] = sem.observed_agg
    elif len(extra) == 1 and extra[0].startswith("not "):
      observed[m] = f"sum(if({extra[0][4:]}, 0, 1))"
    else:
      observed[m] = f"sum(if({' and '.join(extra)}, 1, 0))"
  return stage_filter, observed


# ---------------------------------------------------------------------------
# Fusion pair validation.
# ---------------------------------------------------------------------------


# Companion dimensions that partition a metric's events by log source rather than by behavior.
# Only used to choose which companion a roll-up sector reports as its distinct-key count.
_SOURCE_COMPANIONS = frozenset({"EVENT_TYPE", "VENDOR_NAME", "PRODUCT_NAME"})


def companion_var(dimension: str) -> str:
  """Placeholder bound to a companion dimension in a roll-up detail stage ($event_type, ...)."""
  return "$" + dimension.lower()


def rollup_dimension_sets(metric: str, entity_dimension: str) -> List[FrozenSet[str]]:
  """Valid sets of `metric` whose only user/device dimension is `entity_dimension`, smallest first."""
  out = [
      s for s in metric_dimension_sets().get(metric.lower(), ())
      if entity_dimension in s and len(s & ENTITY_DIMENSIONS) == 1 and len(s) > 1
  ]
  return sorted(out, key=lambda st: (len(st), sorted(st)))


@dataclass(frozen=True)
class RollupPlan:
  """How a composite-only metric becomes a fusion sector.

  The detail stage matches on the entity plus every companion dimension of one valid set, so each
  metric call carries a complete valid set. A roll-up stage then collapses the detail rows to one
  row per entity (max per-key Z, count of keys at Z >= threshold, count of never-seen keys).
  """

  metric: str
  entity_field: str
  companions: Tuple[str, ...]

  @property
  def companion_fields(self) -> Tuple[str, ...]:
    return tuple(dimension_fields()[d][0] for d in self.companions)

  @property
  def detail_key_dimension(self) -> str:
    specific = [d for d in self.companions if d not in _SOURCE_COMPANIONS]
    if specific:
      return specific[0]
    return "PRODUCT_NAME" if "PRODUCT_NAME" in self.companions else self.companions[0]

  @property
  def detail_key_label(self) -> str:
    return dimension_fields()[self.detail_key_dimension][0]

  def companion_bindings(self) -> List[str]:
    """Event-section lines that bind each companion field to its placeholder."""
    lines = []
    for dim, fld in zip(self.companions, self.companion_fields):
      var = companion_var(dim)
      lines.append(f"{fld} = {var}")
      if dim != "EVENT_TYPE":  # enum field; the observed filter already constrains it
        lines.append(f'{var} != ""')
    return lines

  def match_keys(self) -> str:
    return ", ".join(["$entity"] + [companion_var(d) for d in self.companions])

  def metric_filters(self) -> str:
    return ", ".join([f"{self.entity_field}: $entity"] + [
        f"{fld}: {companion_var(dim)}" for dim, fld in zip(self.companions, self.companion_fields)
    ])


def rollup_plan(metric: str, entity_field: str, companions: Optional[Sequence[str]] = None) -> RollupPlan:
  """Roll-up plan for a composite-only metric keyed on `entity_field` (smallest valid set by default)."""
  binding = entity_binding_for_field(entity_field)
  sets = rollup_dimension_sets(metric, binding.dimension)
  if not sets:
    valid = sorted({d for st in metric_dimension_sets().get(metric.lower(), ()) for d in st & ENTITY_DIMENSIONS})
    raise ValueError(
        f"'{metric}' has no valid dimension set whose only entity dimension is {binding.dimension} "
        f"({entity_field}); entity dimensions it supports in a set: {valid or 'none'}"
    )
  if companions is None:
    chosen = sets[0]
  else:
    chosen = frozenset(companions) | {binding.dimension}
    if chosen not in sets:
      raise ValueError(
          f"{sorted(chosen)} is not a valid roll-up set for {metric}; choose one of "
          f"{[' + '.join(sorted(st)) for st in sets]}"
      )
  plan = RollupPlan(metric=metric.lower(), entity_field=entity_field,
                    companions=tuple(sorted(chosen - {binding.dimension})))
  err = validate_filter_fields(metric, [entity_field, *plan.companion_fields])
  if err:
    raise ValueError(err)
  return plan


@dataclass
class SectorSpec:
  metric: str
  entity_field: str
  # Composite-only metrics only: companion dimensions of the valid set to roll up over.
  # None picks the smallest valid set that contains the entity's dimension.
  companions: Optional[Tuple[str, ...]] = None

  @property
  def binding(self) -> EntityBinding:
    return entity_binding_for_field(self.entity_field)

  @property
  def is_rollup(self) -> bool:
    return self.metric in known_metrics() and is_composite_only(self.metric)

  def rollup(self) -> RollupPlan:
    return rollup_plan(self.metric, self.entity_field, self.companions)

  def label(self) -> str:
    if self.is_rollup:
      plan = self.rollup()
      return f"{self.metric} keyed on {self.entity_field}, rolled up over {', '.join(plan.companion_fields)}"
    return f"{self.metric} keyed on {self.entity_field}"


@dataclass
class FusionPairCheck:
  errors: List[str]
  advisories: List[str]

  @property
  def ok(self) -> bool:
    return not self.errors


def check_fusion_pair(a: SectorSpec, b: SectorSpec) -> FusionPairCheck:
  """Validates two sectors for a fusion pipeline. Errors block; advisories are informational.

  A composite-only metric (no entity-only dimension set) can be a sector through a roll-up
  (see RollupPlan); at most one sector per query may be a roll-up.
  """
  errors: List[str] = []
  advisories: List[str] = []
  bindings: List[Optional[EntityBinding]] = []
  rollups = 0
  for tag, s in (("A", a), ("B", b)):
    if s.metric not in known_metrics():
      errors.append(f"Sector {tag}: unknown metric '{s.metric}'.")
      bindings.append(None)
      continue
    try:
      bnd = entity_binding_for_field(s.entity_field)
    except ValueError as e:
      errors.append(f"Sector {tag}: {e}")
      bindings.append(None)
      continue
    if is_composite_only(s.metric):
      rollups += 1
      try:
        plan = rollup_plan(s.metric, s.entity_field, s.companions)
      except ValueError as e:
        errors.append(f"Sector {tag}: {e}")
        bindings.append(None)
        continue
      advisories.append(
          f"Sector {tag} rolls {s.metric} up from per-({', '.join(plan.companion_fields)}) baselines: its Z is "
          f"the largest per-{plan.detail_key_label} Z for the entity, not a Z of the entity's total volume "
          "(the metric has no entity-only baseline)."
      )
    else:
      err = validate_filter_fields(s.metric, [s.entity_field])
      if err:
        errors.append(
            f"Sector {tag}: {err}. Entity dimensions valid on their own for {s.metric}: "
            f"{entity_only_dimensions(s.metric)}."
        )
    bindings.append(bnd)
  if rollups > 1:
    errors.append(
        "Both sectors are composite-only metrics. The roll-up fusion templates support one roll-up "
        "sector per query; make the other sector an entity-keyed metric."
    )
  if a.metric == b.metric:
    errors.append(f"Both sectors use '{a.metric}'. Fusion needs two different metrics.")
  ba, bb = bindings
  if ba and bb:
    if ba.entity_class != bb.entity_class:
      errors.append(
          f"Sector A is keyed on a {ba.entity_class} ({a.entity_field}) and sector B on a "
          f"{bb.entity_class} ({b.entity_field}). User and host sectors cannot be joined."
      )
    elif ba.identifier != bb.identifier:
      errors.append(
          f"Sector A binds '{ba.identifier}' and sector B binds '{bb.identifier}'. Baselines are keyed by "
          f"(field, value), so both sectors must bind the same identifier kind to join."
      )
    if ba.is_repeated or bb.is_repeated:
      advisories.append(
          f"'{ba.identifier if ba.is_repeated else bb.identifier}' is a repeated UDM field: each value becomes "
          "its own row, so one event can contribute to several entities."
      )
  if a.metric in known_metrics() and b.metric in known_metrics() and a.metric != b.metric:
    if metric_family(a.metric) == metric_family(b.metric):
      advisories.append(
          f"'{a.metric}' and '{b.metric}' are both {metric_family(a.metric)} metrics. They are likely "
          "correlated, so the fused distance will overweight that one behavior."
      )
  return FusionPairCheck(errors=errors, advisories=advisories)


# ---------------------------------------------------------------------------
# Observed-vs-baseline event selection check.
# ---------------------------------------------------------------------------

_STAGE_RE = re.compile(r"stage\s+(\w+)\s*\{")


def _normalize_predicate_text(text: str) -> str:
  text = re.sub(r"\$\w+\.(?=[a-z])", "", text)  # drop event-variable prefixes such as `$e.`
  text = text.replace('\\"', '"')
  return re.sub(r"\s+", " ", text).strip()


@dataclass
class StageFilterGap:
  stage: str
  line: int
  metrics: List[str]
  missing: List[str]


def observed_filter_gaps(text: str) -> List[StageFilterGap]:
  """Stages whose event section lacks a called metric's observed-filter line.

  For every `stage NAME { ... }` that calls `metrics.X(...)`, the event section
  (text before `match:`) must contain each observed-filter line shared by all
  metrics called in that stage. Stages that still contain `{{slots}}` are
  skipped. `$v = field` + `$v = "X"` counts as `field = "X"`.
  """
  doc = _semantics_doc()["metrics"]
  gaps: List[StageFilterGap] = []
  for m in _STAGE_RE.finditer(text):
    i, depth = m.end(), 1
    while i < len(text) and depth:
      depth += {"{": 1, "}": -1}.get(text[i], 0)
      i += 1
    body = text[m.end():i - 1]
    if "{{" in body:
      continue
    called = sorted({x for x in re.findall(r"metrics\.(\w+)\s*\(", body) if x in doc})
    if not called:
      continue
    events = _normalize_predicate_text(body.split("match:")[0])
    for var, fld in re.findall(r"(\$\w+) = ([a-z][\w.]+)\b(?! *[=!<>])", events):
      for val in re.findall(re.escape(var) + r' = ("[^"]*")', events):
        events += f" {fld} = {val}"
    common = set(doc[called[0]]["observed_filter"])
    for x in called[1:]:
      common &= set(doc[x]["observed_filter"])
    missing = sorted(ln for ln in common if _normalize_predicate_text(ln) not in events)
    if missing:
      gaps.append(StageFilterGap(m.group(1), text.count("\n", 0, m.start()) + 1, called, missing))
  return gaps
