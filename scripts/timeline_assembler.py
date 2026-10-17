"""Mode C Per-Day Baseline Timeline Collator for SecOps Risk Metrics.

Author: Greg Kushmerek

A `metrics.*(period: 1d, window: 30d)` call resolves to ONE baseline window per search
request, anchored at the request start day. Mode C therefore runs the approved query once
per UTC day ("shard"), so every scored day is compared to its own trailing 30 days. This
script reshapes the saved shard results into one timeline report.

It computes no baselines and no Z-scores: every score comes from Chronicle. The only
derived values are D = sqrt(composite_threat_norm_sq) when a template emits just the
squared norm, and the canonical CRI sigmoid.
"""

import argparse
import datetime
import json
import math
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPT_DIR not in sys.path:
  sys.path.insert(0, _SCRIPT_DIR)

ENTITY_CANDIDATES = ("entity", "host", "hostname", "user", "userid", "principal", "asset", "token")
NON_ENTITY_COLUMNS = {"ws", "TIME_BUCKET", "window_start"}
# (column, is_squared): first match wins.
SCORE_CANDIDATES = (
    ("composite_threat_norm_sq", True),
    ("threat_vector_norm_sq", True),
    ("threat_distance_sq", True),
    ("d_vs_fleet_sq", True),
    ("d_vs_team_sq", True),
    ("threat_distance", False),
    ("composite_threat_distance", False),
    ("threat_score", False),
    ("beacon_score", False),
    ("personal_z", False),
    ("shielded_z", False),
    ("modified_z", False),
    ("upper_tail_z", False),
    ("poisson_z", False),
    ("hourly_z", False),
    ("flow_z", False),
    ("clamped_z", False),
    ("fast_z", False),
    ("normalized_odds_score", False),
    ("cusum_drift_score", False),
    ("hurdle_threat_score", False),
    ("circadian_threat_score", False),
    ("macd_momentum_score", False),
    ("sensitivity_excess", False),
    ("cri_score", False),
    ("z_score", False),
    ("z", False),
    ("surge_ratio", False),
    ("bayes_shift_ratio", False),
    ("posterior_fail_prob", False),
    ("fano_factor", False),
    ("ratio", False),
)
SECTOR_Z_EXCLUDED_SUFFIXES = ("_sq", "_raw", "_pos")


def cri_from_score(score: float) -> int:
  """Canonical Calibrated Risk Index sigmoid (anchored at 3.0σ = 50)."""
  return round(100.0 / (1.0 + math.exp(-0.6 * (max(0.0, score) - 3.0))))


def _parse_day(day: str) -> datetime.date:
  try:
    return datetime.date.fromisoformat(day)
  except ValueError as e:
    raise ValueError(f"Shard day must be UTC YYYY-MM-DD, got '{day}'") from e


def _compact_number(value: Any) -> Any:
  if isinstance(value, float) and value.is_integer():
    return int(value)
  return value


def _cell_value(cell: Dict[str, Any]) -> Any:
  value = cell.get("value", {})
  if not value:
    return None
  kind, raw = next(iter(value.items()))
  if kind in ("int64Val", "uint64Val"):
    return int(raw)
  if kind == "doubleVal":
    return float(raw)
  if kind == "boolVal":
    return bool(raw)
  if kind == "list":
    return [_cell_value({"value": v}) for v in raw.get("values", [])]
  return raw


def parse_stats_payload(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
  """Converts a udm_search `stats` payload into row dictionaries.

  An empty payload (`{}`, `{"stats": {}}`, or columns without values) is a valid clean shard.
  A payload with raw `events` and no `stats` is a non-aggregated query and is rejected.
  """
  if not payload:
    return []
  if "stats" not in payload:
    if payload.get("events"):
      raise ValueError("RAW_LOG_DUMP_DETECTED: shard returned raw events without stats")
    return []
  results = (payload.get("stats") or {}).get("results") or []
  columns: Dict[str, List[Any]] = {}
  for col in results:
    columns[col["column"]] = [_cell_value(v) for v in col.get("values", [])]
  n_rows = max((len(v) for v in columns.values()), default=0)
  rows = []
  for i in range(n_rows):
    rows.append({name: (vals[i] if i < len(vals) else None) for name, vals in columns.items()})
  return rows


def load_shard_spec(spec: str) -> Tuple[str, List[Dict[str, Any]]]:
  """Parses `YYYY-MM-DD=<path or inline JSON>`."""
  if "=" not in spec:
    raise ValueError(f"Shard spec must be DAY=PATH_OR_JSON, got '{spec}'")
  day, source = spec.split("=", 1)
  day = day.strip()
  _parse_day(day)
  source = source.strip()
  if source.startswith("{"):
    payload = json.loads(source)
  else:
    with open(source, "r", encoding="utf-8") as f:
      text = f.read().strip()
    payload = json.loads(text) if text else {}
  return day, parse_stats_payload(payload)


class TimelineAssembler:
  """Collates per-day shard rows into a timeline summary."""

  def __init__(
      self,
      entity_field: Optional[str] = None,
      score_field: Optional[str] = None,
      min_baseline_days: int = 5,
      top_n: int = 15,
  ):
    self.entity_field = entity_field
    self.score_field = score_field
    self.min_baseline_days = min_baseline_days
    self.top_n = top_n
    self.shards: Dict[str, List[Dict[str, Any]]] = {}
    self.failed: Dict[str, str] = {}

  def add_shard(self, day: str, rows: List[Dict[str, Any]]) -> None:
    _parse_day(day)
    if day in self.shards or day in self.failed:
      raise ValueError(f"Duplicate shard day '{day}'")
    self.shards[day] = rows

  def add_failed(self, day: str, reason: str = "failed after retry") -> None:
    _parse_day(day)
    if day in self.shards or day in self.failed:
      raise ValueError(f"Duplicate shard day '{day}'")
    self.failed[day] = reason

  # ---- field resolution -------------------------------------------------------------------

  def _all_columns(self) -> List[str]:
    seen: List[str] = []
    for rows in self.shards.values():
      for row in rows:
        for name in row:
          if name not in seen:
            seen.append(name)
    return seen

  def _resolve_entity_field(self, columns: List[str]) -> Optional[str]:
    if self.entity_field:
      return self.entity_field
    for name in ENTITY_CANDIDATES:
      if name in columns:
        return name
    for rows in self.shards.values():
      for row in rows:
        for name, value in row.items():
          if name not in NON_ENTITY_COLUMNS and isinstance(value, str):
            return name
    return None

  def _resolve_score_field(self, columns: List[str]) -> Tuple[Optional[str], bool]:
    if self.score_field:
      return self.score_field, self.score_field.endswith("_sq")
    for name, squared in SCORE_CANDIDATES:
      if name in columns:
        return name, squared
    return None, False

  @staticmethod
  def _sector_z_fields(columns: List[str]) -> List[str]:
    fields = []
    for name in columns:
      is_z = name.startswith("z_") or name.startswith("sector_z_")
      if is_z and not name.endswith(SECTOR_Z_EXCLUDED_SUFFIXES):
        fields.append(name)
    return fields

  @staticmethod
  def _sparse_pairs(columns: List[str]) -> List[Tuple[str, str, str]]:
    pairs = []
    for name in columns:
      if name.endswith("_active_days"):
        prefix = name[: -len("_active_days")]
        for obs in (f"{prefix}_observed", f"{prefix}_obs"):
          if obs in columns:
            pairs.append((prefix, name, obs))
            break
    return pairs

  # ---- assembly ---------------------------------------------------------------------------

  def build(self) -> Dict[str, Any]:
    columns = self._all_columns()
    entity_field = self._resolve_entity_field(columns)
    score_field, squared = self._resolve_score_field(columns)
    sector_fields = self._sector_z_fields(columns)
    sparse_pairs = self._sparse_pairs(columns)
    has_rows = any(self.shards.values())
    if has_rows and (entity_field is None or score_field is None):
      raise ValueError(
          "Could not resolve entity/score columns; pass --entity-field and --score-field. "
          f"Columns seen: {columns}")

    # Peak per (entity, day): templates with extra match keys can emit several rows.
    cells: Dict[Tuple[str, str], Dict[str, Any]] = {}
    sparse: List[Dict[str, Any]] = []
    for day, rows in self.shards.items():
      for row in rows:
        entity = str(row.get(entity_field))
        raw = row.get(score_field)
        if raw is None:
          continue
        raw = float(raw)
        score = math.sqrt(max(0.0, raw)) if squared else raw
        key = (entity, day)
        if key not in cells or score > cells[key]["score"]:
          cells[key] = {
              "entity": entity,
              "day": day,
              "score": score,
              "cri": cri_from_score(score),
              "sectors": {f: row.get(f) for f in sector_fields},
          }
        for prefix, days_col, obs_col in sparse_pairs:
          active, observed = row.get(days_col), row.get(obs_col)
          if active is not None and observed and float(observed) > 0 and float(active) < self.min_baseline_days:
            sparse.append({
                "entity": entity, "day": day, "sector": prefix,
                "observed": observed, "baseline_days": _compact_number(active),
            })

    all_days = sorted(set(self.shards) | set(self.failed))
    missing_days = []
    if all_days:
      first, last = _parse_day(all_days[0]), _parse_day(all_days[-1])
      provided = set(all_days)
      for offset in range((last - first).days + 1):
        day = (first + datetime.timedelta(days=offset)).isoformat()
        if day not in provided:
          missing_days.append(day)
    day_rows = []
    for day in all_days:
      if day in self.failed:
        day_rows.append({"day": day, "status": "failed", "reason": self.failed[day], "outliers": 0})
        continue
      day_cells = [c for (e, d), c in cells.items() if d == day]
      top = max(day_cells, key=lambda c: c["score"]) if day_cells else None
      day_rows.append({
          "day": day,
          "status": "ok" if day_cells else "empty",
          "outliers": len(day_cells),
          "top_entity": top["entity"] if top else None,
          "top_score": round(top["score"], 2) if top else None,
      })

    entities: Dict[str, Dict[str, Any]] = {}
    for entity in sorted({e for e, _ in cells}):
      flagged = sorted((c for (e, _), c in cells.items() if e == entity), key=lambda c: c["day"])
      ordinals = [_parse_day(c["day"]).toordinal() for c in flagged]
      longest, current, escalating = 1, 1, False
      rising = 1
      for i in range(1, len(flagged)):
        consecutive = ordinals[i] == ordinals[i - 1] + 1
        current = current + 1 if consecutive else 1
        longest = max(longest, current)
        rising = rising + 1 if consecutive and flagged[i]["score"] > flagged[i - 1]["score"] else 1
        if rising >= 3:
          escalating = True
      peak = max(flagged, key=lambda c: c["score"])
      onsets = {}
      for field in sector_fields:
        for c in flagged:
          value = c["sectors"].get(field)
          if value is not None and float(value) > 0:
            onsets[field] = c["day"]
            break
      entities[entity] = {
          "days_flagged": len(flagged),
          "first_day": flagged[0]["day"],
          "last_day": flagged[-1]["day"],
          "longest_run": longest,
          "peak_score": round(peak["score"], 2),
          "peak_day": peak["day"],
          "peak_cri": peak["cri"],
          "escalating": escalating,
          "sector_onsets": onsets,
      }

    top_rows = sorted(cells.values(), key=lambda c: c["score"], reverse=True)[: self.top_n]
    return {
        "meta": {
            "entity_field": entity_field,
            "score_field": score_field,
            "score_is_sqrt_of_field": squared,
            "sector_fields": sector_fields,
            "days_requested": len(all_days),
            "first_day": all_days[0] if all_days else None,
            "last_day": all_days[-1] if all_days else None,
            "failed_days": sorted(self.failed),
            "missing_days": missing_days,
            "min_baseline_days": self.min_baseline_days,
        },
        "days": day_rows,
        "entities": entities,
        "top": [
            {"entity": c["entity"], "day": c["day"], "score": round(c["score"], 2),
             "cri": c["cri"], "sectors": c["sectors"]}
            for c in top_rows
        ],
        "sparse_baseline": sparse,
    }

  # ---- rendering --------------------------------------------------------------------------

  @staticmethod
  def render_markdown(summary: Dict[str, Any], top_n: int = 15) -> str:
    meta = summary["meta"]
    score_label = "D" if meta["score_is_sqrt_of_field"] else (meta["score_field"] or "score")
    lines = [
        f"### Per-Day Baseline Timeline: {meta['first_day']} → {meta['last_day']} "
        f"({meta['days_requested']} daily shards)",
        "",
        "Each scored day D is compared to its own baseline [D − 30d, D).",
        "",
    ]
    if meta["failed_days"]:
      lines += [
          f"> [!WARNING]\n> Failed shards (reported, not filled): {', '.join(meta['failed_days'])}",
          "",
      ]
    if meta["missing_days"]:
      lines += [
          f"> [!WARNING]\n> Days inside the range with no shard supplied: {', '.join(meta['missing_days'])}",
          "",
      ]
    lines += ["| Day | Status | Outliers | Top Entity | Top " + score_label + " |",
              "| :--- | :--- | ---: | :--- | ---: |"]
    for d in summary["days"]:
      top = f"`{d['top_entity']}`" if d.get("top_entity") else "—"
      score = d.get("top_score")
      lines.append(f"| {d['day']} | {d['status']} | {d['outliers']} | {top} | "
                   f"{score if score is not None else '—'} |")

    entities = summary["entities"]
    if entities:
      ranked = sorted(entities.items(), key=lambda kv: kv[1]["peak_score"], reverse=True)[:top_n]
      sector_fields = meta["sector_fields"]
      lines += ["", "#### Entity Persistence & Onset", "",
                "| Entity | Days Flagged | First | Last | Longest Run | Peak " + score_label
                + " (Day) | CRI | Escalating | Sector Onsets |",
                "| :--- | ---: | :--- | :--- | ---: | :--- | ---: | :--- | :--- |"]
      for entity, e in ranked:
        onsets = ", ".join(f"{k}: {v}" for k, v in e["sector_onsets"].items()) if sector_fields else "—"
        lines.append(
            f"| `{entity}` | {e['days_flagged']} | {e['first_day']} | {e['last_day']} | "
            f"{e['longest_run']} | {e['peak_score']} ({e['peak_day']}) | {e['peak_cri']} | "
            f"{'yes' if e['escalating'] else 'no'} | {onsets or '—'} |")

    if summary["top"]:
      lines += ["", "#### Top Outlier Cells", "",
                "| Entity | Day | " + score_label + " | CRI | Sector Z |",
                "| :--- | :--- | ---: | ---: | :--- |"]
      for c in summary["top"][:top_n]:
        sectors = ", ".join(
            f"{k}={float(v):.2f}" for k, v in c["sectors"].items() if v is not None) or "—"
        lines.append(f"| `{c['entity']}` | {c['day']} | {c['score']} | {c['cri']} | {sectors} |")

    if summary["sparse_baseline"]:
      lines += ["", f"#### Too New to Baseline (< {meta['min_baseline_days']} baseline days; sector scored 0)", "",
                "| Entity | Day | Sector | Observed | Baseline Days |",
                "| :--- | :--- | :--- | ---: | ---: |"]
      for s in sorted(summary["sparse_baseline"], key=lambda s: float(s["observed"]), reverse=True)[:top_n]:
        lines.append(f"| `{s['entity']}` | {s['day']} | {s['sector']} | {s['observed']} | {s['baseline_days']} |")

    if not entities:
      lines += ["", "🟢 No outliers in any completed shard (nominal baseline)."]
    return "\n".join(lines) + "\n"

  @staticmethod
  def ranked_records(summary: Dict[str, Any], top_n: int = 15) -> List[Dict[str, Any]]:
    ranked = sorted(summary["entities"].items(), key=lambda kv: kv[1]["peak_score"], reverse=True)[:top_n]
    return [
        {"entity": f"{entity} ({e['peak_day']})", "threat_distance_d": e["peak_score"], "cri": e["peak_cri"]}
        for entity, e in ranked
    ]

  @staticmethod
  def render_html(summary: Dict[str, Any], top_n: int = 15) -> str:
    from radar_collector import EntityRadarCollector  # pylint: disable=g-import-not-at-top
    meta = summary["meta"]
    title = (f"Per-Day Baseline Timeline: Peak Outliers "
             f"({meta['days_requested']} days, {meta['first_day']} → {meta['last_day']})")
    return EntityRadarCollector.generate_ranked_fleet_html(
        TimelineAssembler.ranked_records(summary, top_n), title=title)


def main(argv: Optional[List[str]] = None) -> int:
  parser = argparse.ArgumentParser(description="Collate Mode C per-day shard results into one timeline report.")
  parser.add_argument("--shard", action="append", default=[],
                      help="DAY=PATH_OR_JSON (UTC YYYY-MM-DD). Repeat once per shard.")
  parser.add_argument("--failed", action="append", default=[],
                      help="DAY or DAY=REASON for a shard that failed after one retry.")
  parser.add_argument("--entity-field", help="Entity column (default: auto-detect)")
  parser.add_argument("--score-field", help="Score column; *_sq columns are square-rooted (default: auto-detect)")
  parser.add_argument("--min-baseline-days", type=int, default=5)
  parser.add_argument("--top", type=int, default=15)
  parser.add_argument("--markdown-out")
  parser.add_argument("--json-out")
  parser.add_argument("--html-out")
  args = parser.parse_args(argv)

  if not args.shard and not args.failed:
    parser.error("at least one --shard or --failed is required")

  assembler = TimelineAssembler(
      entity_field=args.entity_field, score_field=args.score_field,
      min_baseline_days=args.min_baseline_days, top_n=args.top)
  try:
    for spec in args.shard:
      day, rows = load_shard_spec(spec)
      assembler.add_shard(day, rows)
    for spec in args.failed:
      day, _, reason = spec.partition("=")
      assembler.add_failed(day.strip(), reason.strip() or "failed after retry")
    summary = assembler.build()
  except (ValueError, OSError, json.JSONDecodeError) as e:
    print(f"ERROR: {e}", file=sys.stderr)
    return 2

  markdown = TimelineAssembler.render_markdown(summary, args.top)
  if args.markdown_out:
    with open(args.markdown_out, "w", encoding="utf-8") as f:
      f.write(markdown)
  if args.json_out:
    with open(args.json_out, "w", encoding="utf-8") as f:
      json.dump(summary, f, indent=2)
  if args.html_out:
    with open(args.html_out, "w", encoding="utf-8") as f:
      f.write(TimelineAssembler.render_html(summary, args.top))
  print(markdown)
  return 0


if __name__ == "__main__":
  sys.exit(main())
