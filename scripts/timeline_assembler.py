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
from dataclasses import dataclass, field
import datetime
import json
import math
import os
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPT_DIR not in sys.path:
  sys.path.insert(0, _SCRIPT_DIR)

try:
  from .ueba_constants import (
      DEFAULT_MIN_BASELINE_DAYS,
      _coerce_finite_float,
      calculate_cri,
      coerce_cri_int,
      cri_from_model_score,
      format_cri,
      get_score_semantics,
      is_inverted_score_key,
      score_to_z_equivalent,
  )
except ImportError:
  try:
    from scripts.ueba_constants import (
        DEFAULT_MIN_BASELINE_DAYS,
        _coerce_finite_float,
        calculate_cri,
        coerce_cri_int,
        cri_from_model_score,
        format_cri,
        get_score_semantics,
        is_inverted_score_key,
        score_to_z_equivalent,
    )
  except ImportError:
    from ueba_constants import (  # type: ignore[no-redef]
        DEFAULT_MIN_BASELINE_DAYS,
        _coerce_finite_float,
        calculate_cri,
        coerce_cri_int,
        cri_from_model_score,
        format_cri,
        get_score_semantics,
        is_inverted_score_key,
        score_to_z_equivalent,
    )

ENTITY_CANDIDATES = ("entity", "host", "hostname", "user", "userid", "principal", "asset", "token")
NON_ENTITY_COLUMNS = {"ws", "TIME_BUCKET", "window_start"}
# (column, is_squared): first match wins.
SCORE_CANDIDATES = (
    ("composite_threat_norm_sq", True),
    ("threat_vector_norm_sq", True),
    ("threat_distance_sq", True),
    ("poisson_z_sq", True),
    ("d_vs_fleet_sq", True),
    ("d_vs_team_sq", True),
    ("d_sq", True),
    ("norm_sq", True),
    ("threat_distance", False),
    ("composite_threat_distance", False),
    ("composite_risk", False),
    ("fused_threat_score", False),
    ("markov_threat_score", False),
    ("threat_score", False),
    ("flow_surge_score", False),
    ("beacon_score", False),
    ("recon_score", False),
    ("target_risk_score", False),
    ("quantile_z", False),
    ("fence_z", False),
    ("tukey_excess_z", False),
    ("tukey_fence_ratio", False),
    ("modified_z", False),
    ("m_z_score", False),
    ("macd_z", False),
    ("above_max_z", False),
    ("bayesian_z", False),
    ("beta_binomial_z", False),
    ("adaptive_z", False),
    ("hod_z_score", False),
    ("burst_z", False),
    ("deficit_z", False),
    ("delta_z", False),
    ("targeted_delta_z", False),
    ("shielded_z", False),
    ("upper_tail_z", False),
    ("poisson_z", False),
    ("hourly_z", False),
    ("flow_z", False),
    ("clamped_z", False),
    ("fast_z", False),
    ("z_log", False),
    ("fleet_z", False),
    ("z_vs_enterprise", False),
    ("z_vs_team", False),
    ("z_sector", False),
    ("macro_z_score", False),
    ("normalized_odds_score", False),
    ("cusum_drift_score", False),
    ("windowed_slack_sum", False),
    ("hurdle_threat_score", False),
    ("hurdle_anomaly_score", False),
    ("circadian_threat_score", False),
    ("macd_momentum_score", False),
    ("sensitivity_excess", False),
    ("shannon_entropy_score", False),
    ("entropy_score", False),
    ("zipf_rarity_score", False),
    ("rarity_score", False),
    ("ewma_velocity_score", False),
    ("velocity_score", False),
    ("velocity_kmh", False),
    ("bayes_shift_ratio", False),
    ("posterior_lift", False),
    ("posterior_fail_prob", False),
    ("posterior_fail_rate", False),
    ("regularized_failure_prob", False),
    ("posterior_rate", False),
    ("empirical_shift", False),
    ("concentration_ratio", False),
    ("producer_ratio", False),
    ("fold_change", False),
    ("rel_dev_z_equiv", False),
    ("surge_ratio", False),
    ("hourly_surge_ratio", False),
    ("ratio_1v7", False),
    ("ratio_1v30", False),
    ("fano_factor", False),
    ("cv", False),
    ("diversity_z", False),
    ("novelty_flag", False),
    ("cri_score", False),
    ("personal_z", False),
    ("z_score", False),
    ("anomaly_score", False),
    ("z", False),
    ("ratio", False),
)
SECTOR_Z_EXCLUDED_SUFFIXES = ("_sq", "_raw", "_pos")


def cri_from_score(score: Any) -> Optional[int]:
  """Canonical Calibrated Risk Index [0..100] (0 for Z<=0, 50 at 3.0σ, None on missing/error)."""
  return calculate_cri(score)


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
  """Parses `YYYY-MM-DD[:sector]=<path or inline JSON>`."""
  if "=" not in spec:
    raise ValueError(f"Shard spec must be DAY[:SECTOR]=PATH_OR_JSON, got '{spec}'")
  day_spec, source = spec.split("=", 1)
  day_spec = day_spec.strip()
  day_part, sep, sector_part = day_spec.partition(":")
  _parse_day(day_part.strip())
  if sep and not sector_part.strip():
    raise ValueError(f"Shard spec has empty sector after ':': '{spec}'")
  source = source.strip()
  if source.startswith("{"):
    payload = json.loads(source)
  else:
    with open(source, "r", encoding="utf-8") as f:
      text = f.read().strip()
    payload = json.loads(text) if text else {}
  return day_spec, parse_stats_payload(payload)


def _normalize_sector_col(sector: str) -> str:
  clean = sector.strip().lower().replace(" ", "_").replace("-", "_")
  if clean.startswith(("z_", "sector_z_")):
    return clean
  return f"z_{clean}"


class TimelineAssembler:
  """Collates per-day shard rows into a timeline summary."""

  def __init__(
      self,
      entity_field: Optional[str] = None,
      score_field: Optional[str] = None,
      min_baseline_days: int = DEFAULT_MIN_BASELINE_DAYS,
      top_n: int = 15,
  ):
    self.entity_field = entity_field
    self.score_field = score_field
    self.min_baseline_days = min_baseline_days
    self.top_n = top_n
    self.shards: Dict[str, List[Dict[str, Any]]] = {}
    self.unsectored_days: set[str] = set()
    self.sector_shards: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    self.failed: Dict[str, str] = {}

  def add_shard(
      self,
      day: str,
      rows: List[Dict[str, Any]],
      sector: Optional[str] = None,
  ) -> None:
    day_part, sep, inline_sector = day.partition(":")
    day_str = day_part.strip()
    _parse_day(day_str)
    eff_sector = sector or (inline_sector.strip() if sep else None)
    if day_str in self.failed:
      raise ValueError(f"Duplicate shard day '{day_str}'")
    if eff_sector:
      sec_col = _normalize_sector_col(eff_sector)
      if day_str in self.unsectored_days or (day_str, sec_col) in self.sector_shards:
        raise ValueError(f"Duplicate shard day/sector '{day_str}:{eff_sector}'")
      self.sector_shards[(day_str, sec_col)] = rows
      self.shards.setdefault(day_str, [])
    else:
      if day_str in self.shards:
        raise ValueError(f"Duplicate shard day '{day_str}'")
      self.unsectored_days.add(day_str)
      self.shards[day_str] = rows

  def add_failed(self, day: str, reason: str = "failed after retry") -> None:
    day_part, sep, inline_sector = day.partition(":")
    day_str = day_part.strip()
    _parse_day(day_str)
    if not sep and (day_str in self.shards or day_str in self.failed):
      raise ValueError(f"Duplicate shard day '{day_str}'")
    if sep:
      sec_label = inline_sector.strip() or "sector"
      prev = self.failed.get(day_str)
      self.failed[day_str] = f"{prev}; {sec_label}: {reason}" if prev else f"{sec_label}: {reason}"
    else:
      self.failed[day_str] = reason

  # ---- field resolution -------------------------------------------------------------------

  def _iter_all_rows(self) -> List[Dict[str, Any]]:
    all_rows: List[Dict[str, Any]] = []
    for rows in self.shards.values():
      all_rows.extend(rows)
    for rows in self.sector_shards.values():
      all_rows.extend(rows)
    return all_rows

  def _all_columns(self) -> List[str]:
    seen: List[str] = []
    for row in self._iter_all_rows():
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
    for row in self._iter_all_rows():
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
    # Fallback for multi-metric sector queries emitting z_<metric> columns (e.g. z_create, z_fail)
    for name in columns:
      if name.startswith("z_") and not name.endswith(SECTOR_Z_EXCLUDED_SUFFIXES):
        return name, False
    return None, False

  @staticmethod
  def _extract_row_score(
      row: Dict[str, Any],
      score_field: Optional[str],
      squared: bool,
  ) -> Optional[float]:
    if score_field and row.get(score_field) is not None:
      raw = _coerce_finite_float(row[score_field])
      if raw is None:
        return None
      return math.sqrt(max(0.0, raw)) if squared else raw
    z_vals = []
    for k, v in row.items():
      if k.startswith("z_") and not k.endswith(SECTOR_Z_EXCLUDED_SUFFIXES) and v is not None:
        parsed_v = _coerce_finite_float(v)
        if parsed_v is not None:
          z_vals.append(parsed_v)
    return max(z_vals) if z_vals else None

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
    for _, sec_col in self.sector_shards:
      if sec_col not in sector_fields:
        sector_fields.append(sec_col)
    sparse_pairs = self._sparse_pairs(columns)
    has_rows = any(self.shards.values()) or any(self.sector_shards.values())
    if has_rows and (entity_field is None or score_field is None):
      raise ValueError(
          "Could not resolve entity/score columns; pass --entity-field and --score-field. "
          f"Columns seen: {columns}")

    # Peak per (entity, day): templates with extra match keys can emit several rows.
    cells: Dict[Tuple[str, str], Dict[str, Any]] = {}
    sparse: List[Dict[str, Any]] = []
    sem = get_score_semantics(score_field)
    inverted_key = is_inverted_score_key(score_field)
    boolean_key = sem.kind == "boolean_flag"
    for day, rows in self.shards.items():
      for row in rows:
        entity = str(row.get(entity_field))
        score = self._extract_row_score(row, score_field, squared)
        if score is None:
          continue
        if boolean_key:
          if score < sem.threshold:
            continue
          z_equiv = None
          rank_tuple: Tuple[float, float] = (score, score)
          cri_val = None
        else:
          z_equiv = score_to_z_equivalent(score_field, score, already_sqrt=squared)
          if z_equiv is None:
            continue
          rank_tuple = (z_equiv, -score if inverted_key else score)
          cri_val = cri_from_model_score(score_field, score, already_sqrt=squared)
        key = (entity, day)
        if key not in cells or rank_tuple > cells[key]["_rank"]:
          cells[key] = {
              "entity": entity,
              "day": day,
              "score": score,
              "z_equiv": z_equiv,
              "_rank": rank_tuple,
              "cri": cri_val,
              "sectors": {f: row.get(f) for f in sector_fields},
          }
        for prefix, days_col, obs_col in sparse_pairs:
          active, observed = row.get(days_col), row.get(obs_col)
          if active is not None and observed and float(observed) > 0 and float(active) < self.min_baseline_days:
            sparse.append({
                "entity": entity, "day": day, "sector": prefix,
                "observed": observed, "baseline_days": _compact_number(active),
            })

    # Multi-sector per-day shards (360° Radar Mode C): fuse per-sector Z-scores into D = sqrt(sum max(0, Z_s)^2)
    if self.sector_shards:
      sector_cells: Dict[Tuple[str, str], Dict[str, float]] = {}
      for (day, sec_col), rows in self.sector_shards.items():
        for row in rows:
          entity = str(row.get(entity_field))
          sec_z = self._extract_row_score(row, score_field, squared)
          if sec_z is None:
            continue
          key = (entity, day)
          ent_sectors = sector_cells.setdefault(key, {})
          if sec_col not in ent_sectors or sec_z > ent_sectors[sec_col]:
            ent_sectors[sec_col] = sec_z
          for prefix, days_col, obs_col in sparse_pairs:
            active, observed = row.get(days_col), row.get(obs_col)
            if active is not None and observed and float(observed) > 0 and float(active) < self.min_baseline_days:
              sparse.append({
                  "entity": entity, "day": day, "sector": sec_col,
                  "observed": observed, "baseline_days": _compact_number(active),
              })
      for (entity, day), ent_sectors in sector_cells.items():
        norm_sq = sum(max(0.0, z) ** 2 for z in ent_sectors.values())
        d_score = math.sqrt(norm_sq) if norm_sq > 0 else max(ent_sectors.values(), default=0.0)
        z_equiv_d = score_to_z_equivalent("threat_distance", d_score) or 0.0
        cells[(entity, day)] = {
            "entity": entity,
            "day": day,
            "score": d_score,
            "z_equiv": z_equiv_d,
            "_rank": (z_equiv_d, d_score),
            "cri": cri_from_model_score("threat_distance", d_score),
            "sectors": {f: ent_sectors.get(f) for f in sector_fields},
        }
      squared = True  # Label composite distance column as D in markdown output.

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
      top = max(day_cells, key=lambda c: c["_rank"]) if day_cells else None
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
        rising = rising + 1 if consecutive and flagged[i]["_rank"] > flagged[i - 1]["_rank"] else 1
        if rising >= 3:
          escalating = True
      peak = max(flagged, key=lambda c: c["_rank"])
      onsets = {}
      for field in sector_fields:
        for c in flagged:
          value = c["sectors"].get(field)
          if value is not None and float(value) > 0:
            onsets[field] = c["day"]
            break
      # Sequential Page one-sided CUSUM (S_t = max(0.0, S_{t-1} + z_t - k), k = 0.5)
      cusum_s = 0.0
      peak_cusum_s = 0.0
      cum_z = 0.0
      flagged_by_day = {
          c["day"]: float(c["z_equiv"])
          for c in flagged
          if c["z_equiv"] is not None
      }
      for d in sorted(self.shards):
        z_t = flagged_by_day.get(d, 0.0)
        cum_z += z_t
        cusum_s = max(0.0, cusum_s + z_t - 0.5)
        peak_cusum_s = max(peak_cusum_s, cusum_s)

      entities[entity] = {
          "days_flagged": len(flagged),
          "first_day": flagged[0]["day"],
          "last_day": flagged[-1]["day"],
          "longest_run": longest,
          "peak_score": round(peak["score"], 2),
          "peak_day": peak["day"],
          "peak_cri": peak["cri"],
          "cusum_pos": round(cusum_s, 2),
          "peak_cusum_pos": round(peak_cusum_s, 2),
          "cumulative_z": round(cum_z, 2),
          "escalating": escalating,
          "sector_onsets": onsets,
      }

    top_rows = sorted(cells.values(), key=lambda c: c["_rank"], reverse=True)[: self.top_n]
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
        "> [!NOTE]",
        "> **Sustained-Attack Baseline Absorption & Fade Caveat (D10)**: Because each day `D` uses `[D − 30d, D)`, "
        "a sustained multi-day shift enters subsequent days' trailing baselines and inflates `σ` (Gaussian approximation: "
        "a sustained `+3σ` shift reads `≈ 2.5σ` on day 2; a sustained `+6σ` shift stays above `3σ` for ~3 days; no guard band). "
        "Never read a fading Mode C timeline as \"the attack stopped\" — use `LONGITUDINAL_CUSUM` (`longitudinal_cusum.yl2`) "
        "to evaluate sustained persistence.",
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
      is_inv = is_inverted_score_key(meta.get("score_field"))
      ranked = sorted(
          entities.items(),
          key=lambda kv: (
              kv[1].get("peak_cri") if kv[1].get("peak_cri") is not None else -1,
              -kv[1]["peak_score"] if is_inv else kv[1]["peak_score"],
          ),
          reverse=True,
      )[:top_n]
      sector_fields = meta["sector_fields"]
      lines += ["", "#### Entity Persistence & Onset", "",
                "| Entity | Days Flagged | First | Last | Longest Run | Peak " + score_label
                + " (Day) | CRI | Escalating | Sector Onsets |",
                "| :--- | ---: | :--- | :--- | ---: | :--- | ---: | :--- | :--- |"]
      for entity, e in ranked:
        onsets = ", ".join(f"{k}: {v}" for k, v in e["sector_onsets"].items()) if sector_fields else "—"
        lines.append(
            f"| `{entity}` | {e['days_flagged']} | {e['first_day']} | {e['last_day']} | "
            f"{e['longest_run']} | {e['peak_score']} ({e['peak_day']}) | {format_cri(e.get('peak_cri'))} | "
            f"{'yes' if e['escalating'] else 'no'} | {onsets or '—'} |")

    if summary["top"]:
      lines += ["", "#### Top Outlier Cells", "",
                "| Entity | Day | " + score_label + " | CRI | Sector Z |",
                "| :--- | :--- | ---: | ---: | :--- |"]
      for c in summary["top"][:top_n]:
        sectors = ", ".join(
            f"{k}={float(v):.2f}" for k, v in c["sectors"].items() if v is not None) or "—"
        lines.append(f"| `{c['entity']}` | {c['day']} | {c['score']} | {format_cri(c.get('cri'))} | {sectors} |")

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
    is_inv = is_inverted_score_key(summary["meta"].get("score_field"))
    ranked = sorted(
        summary["entities"].items(),
        key=lambda kv: (
            kv[1].get("peak_cri") if kv[1].get("peak_cri") is not None else -1,
            -kv[1]["peak_score"] if is_inv else kv[1]["peak_score"],
        ),
        reverse=True,
    )[:top_n]
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



@dataclass
class TimelinePoint:
  """Single daily observation point in an entity timeline series."""
  day: str
  z_score: Optional[float] = 0.0
  observed: float = 0.0
  baseline_mean: float = 0.0
  baseline_stddev: float = 1.0
  cumulative_z: float = 0.0
  cusum_pos: float = 0.0
  cri: Optional[int] = None

  def __post_init__(self) -> None:
    if self.cri is None:
      self.cri = cri_from_score(self.z_score)


@dataclass
class EntityTimelineSeries:
  """Time-ordered sequence of TimelinePoint records for an entity with sequential Page CUSUM."""
  entity: str
  points: List[TimelinePoint] = field(default_factory=list)
  slack_k: float = 0.5
  peak_score: float = 0.0
  peak_day: str = ""
  cusum_pos: float = 0.0
  cumulative_z: float = 0.0

  def __post_init__(self) -> None:
    self.recompute(self.slack_k)

  def recompute(self, slack_k: float = 0.5) -> None:
    """Computes sequential cumulative sum and Page one-sided CUSUM (S_t = max(0, S_{t-1} + z_t - k))."""
    cum_z = 0.0
    s_t = 0.0
    peak_z = -math.inf
    peak_d = ""
    for pt in self.points:
      z_val = _coerce_finite_float(pt.z_score)
      if z_val is None:
        pt.cumulative_z = round(cum_z, 4)
        pt.cusum_pos = round(s_t, 4)
        if pt.cri is None:
          pt.cri = None
        continue
      cum_z += z_val
      s_t = max(0.0, s_t + z_val - slack_k)
      pt.cumulative_z = round(cum_z, 4)
      pt.cusum_pos = round(s_t, 4)
      if pt.cri is None:
        pt.cri = cri_from_score(z_val)
      if z_val > peak_z:
        peak_z = z_val
        peak_d = pt.day
    self.cumulative_z = round(cum_z, 4)
    self.cusum_pos = round(s_t, 4)
    if peak_z > -math.inf:
      self.peak_score = round(peak_z, 4)
      self.peak_day = peak_d


def rebuild_calendar_day_stats(
    active_days: float,
    active_avg: float,
    active_sd: float,
    historical_sum: Optional[float] = None,
    window_days: float = 30.0,
) -> Dict[str, float]:
  """Rebuilds 30-day calendar-day statistics from active-day metrics.* outputs (PF-1, PF-2, WS1-05).

  Malachite `metrics.*` computes `avg` and sample `stddev` (N-1) over `num_metric_periods`
  (active days only), omitting zero-activity days. Given (n, avg, sd), this helper reconstructs:
    sum_x      = historical_sum if provided else n * avg
    sum_x2     = max(n - 1, 0) * sd^2 + n * avg^2
    lambda_cal = sum_x / window_days
    mu_cal     = sum_x / window_days
    var_cal    = max(sum_x2 / window_days - mu_cal^2, 0.0)
    sd_cal     = sqrt(var_cal)
  """
  win = float(window_days) if float(window_days) > 0.0 else 30.0
  n = max(0.0, float(active_days))
  avg = float(active_avg) if n > 0.0 else 0.0
  sd = max(0.0, float(active_sd)) if n > 1.0 else 0.0
  if n <= 0.0:
    sum_x = 0.0
    sum_x2 = 0.0
  else:
    sum_x = float(historical_sum) if historical_sum is not None else (n * avg)
    df_minus_one = max(n - 1.0, 0.0)
    sum_x2 = (df_minus_one * sd * sd) + (n * avg * avg)
  mu_cal = sum_x / win
  raw_var_cal = (sum_x2 / win) - (mu_cal * mu_cal)
  var_cal = max(raw_var_cal, 0.0)
  sd_cal = math.sqrt(var_cal)
  return {
      "active_days": n,
      "window_days": win,
      "dormant_days": max(0.0, win - n),
      "active_day_fraction": min(1.0, max(0.0, n / win)),
      "sum_x": sum_x,
      "sum_x2": sum_x2,
      "lambda_cal": mu_cal,
      "mu_cal": mu_cal,
      "var_cal": var_cal,
      "sd_cal": sd_cal,
  }


def calculate_page_cusum_series(z_scores: Sequence[Any], slack_k: float = 0.5) -> List[Any]:
  """Computes sequential Page one-sided upper CUSUM S_t = max(0.0, S_{t-1} + z_t - k)."""
  out: List[Any] = []
  s_t = 0.0
  cum_z = 0.0
  for item in z_scores:
    if isinstance(item, TimelinePoint):
      z_val = float(item.z_score)
      cum_z += z_val
      s_t = max(0.0, s_t + z_val - slack_k)
      item.cumulative_z = round(cum_z, 4)
      item.cusum_pos = round(s_t, 4)
      out.append(item)
    elif isinstance(item, dict):
      z_val = float(item.get("z_score", item.get("z", item.get("score", 0.0))))
      cum_z += z_val
      s_t = max(0.0, s_t + z_val - slack_k)
      new_d = dict(item)
      new_d["cumulative_z"] = round(cum_z, 4)
      new_d["cusum_pos"] = round(s_t, 4)
      out.append(new_d)
    else:
      s_t = max(0.0, s_t + float(item) - slack_k)
      out.append(round(s_t, 4))
  return out


def format_markdown_table(
    series_or_points: Union[EntityTimelineSeries, Sequence[Any], Dict[str, Any]],
    slack_k: float = 0.5,
) -> str:
  """Formats an EntityTimelineSeries, list of TimelinePoint/dicts, or assembler summary dict into Markdown."""
  if isinstance(series_or_points, dict) and "meta" in series_or_points and "days" in series_or_points:
    return TimelineAssembler.render_markdown(series_or_points)

  if isinstance(series_or_points, EntityTimelineSeries):
    series_or_points.recompute(slack_k=slack_k)
    points = series_or_points.points
    entity_header = f"#### Entity Timeline: `{series_or_points.entity}`\n\n"
  elif isinstance(series_or_points, (list, tuple)):
    raw_pts: List[TimelinePoint] = []
    for item in series_or_points:
      if isinstance(item, TimelinePoint):
        raw_pts.append(item)
      elif isinstance(item, dict):
        has_raw_z = any(k in item for k in ("z_score", "z", "score"))
        raw_z = item.get("z_score", item.get("z", item.get("score"))) if has_raw_z else 0.0
        parsed_z = _coerce_finite_float(raw_z)
        explicit_cri = coerce_cri_int(item.get("cri")) if "cri" in item and item.get("cri") is not None else None
        raw_pts.append(
            TimelinePoint(
                day=str(item.get("day", item.get("date", ""))),
                z_score=parsed_z,
                observed=float(item.get("observed", item.get("observed_val", 0.0))),
                baseline_mean=float(item.get("baseline_mean", item.get("hist_avg", 0.0))),
                baseline_stddev=float(item.get("baseline_stddev", item.get("hist_stddev", 1.0))),
                cumulative_z=float(item.get("cumulative_z", 0.0)),
                cusum_pos=float(item.get("cusum_pos", 0.0)),
                cri=explicit_cri,
            )
        )
    temp_series = EntityTimelineSeries(entity="target_entity", points=raw_pts, slack_k=slack_k)
    points = temp_series.points
    entity_header = ""
  else:
    return "*(No timeline points)*"

  if not points:
    return entity_header + "*(No timeline points)*"

  lines = [
      entity_header.rstrip() if entity_header else "",
      "| Date (UTC) | Observed | Daily Z-Score | Cumulative Z | Page CUSUM+ (S_t) | CRI (0-100) |",
      "| :--- | ---: | ---: | ---: | ---: | ---: |",
  ]
  lines = [ln for ln in lines if ln != ""]
  for pt in points:
    z_num = _coerce_finite_float(pt.z_score)
    z_cell = "N/A" if z_num is None else f"{z_num:+.2f}σ"
    cri_cell = format_cri(pt.cri)
    lines.append(
        f"| `{pt.day}` | `{pt.observed:.2f}` | `{z_cell}` | "
        f"`{pt.cumulative_z:+.2f}σ` | `{pt.cusum_pos:.2f}σ` | **`{cri_cell}`** |"
    )
  return "\n".join(lines)


TimelineAssembler.format_markdown_table = staticmethod(format_markdown_table)


def main(argv: Optional[List[str]] = None) -> int:
  parser = argparse.ArgumentParser(description="Collate Mode C per-day shard results into one timeline report.")
  parser.add_argument("--shard", action="append", default=[],
                      help="DAY=PATH_OR_JSON (UTC YYYY-MM-DD). Repeat once per shard.")
  parser.add_argument("--failed", action="append", default=[],
                      help="DAY or DAY=REASON for a shard that failed after one retry.")
  parser.add_argument("--entity-field", help="Entity column (default: auto-detect)")
  parser.add_argument("--score-field", help="Score column; *_sq columns are square-rooted (default: auto-detect)")
  parser.add_argument("--min-baseline-days", type=int, default=DEFAULT_MIN_BASELINE_DAYS)
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
