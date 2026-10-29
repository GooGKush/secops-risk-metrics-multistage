# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Canonical Shared UEBA Thresholds, Tiers, CRI, and Score Semantics (WS2-08, WS7-01, WS7-02).

This module is duplicated byte-for-byte identically across both skills in the
Bilateral UEBA Harness (`secops-risk-metrics-multistage` and
`secops-statistical-hunter`) per Rule 3 (self-contained skills, zero cross-repo
imports at runtime) and verified via SHA-256 contract tests.
"""

import math
from typing import Any, Dict, NamedTuple, Optional, Tuple

# ---------------------------------------------------------------------------
# Sensitivity Tier Thresholds & Cross-Skill Alias Resolution (WS2-08)
# ---------------------------------------------------------------------------

DEFAULT_SENSITIVITY_TIER: str = "BALANCED"

DEFAULT_ANOMALY_THRESHOLD: float = 3.0
DEFAULT_FOLD_CHANGE_THRESHOLD: float = 2.0
DEFAULT_FUSION_THRESHOLD_SQ: float = 12.25
DEFAULT_ROBUST_THRESHOLD: float = 3.5

SENSITIVITY_THRESHOLD_MAP: Dict[str, Dict[str, float]] = {
    "HIGH_RECALL": {
        "anomaly_threshold": 2.0,
        "fold_change_threshold": 1.5,
        "fusion_threshold_sq": 6.25,
        "robust_threshold": 2.5,
    },
    "BALANCED": {
        "anomaly_threshold": DEFAULT_ANOMALY_THRESHOLD,
        "fold_change_threshold": DEFAULT_FOLD_CHANGE_THRESHOLD,
        "fusion_threshold_sq": DEFAULT_FUSION_THRESHOLD_SQ,
        "robust_threshold": DEFAULT_ROBUST_THRESHOLD,
    },
    "HIGH_PRECISION": {
        "anomaly_threshold": 4.0,
        "fold_change_threshold": 3.0,
        "fusion_threshold_sq": 20.25,
        "robust_threshold": 4.5,
    },
}

SENSITIVITY_ALIASES: Dict[str, str] = {
    "HIGH_RECALL": "HIGH_RECALL",
    "AGGRESSIVE": "HIGH_RECALL",
    "LOW": "HIGH_RECALL",
    "BROAD": "HIGH_RECALL",
    "SENSITIVE": "HIGH_RECALL",
    "BALANCED": "BALANCED",
    "MEDIUM": "BALANCED",
    "DEFAULT": "BALANCED",
    "STANDARD": "BALANCED",
    "HIGH_PRECISION": "HIGH_PRECISION",
    "CONSERVATIVE": "HIGH_PRECISION",
    "HIGH": "HIGH_PRECISION",
    "STRICT": "HIGH_PRECISION",
}

MICRO_SENSITIVITY_FROM_CANONICAL: Dict[str, str] = {
    "HIGH_RECALL": "AGGRESSIVE",
    "BALANCED": "BALANCED",
    "HIGH_PRECISION": "CONSERVATIVE",
}

CANONICAL_FROM_MICRO_SENSITIVITY: Dict[str, str] = {
    "AGGRESSIVE": "HIGH_RECALL",
    "BALANCED": "BALANCED",
    "CONSERVATIVE": "HIGH_PRECISION",
}

# ---------------------------------------------------------------------------
# Operational Baselines, Fusion, Write-Back, Loopback & Window Caps (WS2-08)
# ---------------------------------------------------------------------------

DEFAULT_MIN_BASELINE_DAYS: int = 7
RADAR_FUSION_DISTANCE_THRESHOLD: float = 3.0
WRITEBACK_CRI_THRESHOLD: int = 50
LOOPBACK_COMPOSITE_SUM_Z_SQ_THRESHOLD: float = 25.0
LOOPBACK_MIN_DISTINCT_HITS: int = 2

MAX_MODE_B_DAYS_MACRO: int = 3
MAX_CUSUM_MODE_B_DAYS_MACRO: int = 14
MAX_MODE_C_DAYS_MACRO: int = 30
MAX_MODE_B_DAYS_MICRO: int = 14

# ---------------------------------------------------------------------------
# Canonical Calibrated Risk Index (CRI) Contract (WS7-01 / D5)
# ---------------------------------------------------------------------------

CRI_BANDS: Tuple[Tuple[int, int, str, str, str], ...] = (
    (0, 25, "INFORMATIONAL", "Nominal", "🟢"),
    (26, 45, "LOW", "Low Drift", "🟡"),
    (46, 69, "MEDIUM", "Medium Outlier", "🟠"),
    (70, 89, "HIGH", "High Threat", "🔴"),
    (90, 100, "CRITICAL", "Critical Outlier", "🚨"),
)

_INVALID_NUMERIC_STRINGS = frozenset({
    "",
    "-",
    "—",
    "N/A",
    "NA",
    "NAN",
    "INF",
    "+INF",
    "-INF",
    "INFINITY",
    "+INFINITY",
    "-INFINITY",
    "NONE",
    "NULL",
})


def _coerce_finite_float(value: Any) -> Optional[float]:
  """Coerces finite numeric scalars/strings to float; returns None on missing/error."""
  if value is None or isinstance(value, bool):
    return None
  if isinstance(value, str):
    stripped = value.strip()
    if stripped.upper() in _INVALID_NUMERIC_STRINGS:
      return None
    try:
      parsed = float(stripped)
    except (TypeError, ValueError):
      return None
    return parsed if math.isfinite(parsed) else None
  try:
    parsed = float(value)
  except (TypeError, ValueError):
    return None
  return parsed if math.isfinite(parsed) else None


def calculate_cri(
    score: Any,
    baseline_threshold: float = DEFAULT_ANOMALY_THRESHOLD,
) -> Optional[int]:
  """Canonical Calibrated Risk Index [0..100] with zero floor for Z<=0 and None on missing/error."""
  val = _coerce_finite_float(score)
  thresh = _coerce_finite_float(baseline_threshold)
  if val is None or thresh is None:
    return None
  if val <= 0.0:
    return 0
  exp_arg = -0.6 * (val - thresh)
  if exp_arg > 50.0:
    return 0
  if exp_arg < -50.0:
    return 100
  raw_cri = int(round(100.0 / (1.0 + math.exp(exp_arg))))
  return max(0, min(100, raw_cri))


cri_from_score = calculate_cri


def coerce_cri_int(cri: Any) -> Optional[int]:
  """Clamps a valid finite CRI value to [0..100], or returns None on missing/error."""
  val = _coerce_finite_float(cri)
  if val is None:
    return None
  return max(0, min(100, int(round(val))))


def format_cri(cri: Any) -> str:
  """Formats a CRI score as '0'..'100', or 'N/A' when missing/invalid."""
  val = coerce_cri_int(cri)
  return "N/A" if val is None else str(val)


def get_cri_band_info(cri: Any) -> Tuple[str, str, str]:
  """Returns `(short_code, band_label, emoji)` for a CRI value across 26/46/70/90 cutoffs."""
  val = coerce_cri_int(cri)
  if val is None:
    return "N/A", "N/A", "⚪"
  for low, high, code, label, emoji in CRI_BANDS:
    if low <= val <= high:
      return code, label, emoji
  return "CRITICAL", "Critical Outlier", "🚨"


def get_cri_badge(cri: Any) -> Tuple[str, str]:
  """Returns `(formatted_badge, band_label)` for micro/macro triage tables."""
  val = coerce_cri_int(cri)
  if val is None:
    return "⚪ `[CRI: N/A]`", "N/A"
  _, label, emoji = get_cri_band_info(val)
  return f"{emoji} `[CRI: {val}]`", label


def get_cri_band_metadata(
    cri: Any,
    bar_blocks: int = 8,
) -> Tuple[str, str, str]:
  """Returns `(short_code, emoji_band_label, unicode_bar)` for macro dossiers."""
  val = coerce_cri_int(cri)
  if val is None:
    return "N/A", "⚪ N/A", "░" * bar_blocks
  code, label, emoji = get_cri_band_info(val)
  blocks = max(0, min(bar_blocks, int(round((val / 100.0) * bar_blocks))))
  bar = ("█" * blocks) + ("░" * (bar_blocks - blocks))
  return code, f"{emoji} {label}", bar


def resolve_sensitivity_tier(
    tier: Optional[str] = None,
    *,
    strict: bool = False,
) -> str:
  """Resolves any macro or micro sensitivity label to canonical macro tier."""
  if tier is None:
    return DEFAULT_SENSITIVITY_TIER
  raw = str(tier).strip().upper().replace("-", "_").replace(" ", "_")
  if not raw:
    return DEFAULT_SENSITIVITY_TIER
  if raw in SENSITIVITY_ALIASES:
    return SENSITIVITY_ALIASES[raw]
  if strict:
    raise ValueError(
        f"Invalid sensitivity tier '{tier}'. Valid tiers: "
        f"{sorted(SENSITIVITY_THRESHOLD_MAP.keys())} (or micro aliases "
        f"{sorted(CANONICAL_FROM_MICRO_SENSITIVITY.keys())})."
    )
  return DEFAULT_SENSITIVITY_TIER


def resolve_sensitivity_thresholds(
    tier: Optional[str] = None,
    *,
    strict: bool = False,
) -> Tuple[str, Dict[str, float]]:
  """Resolves sensitivity label to `(canonical_tier, thresholds_dict_copy)`."""
  resolved = resolve_sensitivity_tier(tier, strict=strict)
  return resolved, dict(SENSITIVITY_THRESHOLD_MAP[resolved])


def resolve_micro_sensitivity_tier(
    tier: Optional[str] = None,
    *,
    strict: bool = False,
) -> str:
  """Resolves any macro or micro sensitivity label to canonical micro tier."""
  canonical = resolve_sensitivity_tier(tier, strict=strict)
  return MICRO_SENSITIVITY_FROM_CANONICAL[canonical]


# ---------------------------------------------------------------------------
# Canonical Z-Equivalent Score Semantics & Unit Registry (WS7-02)
# ---------------------------------------------------------------------------


class ScoreSemantics(NamedTuple):
  """Score normalization, direction, and unit metadata for a model output column."""

  kind: str
  threshold: float
  neutral: float
  is_true_sigma: bool


def _build_score_semantics_registry() -> Dict[str, ScoreSemantics]:
  """Builds the canonical score-column registry across all macro and micro templates."""
  reg: Dict[str, ScoreSemantics] = {}

  # 1. Standard 3.0σ true Z-scores (threshold = 3.0, neutral = 0.0, is_true_sigma = True)
  for k in (
      "z_score",
      "z",
      "personal_z",
      "poisson_z",
      "hourly_z",
      "upper_tail_z",
      "clamped_z",
      "raw_z",
      "shielded_z",
      "eb_z_score",
      "bayesian_z",
      "delta_z",
      "targeted_delta_z",
      "z_vs_team",
      "z_vs_enterprise",
      "z_team_vs_enterprise",
      "z_sector",
      "macro_z",
      "macro_z_score",
      "fast_z",
      "slow_z",
      "flow_z",
      "fail_z",
      "target_z",
      "alert_z",
      "process_z",
      "intensity_z",
      "breadth_z",
      "hurdle_z",
      "asymmetric_z",
      "macd_z",
      "circadian_z",
      "dest_z",
      "write_z",
      "del_z",
      "create_z",
      "origin_z",
      "daily_z",
      "max_daily_z",
      "z_a",
      "z_b",
      "z_auth",
      "z_proc",
      "z_net",
      "z_dns",
      "z_cloud",
      "z_workspace",
      "z_web",
      "z_alerts",
      "z_fail",
      "z_succ",
      "z_dns_fail",
  ):
    reg[k] = ScoreSemantics("linear", DEFAULT_ANOMALY_THRESHOLD, 0.0, True)

  # 2. Robust / Quantile 3.5σ true Z-scores (threshold = 3.5 -> Z_equiv = 3.0)
  for k in ("modified_z", "m_z_score", "m_z", "quantile_z", "fence_z"):
    reg[k] = ScoreSemantics("linear", DEFAULT_ROBUST_THRESHOLD, 0.0, True)

  # 3. Fleet / Log-normal 2.5σ true Z-scores (threshold = 2.5 -> Z_equiv = 3.0)
  for k in ("fleet_z", "z_log"):
    reg[k] = ScoreSemantics("linear", 2.5, 0.0, True)

  # 4. Inverted true Z-score (diversity deficit: threshold = -1.5 -> Z_equiv = 3.0)
  reg["diversity_z"] = ScoreSemantics("inverted_sigma", -1.5, 0.0, True)

  # 5. Inverted non-sigma ratio (coefficient of variation: neutral = 0.50, threshold = 0.20 -> Z_equiv = 3.0)
  reg["cv"] = ScoreSemantics("inverted_ratio", 0.20, 0.50, False)

  # 6. Baseline-offset ratios/factors (neutral = 1.0 -> Z_equiv = 0.0; threshold -> Z_equiv = 3.0)
  for k in (
      "fold_change",
      "surge_ratio",
      "hourly_surge_ratio",
      "tukey_fence_ratio",
      "bayes_shift_ratio",
      "empirical_shift",
      "posterior_lift",
  ):
    reg[k] = ScoreSemantics("baseline_offset", DEFAULT_FOLD_CHANGE_THRESHOLD, 1.0, False)
  reg["ratio_1v7"] = ScoreSemantics("baseline_offset", 3.0, 1.0, False)
  reg["ratio_1v30"] = ScoreSemantics("baseline_offset", 5.0, 1.0, False)
  reg["fano_factor"] = ScoreSemantics("baseline_offset", 4.0, 1.0, False)

  # relative_deviation.yl2 defines $ratio = ($observed - $hist_avg)/$safe_hist_avg = $fold_change - 1.0
  reg["ratio"] = ScoreSemantics("linear", 1.0, 0.0, False)

  # 7. Bounded probabilities / ratios & specialized non-sigma model scores
  for k in ("posterior_fail_prob", "regularized_failure_prob", "posterior_rate", "error_ratio", "fail_ratio"):
    reg[k] = ScoreSemantics("linear", 0.50, 0.0, False)
  reg["concentration_ratio"] = ScoreSemantics("linear", 0.65, 0.0, False)
  reg["producer_ratio"] = ScoreSemantics("linear", 0.70, 0.0, False)
  for k in ("shannon_entropy_score", "entropy_score"):
    reg[k] = ScoreSemantics("linear", 5.5, 0.0, False)
  for k in ("zipf_rarity_score", "rarity_score"):
    reg[k] = ScoreSemantics("linear", 2.5, 0.0, False)
  for k in ("ewma_velocity_score", "velocity_score"):
    reg[k] = ScoreSemantics("linear", 2.0, 0.0, False)
  reg["velocity_kmh"] = ScoreSemantics("linear", 900.0, 0.0, False)

  # 8. Adaptive threshold excess ($personal_z - $dynamic_threshold: 0.0 -> Z_equiv = 3.0, <= -3.0 -> 0.0)
  reg["sensitivity_excess"] = ScoreSemantics("excess", 0.0, -DEFAULT_ANOMALY_THRESHOLD, False)

  # 9. Squared Euclidean norms / squared Poisson Z
  for k in (
      "composite_threat_norm_sq",
      "threat_distance_sq",
      "d_vs_fleet_sq",
      "d_vs_team_sq",
      "d_sq",
      "norm_sq",
      "poisson_z_sq",
  ):
    reg[k] = ScoreSemantics("squared", DEFAULT_FUSION_THRESHOLD_SQ, 0.0, False)
  reg["threat_vector_norm_sq"] = ScoreSemantics("squared", 9.0, 0.0, False)

  # 10. Dimensionless / composite threat scores anchored at 3.0 (NOT true single-metric sigma)
  for k in (
      "threat_distance",
      "composite_threat_distance",
      "threat_norm",
      "composite_risk",
      "cusum_drift_score",
      "cusum_s",
      "cusum_pos",
      "circadian_threat_score",
      "macd_momentum_score",
      "beacon_score",
      "recon_score",
      "target_risk_score",
      "normalized_odds_score",
      "fused_threat_score",
      "markov_threat_score",
      "threat_score",
      "hurdle_threat_score",
      "hurdle_anomaly_score",
      "anomaly_score",
      "score",
  ):
    reg[k] = ScoreSemantics("linear", DEFAULT_ANOMALY_THRESHOLD, 0.0, False)

  # 11. Pre-computed [0..100] CRI columns
  for k in ("cri", "cri_score"):
    reg[k] = ScoreSemantics("precomputed_cri", float(WRITEBACK_CRI_THRESHOLD), 0.0, False)

  return reg


SCORE_SEMANTICS_REGISTRY: Dict[str, ScoreSemantics] = _build_score_semantics_registry()


def get_score_semantics(score_key: Optional[str]) -> ScoreSemantics:
  """Returns canonical `ScoreSemantics` for any template output column."""
  key = (score_key or "").strip().lstrip("$").lower()
  if not key:
    return ScoreSemantics("linear", DEFAULT_ANOMALY_THRESHOLD, 0.0, False)
  if key in SCORE_SEMANTICS_REGISTRY:
    return SCORE_SEMANTICS_REGISTRY[key]
  if key.endswith("_sq"):
    return ScoreSemantics("squared", DEFAULT_FUSION_THRESHOLD_SQ, 0.0, False)
  if (key.startswith(("z_", "sector_z_")) or key.endswith("_z")) and not key.endswith(
      ("_sq", "_raw", "_pos")
  ):
    return ScoreSemantics("linear", DEFAULT_ANOMALY_THRESHOLD, 0.0, True)
  return ScoreSemantics("linear", DEFAULT_ANOMALY_THRESHOLD, 0.0, False)


def is_true_sigma_key(score_key: Optional[str]) -> bool:
  """Returns True ONLY when `score_key` represents a genuine standard-deviation Z-score."""
  return get_score_semantics(score_key).is_true_sigma


def is_inverted_score_key(score_key: Optional[str]) -> bool:
  """Returns True when lower raw values indicate higher anomaly severity (e.g., `cv`, `diversity_z`)."""
  return get_score_semantics(score_key).kind in ("inverted_ratio", "inverted_sigma")


def score_to_z_equivalent(
    score_key: Optional[str],
    value: Any,
    *,
    already_sqrt: bool = False,
    threshold_override: Optional[float] = None,
) -> Optional[float]:
  """Maps any model's native score onto the canonical Z-equivalent scale where threshold == 3.0."""
  val = _coerce_finite_float(value)
  if val is None:
    return None
  sem = get_score_semantics(score_key)
  thresh = (
      _coerce_finite_float(threshold_override)
      if threshold_override is not None
      else sem.threshold
  )
  if thresh is None:
    return None

  if sem.kind == "linear":
    if val <= sem.neutral or thresh <= sem.neutral:
      return 0.0
    return ((val - sem.neutral) / (thresh - sem.neutral)) * DEFAULT_ANOMALY_THRESHOLD

  if sem.kind == "baseline_offset":
    if val <= sem.neutral or thresh <= sem.neutral:
      return 0.0
    return ((val - sem.neutral) / (thresh - sem.neutral)) * DEFAULT_ANOMALY_THRESHOLD

  if sem.kind == "inverted_ratio":
    if val < 0.0:
      return None
    if val >= sem.neutral or sem.neutral <= thresh:
      return 0.0
    return ((sem.neutral - val) / (sem.neutral - thresh)) * DEFAULT_ANOMALY_THRESHOLD

  if sem.kind == "inverted_sigma":
    if val >= sem.neutral or sem.neutral <= thresh:
      return 0.0
    return ((sem.neutral - val) / (sem.neutral - thresh)) * DEFAULT_ANOMALY_THRESHOLD

  if sem.kind == "excess":
    if val <= sem.neutral or thresh <= sem.neutral:
      return 0.0
    return ((val - sem.neutral) / (thresh - sem.neutral)) * DEFAULT_ANOMALY_THRESHOLD

  if sem.kind == "squared":
    if val <= 0.0 or thresh <= 0.0:
      return 0.0
    root_val = val if already_sqrt else math.sqrt(val)
    root_thresh = math.sqrt(thresh)
    if root_thresh <= 0.0:
      return 0.0
    return (root_val / root_thresh) * DEFAULT_ANOMALY_THRESHOLD

  if sem.kind == "precomputed_cri":
    clamped = max(0.0, min(100.0, val))
    if clamped <= 0.0:
      return 0.0
    if clamped >= 100.0:
      return 15.0
    z_inv = DEFAULT_ANOMALY_THRESHOLD - (math.log((100.0 - clamped) / clamped) / 0.6)
    return max(0.0, z_inv)

  return max(0.0, val)


def cri_from_model_score(
    score_key: Optional[str],
    value: Any,
    *,
    already_sqrt: bool = False,
    threshold_override: Optional[float] = None,
) -> Optional[int]:
  """Computes canonical [0..100] CRI for a model's native score via its Z-equivalent mapping."""
  val = _coerce_finite_float(value)
  if val is None:
    return None
  sem = get_score_semantics(score_key)
  if sem.kind == "precomputed_cri":
    return coerce_cri_int(val)
  z_equiv = score_to_z_equivalent(
      score_key,
      val,
      already_sqrt=already_sqrt,
      threshold_override=threshold_override,
  )
  return calculate_cri(z_equiv, DEFAULT_ANOMALY_THRESHOLD)


def format_score_with_unit(
    score_key: Optional[str],
    value: Any,
    decimals: int = 2,
) -> str:
  """Formats a model score, appending signed `σ` ONLY for true standard-deviation Z-scores."""
  val = _coerce_finite_float(value)
  if val is None:
    return "N/A"
  if is_true_sigma_key(score_key):
    return f"{val:+.{decimals}f}σ"
  return f"{val:.{decimals}f}"
