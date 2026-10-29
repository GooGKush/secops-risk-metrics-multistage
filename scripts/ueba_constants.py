# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Canonical Shared UEBA Thresholds, Tiers, and CRI Semantics (WS2-08, WS7-01).

This module is duplicated byte-for-byte identically across both skills in the
Bilateral UEBA Harness (`secops-risk-metrics-multistage` and
`secops-statistical-hunter`) per Rule 3 (self-contained skills, zero cross-repo
imports at runtime) and verified via SHA-256 contract tests.
"""

import math
from typing import Any, Dict, Optional, Tuple

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
