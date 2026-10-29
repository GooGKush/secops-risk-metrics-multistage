# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Canonical Shared UEBA Thresholds and Sensitivity Tiers (WS2-08).

This module is duplicated byte-for-byte identically across both skills in the
Bilateral UEBA Harness (`secops-risk-metrics-multistage` and
`secops-statistical-hunter`) per Rule 3 (self-contained skills, zero cross-repo
imports at runtime) and verified via SHA-256 contract tests.
"""

from typing import Dict, Optional, Tuple

# ---------------------------------------------------------------------------
# Sensitivity Tier Thresholds & Cross-Skill Alias Resolution
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
# Operational Baselines, Fusion, Write-Back, Loopback & Window Caps
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
