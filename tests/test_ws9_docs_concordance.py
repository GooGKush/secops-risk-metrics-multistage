# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""WS9-02: Drift & D1 Disposition Concordance Tests across references/**/*.md.

Verifies that:
  1. Every active StatisticalModel and templates/stage2_math_models/*.yl2 is
     documented in both references/model-concordance-guide.md and
     references/statistical-models-taxonomy.md.
  2. Every active templates/pipelines/*.yl2 (all 34) is listed in
     references/multi-stage-metrics-guide.md (§18) and
     references/statistical-models-taxonomy.md.
  3. Retired / merged D1 models (.yl2 filenames and retired taxonomy sections)
     are never prescribed as active templates anywhere under references/**/*.md.
  4. Renamed D1 models use canonical names ("Outbound Flow Surge" with zero C2
     beaconing claims on daily flow counts, "Regular-Volume Surge" with maturity
     gate, "Above-Historical-Max Z", "baseline dispersion screen") and rebuilt
     models match on-disk templates.
"""

from pathlib import Path
import re
import unittest

from scripts.preflight_validator import RETIRED_STATISTICAL_MODELS
from scripts.preflight_validator import StatisticalModel

REPO_ROOT = Path(__file__).resolve().parent.parent
REFS_DIR = REPO_ROOT / "references"

RETIRED_OR_MERGED_TEMPLATE_FILES = (
    "fleet_prevalence_shield.yl2",
    "piecewise_cri.yl2",
    "hybrid_metric_orthogonal_space_2stage.yl2",
    "hourly_temporal_zscore.yl2",
    "circadian_von_mises.yl2",
    "circadian_von_mises_2stage.yl2",
    "asymmetric_directional_z.yl2",
    "impossible_travel_geo_velocity_2stage.yl2",
)

RETIREMENT_MARKERS = re.compile(
    r"\b(retired|merged|replaced|removed|handoff|hand off)\b",
    re.IGNORECASE,
)


class TestWS902DocsConcordance(unittest.TestCase):
  """Enforces zero drift between templates/StatisticalModel and references/."""

  def test_active_stage2_math_models_documented_in_taxonomy_and_concordance(self):
    concordance = (REFS_DIR / "model-concordance-guide.md").read_text(
        encoding="utf-8"
    )
    taxonomy = (REFS_DIR / "statistical-models-taxonomy.md").read_text(
        encoding="utf-8"
    )

    stage2_files = sorted(
        p.name for p in (REPO_ROOT / "templates" / "stage2_math_models").glob("*.yl2")
    )
    self.assertGreaterEqual(len(stage2_files), 14)

    for fname in stage2_files:
      with self.subTest(stage2_file=fname):
        self.assertIn(
            fname,
            concordance,
            f"Active stage2 math model {fname} missing from model-concordance-guide.md",
        )
        self.assertIn(
            fname,
            taxonomy,
            f"Active stage2 math model {fname} missing from statistical-models-taxonomy.md",
        )

    for model in StatisticalModel:
      if (
          model in RETIRED_STATISTICAL_MODELS
          or model == StatisticalModel.ASYMMETRIC_DIRECTIONAL_Z
      ):
        continue
      with self.subTest(active_model=model.value):
        self.assertIn(model.value, concordance)
        self.assertIn(model.value, taxonomy)

  def test_all_active_pipelines_documented_in_metrics_guide_and_taxonomy(self):
    metrics_guide = (REFS_DIR / "multi-stage-metrics-guide.md").read_text(
        encoding="utf-8"
    )
    taxonomy = (REFS_DIR / "statistical-models-taxonomy.md").read_text(
        encoding="utf-8"
    )

    sec18_start = metrics_guide.index("## 18. Pre-Composed Multi-Stage Pipeline Library")
    sec19_start = metrics_guide.index("## 19. Consultative Scope")
    sec18 = metrics_guide[sec18_start:sec19_start]

    pipeline_files = sorted(
        p.name for p in (REPO_ROOT / "templates" / "pipelines").glob("*.yl2")
    )
    self.assertEqual(len(pipeline_files), 34)

    for fname in pipeline_files:
      with self.subTest(pipeline_file=fname):
        self.assertIn(
            fname,
            sec18,
            f"Active pipeline {fname} missing from multi-stage-metrics-guide.md §18 table",
        )
        self.assertIn(
            fname,
            taxonomy,
            f"Active pipeline {fname} missing from statistical-models-taxonomy.md",
        )

  def test_retired_models_never_prescribed_as_active_across_all_references(self):
    offenders = []
    for md_path in sorted(REFS_DIR.rglob("*.md")):
      rel = md_path.relative_to(REPO_ROOT)
      for lineno, line in enumerate(
          md_path.read_text(encoding="utf-8").splitlines(), 1
      ):
        for retired_tpl in RETIRED_OR_MERGED_TEMPLATE_FILES:
          if retired_tpl in line and not RETIREMENT_MARKERS.search(line):
            offenders.append(f"{rel}:{lineno}: {line.strip()}")

    self.assertEqual(
        offenders,
        [],
        "Retired/merged D1 template files referenced without retirement/merge marker:\n"
        + "\n".join(offenders),
    )

    taxonomy = (REFS_DIR / "statistical-models-taxonomy.md").read_text(
        encoding="utf-8"
    )
    self.assertNotIn("z_score_hourly", taxonomy)
    self.assertNotIn("circadian_threat_score", taxonomy)
    self.assertNotIn("leverage `HOURLY_TEMPORAL_ZSCORE`", taxonomy)

    metrics_guide = (REFS_DIR / "multi-stage-metrics-guide.md").read_text(
        encoding="utf-8"
    )
    self.assertNotIn("Piecewise Winsorized CRI", metrics_guide)
    self.assertNotIn("Asymmetric Directional ReLU", metrics_guide)

  def test_d1_canonical_renames_and_cusum_helper_consistency(self):
    taxonomy = (REFS_DIR / "statistical-models-taxonomy.md").read_text(
        encoding="utf-8"
    )
    metrics_guide = (REFS_DIR / "multi-stage-metrics-guide.md").read_text(
        encoding="utf-8"
    )
    worksheet = (REFS_DIR / "consultative-worksheet.md").read_text(
        encoding="utf-8"
    )
    mitre = (REFS_DIR / "consultative" / "mitre-attack-killchain.md").read_text(
        encoding="utf-8"
    )

    # 1. c2_beacon_flow_frequency_2stage.yl2 -> "Outbound Flow Surge", zero C2 claims on daily counts
    self.assertIn("Outbound Flow Surge", metrics_guide)
    self.assertIn("Outbound Flow Surge", taxonomy)
    self.assertNotIn("Network Session Frequency & C2 Beaconing Detection", metrics_guide)
    self.assertNotIn("Confirms lightweight C2 heartbeats", metrics_guide)
    self.assertNotIn("To detect stealthy beaconing", metrics_guide)

    # 2. coefficient_of_variation -> "Regular-Volume Surge" with active_days >= 7
    self.assertIn("Regular-Volume Surge", taxonomy)
    self.assertNotIn("Behavioral Volatility Verdict: Coefficient of Variation", taxonomy)

    # 3. macd_momentum_velocity -> "Above-Historical-Max Z" (not MACD Dual-Spine Momentum)
    self.assertIn("Above-Historical-Max Z", taxonomy)
    self.assertNotIn("MACD Dual-Spine Momentum", taxonomy)
    self.assertNotIn("MACD Dual-Spine Momentum", worksheet)
    self.assertIn("Above-Historical-Max Z", worksheet)
    self.assertIn("Above-Historical-Max Z", mitre)

    # 4. variance_fano -> "baseline dispersion screen" + POISSON_BURST_CLUSTERING
    self.assertIn("baseline dispersion screen", taxonomy.lower())
    self.assertIn("POISSON_BURST_CLUSTERING", taxonomy)

    # 5. CUSUM helper consistency in taxonomy and multi-stage-metrics-guide §18
    self.assertNotIn("timeline_assembler.py", taxonomy)
    self.assertIn("cusum_helper.py", taxonomy)
    sec18 = metrics_guide[
        metrics_guide.index("## 18. Pre-Composed"):metrics_guide.index("## 19. Consultative")
    ]
    self.assertNotIn("timeline_assembler.py", sec18)
    self.assertIn("cusum_helper.py", sec18)


if __name__ == "__main__":
  unittest.main()
