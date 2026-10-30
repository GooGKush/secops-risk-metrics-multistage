# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Contract tests for canonical 360° behavioral radar sector templates (REG-P1-16)."""

from pathlib import Path
import unittest

from scripts.preflight_validator import MalachiteASTValidator
from scripts.radar_collector import EntityRadarCollector

REPO_ROOT = Path(__file__).resolve().parent.parent
RADAR_TPL_DIR = REPO_ROOT / "templates" / "radar_360"

EXPECTED_USER_SECTOR_TEMPLATES = (
    ("user_1_auth_risk.yl2", "stage auth_risk {", "metrics.auth_attempts_total"),
    ("user_2_cloud_risk.yl2", "stage cloud_risk {", "metrics.resource_read_total"),
    ("user_3_workspace_risk.yl2", "stage workspace_risk {", "metrics.workspace_total_download_actions"),
    ("user_4_egress_risk.yl2", "stage egress_risk {", "metrics.network_bytes_outbound"),
    ("user_5_dns_risk.yl2", "stage dns_risk {", "metrics.dns_queries_"),
    ("user_6_web_risk.yl2", "stage web_risk {", "metrics.http_queries_total"),
)

EXPECTED_COLLECTOR_STAGES = {
    "IAM & Authentication": "stage auth_risk {",
    "Cloud Infrastructure": "stage cloud_risk {",
    "Workspace Data Hoarding": "stage workspace_risk {",
    "Network Egress & Web": "stage egress_risk {",
    "DNS Resolution": "stage dns_risk {",
    "Web & Proxy Activity": "stage web_risk {",
}


class TestRadar360CanonicalTemplates(unittest.TestCase):
  """Ensures all 6 canonical USER 360° sector queries exist as templates and SKILL.md points to them."""

  def test_six_canonical_user_sector_templates_exist_and_validate(self) -> None:
    self.assertTrue(RADAR_TPL_DIR.is_dir(), f"Missing directory: {RADAR_TPL_DIR}")
    for filename, expected_stage, expected_metric in EXPECTED_USER_SECTOR_TEMPLATES:
      with self.subTest(template=filename):
        path = RADAR_TPL_DIR / filename
        self.assertTrue(path.is_file(), f"Missing canonical 360 sector template: {path}")
        raw = path.read_text(encoding="utf-8")
        self.assertIn(expected_stage, raw)
        self.assertIn(expected_metric, raw)
        self.assertIn("// NO-GATE:", raw)
        rendered = raw.replace("{{entity_id}}", "frank.kolzig")
        errors = MalachiteASTValidator.validate_query(rendered)
        self.assertEqual(errors, [], f"AST validation errors in {filename}: {errors}")

  def test_skill_md_points_to_radar_360_templates_verbatim(self) -> None:
    skill_md = (REPO_ROOT / "SKILL.md").read_text(encoding="utf-8")
    self.assertIn("templates/radar_360/", skill_md)
    self.assertIn("copy verbatim, substitute only the entity", skill_md)

  def test_radar_collector_user_sectors_use_canonical_stage_names(self) -> None:
    for sector_name, expected_stage in EXPECTED_COLLECTOR_STAGES.items():
      with self.subTest(sector=sector_name):
        rendered = EntityRadarCollector.USER_SECTOR_QUERIES[sector_name] % {
            "entity_id": "frank.kolzig"
        }
        self.assertIn(expected_stage, rendered)
        self.assertNotIn("stage s1 {", rendered)


if __name__ == "__main__":
  unittest.main()
