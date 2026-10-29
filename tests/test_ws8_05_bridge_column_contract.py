# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""WS8-05: Contract tests enforcing canonical %ueba_hunt_bridge.entity column syntax.

Ensures templates, router/engine code, SKILL.md, references, and active README
documentation all standardize on `in %ueba_hunt_bridge.entity` without column
name drift (`%ueba_hunt_bridge.hostname`, `%ueba_hunt_bridge.caller_ip`, etc.).
"""

from pathlib import Path
import re
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from scripts.preflight_validator import EntityType, MalachiteASTValidator, QueryIntegrityGate
from scripts.template_router import ChainedHuntRouter


BRIDGE_COL_RE = re.compile(r"%ueba_hunt_bridge\.([A-Za-z0-9_]+)")
BRIDGE_EQ_RE = re.compile(r"=\s*%ueba_hunt_bridge\.[A-Za-z0-9_]+")


class TestWS805BridgeColumnContract(unittest.TestCase):
  """Enforces canonical `%ueba_hunt_bridge.entity` across templates, code, and active docs."""

  def test_hybrid_data_table_bridge_template_uses_canonical_entity_column(self):
    tpl_path = REPO_ROOT / "templates" / "pipelines" / "hybrid_data_table_bridge_2stage.yl2"
    tpl_text = tpl_path.read_text(encoding="utf-8")
    self.assertIn("in %ueba_hunt_bridge.entity", tpl_text)
    self.assertEqual(set(BRIDGE_COL_RE.findall(tpl_text)), {"entity"})
    self.assertIsNone(BRIDGE_EQ_RE.search(tpl_text))
    self.assertEqual(MalachiteASTValidator.validate_query(tpl_text), [])
    gate_report = QueryIntegrityGate.verify_pre_dispatch(
        tpl_text, require_metrics=True
    )
    self.assertTrue(gate_report["valid"], gate_report)

  def test_chained_hunt_router_builds_canonical_entity_bridge_query(self):
    for ent_type in (EntityType.ASSET, EntityType.USER):
      with self.subTest(entity_type=ent_type):
        metric = "network_bytes_outbound" if ent_type == EntityType.ASSET else "auth_attempts_fail"
        query = ChainedHuntRouter.build_data_table_bridge_query(
            entity_type=ent_type,
            target_metric=metric,
        )
        self.assertIn("in %ueba_hunt_bridge.entity", query)
        self.assertEqual(set(BRIDGE_COL_RE.findall(query)), {"entity"})
        self.assertEqual(MalachiteASTValidator.validate_query(query), [])

  def test_skill_md_and_scripts_use_only_canonical_bridge_column(self):
    files_to_check = [REPO_ROOT / "SKILL.md"] + sorted(
        (REPO_ROOT / "scripts").rglob("*.py")
    ) + sorted((REPO_ROOT / "templates").rglob("*.yl2"))

    saw_bridge = False
    for path in files_to_check:
      text = path.read_text(encoding="utf-8")
      cols = BRIDGE_COL_RE.findall(text)
      if cols:
        saw_bridge = True
      rel = path.relative_to(REPO_ROOT)
      for col in cols:
        self.assertEqual(
            col,
            "entity",
            f"Non-canonical %ueba_hunt_bridge.{col} found in {rel}",
        )
      self.assertIsNone(
          BRIDGE_EQ_RE.search(text),
          f"Deprecated '= %ueba_hunt_bridge.<col>' operator found in {rel}; use 'in %ueba_hunt_bridge.entity'",
      )
    self.assertTrue(saw_bridge)

  def test_references_and_active_readme_have_zero_bridge_column_drift(self):
    ref_files = sorted((REPO_ROOT / "references").rglob("*.md"))
    for path in ref_files:
      text = path.read_text(encoding="utf-8")
      rel = path.relative_to(REPO_ROOT)
      for col in BRIDGE_COL_RE.findall(text):
        self.assertEqual(
            col,
            "entity",
            f"Non-canonical %ueba_hunt_bridge.{col} found in {rel}",
        )
      self.assertIsNone(
          BRIDGE_EQ_RE.search(text),
          f"Deprecated '= %ueba_hunt_bridge.<col>' operator found in {rel}; use 'in %ueba_hunt_bridge.entity'",
      )

    readme_full = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    # Exclude historical release notes section at the bottom of README.md
    active_readme = readme_full.split("## 📦 Recent Releases")[0]
    readme_cols = BRIDGE_COL_RE.findall(active_readme)
    self.assertGreaterEqual(len(readme_cols), 1)
    for col in readme_cols:
      self.assertEqual(
          col,
          "entity",
          f"Non-canonical %ueba_hunt_bridge.{col} found in active README.md",
      )
    self.assertIsNone(
        BRIDGE_EQ_RE.search(active_readme),
        "Deprecated '= %ueba_hunt_bridge.<col>' operator found in active README.md; use 'in %ueba_hunt_bridge.entity'",
    )


if __name__ == "__main__":
  unittest.main()
