"""Re-syncs (or checks) the vendored Malachite catalog data against google3.

Vendored files (data/malachite/):
  dimension_field_mapping.textproto  verbatim copy
  config.proto                       verbatim copy (schema of config.textproto)
  ueba_metric.proto                  verbatim copy (schema of the mapping)
  config_dimensions.textproto        reduced copy of config.textproto: only
                                     metric_name + dimensions are kept. The
                                     query / filter_string fields are dropped
                                     because they reference or embed SQL.

Usage:
  python3 -m scripts.sync_malachite_catalog --check [--google3 PATH]
  python3 -m scripts.sync_malachite_catalog --write [--google3 PATH] [--cl CL]

Author: Greg Kushmerek
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Tuple

from . import malachite_catalog as mc

DEFAULT_GOOGLE3 = Path("/google/src/head/depot/google3")
MALACHITE_REL = Path("googlex/security/malachite")
CONFIG_REL = MALACHITE_REL / "analytics/configs/config.textproto"
VERBATIM: Tuple[Tuple[Path, str], ...] = (
    (MALACHITE_REL / "rules/yl2/compiler/ueba/dimension_field_mapping.textproto", "dimension_field_mapping.textproto"),
    (MALACHITE_REL / "analytics/configs/config.proto", "config.proto"),
    (MALACHITE_REL / "rules/proto/ueba_metric.proto", "ueba_metric.proto"),
)


def reduced_header(cl: str) -> str:
  return (
      "# proto-file: config.proto (vendored copy of googlex/security/malachite/analytics/configs/config.proto)\n"
      "# proto-message: googlex.security.malachite.analytics.MetricConfig\n"
      "#\n"
      f"# Reduced copy of googlex/security/malachite/analytics/configs/config.textproto @ CL {cl}.\n"
      "# Only metric_name and dimensions are kept. query, filter_string, shard_number and\n"
      "# has_sum_measure are removed because they reference or embed baseline SQL.\n"
      "# Each query_info block is one valid dimension set for the metric.\n"
      "# Regenerate with: python3 -m scripts.sync_malachite_catalog --write --cl <CL>"
  )


def _read_vendored_cl() -> str:
  for line in mc.CONFIG_DIMENSIONS_PATH.read_text(encoding="utf-8").splitlines():
    if "@ CL " in line:
      return line.split("@ CL ", 1)[1].split(".", 1)[0].strip()
  return "unknown"


def check(google3: Path) -> List[str]:
  """Returns a list of human-readable drift findings (empty = in sync)."""
  problems: List[str] = []
  src_cfg = google3 / CONFIG_REL
  upstream = mc.parse_config_query_infos(src_cfg.read_text(encoding="utf-8"))
  vendored = mc.parse_config_query_infos(mc.CONFIG_DIMENSIONS_PATH.read_text(encoding="utf-8"))
  up_set = {(m, frozenset(d)) for m, d in upstream}
  ve_set = {(m, frozenset(d)) for m, d in vendored}
  for m, d in sorted(up_set - ve_set):
    problems.append(f"config: upstream has {m} {sorted(d)} but vendored copy does not")
  for m, d in sorted(ve_set - up_set):
    problems.append(f"config: vendored copy has {m} {sorted(d)} but upstream does not")
  for rel, name in VERBATIM:
    if (google3 / rel).read_bytes() != (mc.MALACHITE_DATA_DIR / name).read_bytes():
      problems.append(f"{name}: differs from {rel}")
  return problems


def write(google3: Path, cl: str) -> None:
  upstream = mc.parse_config_query_infos((google3 / CONFIG_REL).read_text(encoding="utf-8"))
  mc.MALACHITE_DATA_DIR.mkdir(parents=True, exist_ok=True)
  mc.CONFIG_DIMENSIONS_PATH.write_text(mc.render_reduced_config(upstream, reduced_header(cl)), encoding="utf-8")
  for rel, name in VERBATIM:
    (mc.MALACHITE_DATA_DIR / name).write_bytes((google3 / rel).read_bytes())


def main(argv: List[str]) -> int:
  ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
  ap.add_argument("--google3", type=Path, default=DEFAULT_GOOGLE3)
  mode = ap.add_mutually_exclusive_group(required=True)
  mode.add_argument("--check", action="store_true")
  mode.add_argument("--write", action="store_true")
  ap.add_argument("--cl", default=None, help="CL number recorded in the reduced config header (--write)")
  args = ap.parse_args(argv)
  if args.write:
    write(args.google3, args.cl or _read_vendored_cl())
    print(f"Wrote vendored catalog to {mc.MALACHITE_DATA_DIR}")
    return 0
  problems = check(args.google3)
  for p in problems:
    print("DRIFT:", p)
  print("in sync" if not problems else f"{len(problems)} drift finding(s)")
  return 1 if problems else 0


if __name__ == "__main__":
  sys.exit(main(sys.argv[1:]))
