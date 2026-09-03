"""360-Degree Entity Behavioral Risk Radar Collector & Visualizer for Google SecOps.

Author: Greg Kushmerek
Specification: 360 Entity Behavioral Risk Fingerprint & Playbook Hook
"""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
import json
import math
import sys
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class MetricSpoke:
  """Represents a single radial spoke in the 360-degree risk radar."""
  sector: str
  spoke_name: str
  metric_table: str
  observed: float
  baseline_mean: float
  baseline_stddev: float
  z_score: float
  unit: str = "events"
  cri_score: int = 0

  def __post_init__(self):
    if self.cri_score == 0 and self.z_score is not None:
      self.cri_score = round(100.0 / (1.0 + math.exp(-0.6 * (max(0.0, self.z_score) - 3.0))))

  def to_dict(self) -> Dict[str, Any]:
    return asdict(self)


class EntityRadarCollector:
  """Collects multi-sector behavioral metrics for an entity and renders radial risk fingerprints."""

  USER_SECTOR_QUERIES = {
      "IAM & Authentication": """
// Sector: IAM & Authentication
stage s1 {
    metadata.event_type = "USER_LOGIN"
    security_result.action = "BLOCK"
    target.user.userid = "%(entity_id)s"
    $user = target.user.userid
  match:
    $user by 1d
  outcome:
    $fail_obs = count(metadata.id)
    $fail_avg = max(metrics.auth_attempts_fail(period: 1d, window: 30d, metric: event_count_sum, agg: avg, target.user.userid: "%(entity_id)s"))
    $fail_std = max(metrics.auth_attempts_fail(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, target.user.userid: "%(entity_id)s"))
}
stage s2 {
    metadata.event_type = "USER_LOGIN"
    security_result.action = "ALLOW"
    target.user.userid = "%(entity_id)s"
    $user = target.user.userid
  match:
    $user by 1d
  outcome:
    $succ_obs = count(metadata.id)
    $succ_avg = max(metrics.auth_attempts_success(period: 1d, window: 30d, metric: event_count_sum, agg: avg, target.user.userid: "%(entity_id)s"))
    $succ_std = max(metrics.auth_attempts_success(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, target.user.userid: "%(entity_id)s"))
}
$user = $s1.user
$user = $s2.user
match: $user by 1d
outcome:
  $z_fail = (max($s1.fail_obs) - max($s1.fail_avg)) / (max($s1.fail_std) + 1.0)
  $z_succ = (max($s2.succ_obs) - max($s2.succ_avg)) / (max($s2.succ_std) + 1.0)
""",
      "Cloud Infrastructure": """
// Sector: Cloud Infrastructure CRUD
stage s1 {
    metadata.event_type = "RESOURCE_CREATION"
    principal.user.userid = "%(entity_id)s"
    $user = principal.user.userid
    metadata.vendor_name = $v
    metadata.product_name = $p
  match:
    $user, $v, $p by 1d
  outcome:
    $create_obs = count(metadata.id)
    $create_avg = max(metrics.resource_creation_total(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.user.userid: "%(entity_id)s", metadata.vendor_name: $v, metadata.product_name: $p))
    $create_std = max(metrics.resource_creation_total(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, principal.user.userid: "%(entity_id)s", metadata.vendor_name: $v, metadata.product_name: $p))
}
stage s2 {
    metadata.event_type = "RESOURCE_DELETION"
    principal.user.userid = "%(entity_id)s"
    $user = principal.user.userid
    metadata.vendor_name = $v
    metadata.product_name = $p
  match:
    $user, $v, $p by 1d
  outcome:
    $delete_obs = count(metadata.id)
    $delete_avg = max(metrics.resource_deletion_total(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.user.userid: "%(entity_id)s", metadata.vendor_name: $v, metadata.product_name: $p))
    $delete_std = max(metrics.resource_deletion_total(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, principal.user.userid: "%(entity_id)s", metadata.vendor_name: $v, metadata.product_name: $p))
}
$user = $s1.user
$user = $s2.user
match: $user by 1d
outcome:
  $z_create = (max($s1.create_obs) - max($s1.create_avg)) / (max($s1.create_std) + 1.0)
  $z_delete = (max($s2.delete_obs) - max($s2.delete_avg)) / (max($s2.delete_std) + 1.0)
""",
      "Workspace Data Hoarding": """
// Sector: Workspace & Drive Data
stage s1 {
    metadata.event_type = "USER_RESOURCE_ACCESS"
    principal.user.userid = "%(entity_id)s"
    $user = principal.user.userid
  match:
    $user by 1d
  outcome:
    $dl_obs = count(metadata.id)
    $dl_avg = max(metrics.workspace_total_download_actions(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.user.userid: "%(entity_id)s"))
    $dl_std = max(metrics.workspace_total_download_actions(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, principal.user.userid: "%(entity_id)s"))
    $ch_avg = max(metrics.workspace_total_change_actions(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.user.userid: "%(entity_id)s"))
    $ch_std = max(metrics.workspace_total_change_actions(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, principal.user.userid: "%(entity_id)s"))
}
$user = $s1.user
match: $user by 1d
outcome:
  $z_download = (max($s1.dl_obs) - max($s1.dl_avg)) / (max($s1.dl_std) + 1.0)
  $z_change = (max($s1.dl_obs) - max($s1.ch_avg)) / (max($s1.ch_std) + 1.0)
""",
      "Network Egress & Web": """
// Sector: Network Egress Volume
stage s1 {
    metadata.event_type = "NETWORK_CONNECTION"
    principal.user.userid = "%(entity_id)s"
    $user = principal.user.userid
  match:
    $user by 1d
  outcome:
    $bytes_obs = sum(network.sent_bytes)
    $bytes_avg = max(metrics.network_bytes_outbound(period: 1d, window: 30d, metric: value_sum, agg: avg, principal.user.userid: "%(entity_id)s"))
    $bytes_std = max(metrics.network_bytes_outbound(period: 1d, window: 30d, metric: value_sum, agg: stddev, principal.user.userid: "%(entity_id)s"))
}
$user = $s1.user
match: $user by 1d
outcome:
  $z_egress = (max($s1.bytes_obs) - max($s1.bytes_avg)) / (max($s1.bytes_std) + 1.0)
""",
      "DNS & Web Activity": """
// Sector: DNS & Web Activity
stage s1 {
    metadata.event_type = "NETWORK_DNS"
    network.dns.response_code != 0
    principal.user.userid = "%(entity_id)s"
    $user = principal.user.userid
  match:
    $user by 1d
  outcome:
    $dns_obs = count(metadata.id)
    $dns_avg = max(metrics.dns_queries_fail(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.user.userid: "%(entity_id)s"))
    $dns_std = max(metrics.dns_queries_fail(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, principal.user.userid: "%(entity_id)s"))
}
$user = $s1.user
match: $user by 1d
outcome:
  $z_dns_fail = (max($s1.dns_obs) - max($s1.dns_avg)) / (max($s1.dns_std) + 1.0)
""",
  }

  ASSET_SECTOR_QUERIES = {
      "Authentication & Access": """
// Sector: Asset Authentication
stage s1 {
    metadata.event_type = "USER_LOGIN"
    security_result.action = "BLOCK"
    principal.asset.hostname = "%(entity_id)s"
    $asset = principal.asset.hostname
  match:
    $asset by 1d
  outcome:
    $fail_obs = count(metadata.id)
    $fail_avg = max(metrics.auth_attempts_fail(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.asset.hostname: "%(entity_id)s"))
    $fail_std = max(metrics.auth_attempts_fail(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, principal.asset.hostname: "%(entity_id)s"))
}
$asset = $s1.asset
match: $asset by 1d
outcome:
  $z_fail = (max($s1.fail_obs) - max($s1.fail_avg)) / (max($s1.fail_std) + 1.0)
""",
      "Network Traffic Volume": """
// Sector: Network Inbound & Outbound
stage s1 {
    metadata.event_type = "NETWORK_CONNECTION"
    principal.asset.hostname = "%(entity_id)s"
    $asset = principal.asset.hostname
  match:
    $asset by 1d
  outcome:
    $out_obs = sum(network.sent_bytes)
    $out_avg = max(metrics.network_bytes_outbound(period: 1d, window: 30d, metric: value_sum, agg: avg, principal.asset.hostname: "%(entity_id)s"))
    $out_std = max(metrics.network_bytes_outbound(period: 1d, window: 30d, metric: value_sum, agg: stddev, principal.asset.hostname: "%(entity_id)s"))
    $in_obs = sum(network.received_bytes)
    $in_avg = max(metrics.network_bytes_inbound(period: 1d, window: 30d, metric: value_sum, agg: avg, principal.asset.hostname: "%(entity_id)s"))
    $in_std = max(metrics.network_bytes_inbound(period: 1d, window: 30d, metric: value_sum, agg: stddev, principal.asset.hostname: "%(entity_id)s"))
}
$asset = $s1.asset
match: $asset by 1d
outcome:
  $z_outbound = (max($s1.out_obs) - max($s1.out_avg)) / (max($s1.out_std) + 1.0)
  $z_inbound = (max($s1.in_obs) - max($s1.in_avg)) / (max($s1.in_std) + 1.0)
""",
      "DNS Resolution": """
// Sector: DNS Failures
stage s1 {
    metadata.event_type = "NETWORK_DNS"
    network.dns.response_code != 0
    principal.asset.hostname = "%(entity_id)s"
    $asset = principal.asset.hostname
  match:
    $asset by 1d
  outcome:
    $dns_obs = count(metadata.id)
    $dns_avg = max(metrics.dns_queries_fail(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.asset.hostname: "%(entity_id)s"))
    $dns_std = max(metrics.dns_queries_fail(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, principal.asset.hostname: "%(entity_id)s"))
}
$asset = $s1.asset
match: $asset by 1d
outcome:
  $z_dns_fail = (max($s1.dns_obs) - max($s1.dns_avg)) / (max($s1.dns_std) + 1.0)
""",
  }

  def __init__(self, secops_client: Optional[Any] = None):
    self.client = secops_client

  @staticmethod
  def get_canonical_nominal_spokes(entity_type: str = "USER") -> List[MetricSpoke]:
    """Returns the 5 canonical nominal spokes (Z=0.00σ) when data is omitted or baseline is nominal."""
    if entity_type.upper() == "ASSET":
      return [
          MetricSpoke("Authentication", "Authentication & Access", "metrics.auth_attempts_fail", 0.0, 0.0, 0.0, 0.0, "logins", 0),
          MetricSpoke("Network", "Network Traffic Volume", "metrics.network_bytes_outbound", 0.0, 0.0, 0.0, 0.0, "bytes", 0),
          MetricSpoke("DNS", "DNS Resolution", "metrics.dns_queries_fail", 0.0, 0.0, 0.0, 0.0, "queries", 0),
          MetricSpoke("Cloud", "Cloud Infrastructure", "metrics.resource_creation_total", 0.0, 0.0, 0.0, 0.0, "events", 0),
          MetricSpoke("Endpoint", "Endpoint Process Activity", "PROCESS_LAUNCH", 0.0, 0.0, 0.0, 0.0, "events", 0),
      ]
    return [
        MetricSpoke("IAM & Authentication", "Authentication Attempts", "metrics.auth_attempts_fail", 0.0, 0.0, 0.0, 0.0, "logins", 0),
        MetricSpoke("Cloud Infrastructure", "Cloud Resource CRUD", "metrics.resource_creation_total", 0.0, 0.0, 0.0, 0.0, "events", 0),
        MetricSpoke("Workspace Data", "Workspace & SaaS Exfil", "metrics.workspace_total_download_actions", 0.0, 0.0, 0.0, 0.0, "actions", 0),
        MetricSpoke("Network Egress", "Network Egress", "metrics.network_bytes_outbound", 0.0, 0.0, 0.0, 0.0, "bytes", 0),
        MetricSpoke("DNS & Web Activity", "DNS & Web Activity", "metrics.dns_queries_fail", 0.0, 0.0, 0.0, 0.0, "queries", 0),
    ]

  @staticmethod
  def parse_scores_argument(scores_str: str, entity_type: str = "USER") -> List[MetricSpoke]:
    """Parses convenient comma-separated key=value scores (e.g. 'auth=0.0,cloud=3.8,workspace=3.2,net=0.8,proc=10.8')."""
    canonical = EntityRadarCollector.get_canonical_nominal_spokes(entity_type)
    if not scores_str:
      return canonical

    user_map = {
        "auth": 0, "iam": 0, "login": 0,
        "cloud": 1, "crud": 1, "resource": 1,
        "workspace": 2, "saas": 2, "drive": 2, "doc": 2,
        "net": 3, "network": 3, "egress": 3, "byte": 3,
        "dns": 4, "web": 4, "http": 4, "proc": 4, "endpoint": 4, "process": 4, "launch": 4,
    }
    asset_map = {
        "auth": 0, "login": 0, "access": 0,
        "net": 1, "network": 1, "traffic": 1,
        "dns": 2,
        "cloud": 3, "infra": 3, "crud": 3,
        "proc": 4, "endpoint": 4, "process": 4,
    }
    target_map = asset_map if entity_type.upper() == "ASSET" else user_map

    for part in scores_str.split(","):
      part = part.strip()
      if "=" in part:
        k, v = part.split("=", 1)
        k = k.strip().lower()
        try:
          val = float(v.strip())
          for prefix, idx in target_map.items():
            if prefix in k:
              canonical[idx].z_score = val
              if val > 0:
                canonical[idx].observed = max(1.0, round(val * 10.0))
                canonical[idx].baseline_mean = 5.0
                canonical[idx].baseline_stddev = 2.0
              canonical[idx].__post_init__()
              break
        except ValueError:
          pass
    return canonical

  @staticmethod
  def calculate_composite_risk(spokes: List[MetricSpoke]) -> Tuple[float, int]:
    """Calculates the Euclidean Composite Distance D and Calibrated Risk Index (CRI)."""
    if not spokes:
      return 0.0, 0

    sum_z_sq = sum(max(0.0, s.z_score) ** 2 for s in spokes)
    composite_d = math.sqrt(sum_z_sq)
    cri_score = round(100.0 / (1.0 + math.exp(-0.6 * (composite_d - 3.0))))
    return round(composite_d, 2), max(0, min(100, cri_score))

  def build_radar_payload(
      self,
      entity_id: str,
      entity_type: str,
      spokes: List[MetricSpoke],
  ) -> Dict[str, Any]:
    """Assembles the full radar payload including statistics, SVG, Markdown, and Chart.js specs."""
    active_spokes = spokes if spokes else self.get_canonical_nominal_spokes(entity_type)
    sorted_spokes = sorted(active_spokes, key=lambda s: s.z_score, reverse=True)
    composite_d, cri = self.calculate_composite_risk(sorted_spokes)

    top_outlier = sorted_spokes[0] if sorted_spokes else None
    is_anomalous = composite_d >= 3.0

    return {
        "entity_id": entity_id,
        "entity_type": entity_type.upper(),
        "composite_distance_d": composite_d,
        "calibrated_risk_index": cri,
        "is_anomalous": is_anomalous,
        "spoke_count": len(sorted_spokes),
        "top_outlier_spoke": top_outlier.spoke_name if top_outlier else "N/A",
        "top_outlier_z": top_outlier.z_score if top_outlier else 0.0,
        "spokes": [s.to_dict() for s in sorted_spokes],
        "svg_widget": self.generate_self_contained_svg(
            entity_id, sorted_spokes, composite_d, cri
        ),
        "html_widget": self.generate_html_widget(
            entity_id, sorted_spokes, composite_d, cri
        ),
        "data_uri_image": self.generate_data_uri_image(
            entity_id, sorted_spokes, composite_d, cri
        ),
        "dual_surface_embed": self.generate_dual_surface_embed(
            entity_id, sorted_spokes, composite_d, cri
        ),
        "ascii_chart": self.generate_ascii_chart(
            entity_id, sorted_spokes, composite_d, cri
        ),
        "markdown_table": self.generate_markdown_summary(
            entity_id, sorted_spokes, composite_d, cri
        ),
        "chartjs_spec": self.generate_chartjs_spec(
            entity_id, sorted_spokes, composite_d, cri
        ),
    }

  @staticmethod
  def generate_self_contained_svg(
      entity_id: str,
      spokes: List[MetricSpoke],
      composite_d: float,
      cri: int,
      width: int = 620,
      height: int = 480,
      scale_mode: str = "zscore",
  ) -> str:
    """Renders a self-contained, crisp SVG radar chart with hover tooltips and 3-sigma perimeter."""
    active_spokes = spokes if spokes else EntityRadarCollector.get_canonical_nominal_spokes()
    spokes = active_spokes

    cx, cy = width / 2.0, height / 2.0 + 20
    max_radius = 125.0

    n = len(spokes)
    is_cri_mode = (scale_mode.lower() == "cri")
    display_cap = 100.0 if is_cri_mode else 4.0

    if composite_d >= 3.0:
      poly_fill, poly_stroke = "rgba(217, 48, 37, 0.25)", "#d93025"
      status_badge_bg, status_badge_fg, status_text = "#fce8e6", "#c5221f", "HIGH RISK ANOMALY"
    elif composite_d >= 2.0:
      poly_fill, poly_stroke = "rgba(249, 171, 0, 0.25)", "#f9ab00"
      status_badge_bg, status_badge_fg, status_text = "#fef7e0", "#b06000", "ELEVATED DEVIATION"
    else:
      poly_fill, poly_stroke = "rgba(26, 115, 232, 0.25)", "#1a73e8"
      status_badge_bg, status_badge_fg, status_text = "#e8f0fe", "#1967d2", "NOMINAL BASELINE"

    svg_parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="100%" height="{height}" style="font-family: Roboto, Arial, sans-serif; background: #ffffff; border-radius: 8px;">',
        '  <defs>',
        '    <filter id="shadow" x="-10%" y="-10%" width="120%" height="120%">',
        '      <feDropShadow dx="0" dy="2" stdDeviation="3" flood-opacity="0.1"/>',
        '    </filter>',
        '  </defs>',
        f'  <rect x="20" y="12" width="{width - 40}" height="46" rx="6" fill="{status_badge_bg}"/>',
        f'  <text x="32" y="30" font-size="12" font-weight="bold" fill="{status_badge_fg}">{entity_id} • 360° BEHAVIORAL RADAR</text>',
        f'  <text x="32" y="47" font-size="11" font-weight="500" fill="{status_badge_fg}">Multi-Sector Distance: D = {composite_d:.2f}σ  |  CRI: {cri}/100 ({status_text})</text>',
    ]

    if is_cri_mode:
      ring_values = [(25, False, "CRI 25"), (50, True, "50 (3.0σ Threshold)"), (75, False, "CRI 75"), (100, False, "CRI 100")]
    else:
      ring_values = [(1.0, False, "+1.0σ"), (2.0, False, "+2.0σ"), (3.0, True, "+3.0σ (Threshold)"), (4.0, False, "+4.0σ")]

    for val, is_threshold, ring_label in ring_values:
      r = (val / display_cap) * max_radius
      stroke_color = "#d93025" if is_threshold else "#e0e0e0"
      stroke_dash = 'stroke-dasharray="4,4"' if is_threshold else ""
      stroke_width = "1.5" if is_threshold else "1"

      svg_parts.append(f'  <circle cx="{cx}" cy="{cy}" r="{r:.1f}" fill="none" stroke="{stroke_color}" stroke-width="{stroke_width}" {stroke_dash}/>')
      label_color = "#d93025" if is_threshold else "#9e9e9e"
      svg_parts.append(f'  <text x="{cx + 4}" y="{cy - r + 10}" font-size="9" font-weight="bold" fill="{label_color}">{ring_label}</text>')

    spoke_coords = []
    polygon_points = []

    for i, s in enumerate(spokes):
      angle = -math.pi / 2.0 + (2.0 * math.pi * i / n)
      ax = cx + max_radius * math.cos(angle)
      ay = cy + max_radius * math.sin(angle)
      svg_parts.append(f'  <line x1="{cx}" y1="{cy}" x2="{ax:.1f}" y2="{ay:.1f}" stroke="#eeeeee" stroke-width="1"/>')

      if is_cri_mode:
        val_for_radius = min(max(0.0, float(s.cri_score)), 100.0)
        dr = (val_for_radius / 100.0) * max_radius
      else:
        raw_z = max(0.0, s.z_score)
        # Perimeter pinning: Clamp visual distance to display_cap (4.0σ), avoiding scale compression
        dr = (min(raw_z, display_cap) / display_cap) * max_radius

      px = cx + dr * math.cos(angle)
      py = cy + dr * math.sin(angle)
      polygon_points.append(f"{px:.1f},{py:.1f}")
      spoke_coords.append((px, py, s))

      label_r = max_radius + 20
      lx = cx + label_r * math.cos(angle)
      ly = cy + label_r * math.sin(angle)

      if abs(math.cos(angle)) < 0.2:
        text_anchor = "middle"
      elif math.cos(angle) > 0:
        text_anchor = "start"
      else:
        text_anchor = "end"

      spoke_highlight = "#c5221f" if s.z_score >= 3.0 else "#3c4043"
      outlier_tag = " 🚨" if s.z_score >= 4.0 else ""
      z_formatted = f"{s.z_score:+.1f}σ"

      if i == 0:  # Top spoke
        ly -= 6
      elif i in (1, n - 1):  # Upper side spokes
        ly -= 2

      if is_cri_mode:
        score_subtext = f"(CRI {s.cri_score} | {z_formatted}{outlier_tag})"
      else:
        score_subtext = f"({z_formatted}{outlier_tag})"

      svg_parts.append(
          f'  <text x="{lx:.1f}" y="{ly:.1f}" font-size="10" font-weight="bold" text-anchor="{text_anchor}" fill="{spoke_highlight}">'
          f'<tspan x="{lx:.1f}" dy="0">{s.spoke_name}</tspan>'
          f'<tspan x="{lx:.1f}" dy="13" font-size="9" font-weight="600" fill="{spoke_highlight}">{score_subtext}</tspan>'
          f'</text>'
      )

    poly_str = " ".join(polygon_points)
    svg_parts.append(f'  <polygon points="{poly_str}" fill="{poly_fill}" stroke="{poly_stroke}" stroke-width="2.5" filter="url(#shadow)"/>')

    for px, py, s in spoke_coords:
      pt_color = "#d93025" if s.z_score >= 3.0 else poly_stroke
      z_formatted_title = f"{s.z_score:+.2f}σ"
      svg_parts.append(f'  <circle cx="{px:.1f}" cy="{py:.1f}" r="4.5" fill="{pt_color}" stroke="#ffffff" stroke-width="1.5">')
      svg_parts.append(
          f'    <title>{s.spoke_name}\n• 24h Observed: {s.observed} {s.unit}\n• 30d Baseline Mean: {s.baseline_mean:.1f}\n• 30d StdDev: {s.baseline_stddev:.1f}\n• Deviation: {z_formatted_title}</title>'
      )
      svg_parts.append('  </circle>')

    svg_parts.append('</svg>')
    return "\n".join(svg_parts)

  @staticmethod
  def generate_html_widget(
      entity_id: str,
      spokes: List[MetricSpoke],
      composite_d: float,
      cri: int,
      scale_mode: str = "zscore",
  ) -> str:
    """Wraps self-contained SVG into a Generative UI HTML artifact compatible with <agent-embed>."""
    svg = EntityRadarCollector.generate_self_contained_svg(
        entity_id, spokes, composite_d, cri, scale_mode=scale_mode
    )
    return (
        '<!DOCTYPE html>\n<html>\n<head>\n'
        '  <meta charset="utf-8">\n'
        '  <script src="https://www.gstatic.com/antigravity/web/dev/tailwindcss.min.js"></script>\n'
        '</head>\n<body class="bg-transparent text-[var(--foreground)] antialiased p-2 flex justify-center">\n'
        '  <div class="bg-[var(--card)] border border-[var(--border)] rounded-xl p-3 shadow-sm">\n'
        f'    {svg}\n'
        '  </div>\n</body>\n</html>\n'
    )

  @staticmethod
  def generate_data_uri_image(
      entity_id: str,
      spokes: List[MetricSpoke],
      composite_d: float,
      cri: int,
      scale_mode: str = "zscore",
  ) -> str:
    """Renders self-contained SVG wrapped in a Base64 Markdown image to prevent DOM sanitizers from collapsing text."""
    svg = EntityRadarCollector.generate_self_contained_svg(
        entity_id, spokes, composite_d, cri, scale_mode=scale_mode
    )
    b64_svg = base64.b64encode(svg.encode("utf-8")).decode("utf-8")
    return f"![360° Behavioral Risk Radar: {entity_id}](data:image/svg+xml;base64,{b64_svg})"

  @staticmethod
  def generate_dual_surface_embed(
      entity_id: str,
      spokes: List[MetricSpoke],
      composite_d: float,
      cri: int,
      artifact_path: Optional[str] = None,
      scale_mode: str = "zscore",
  ) -> str:
    """Renders cross-client dual-surface snippet (<agent-embed> for Jetski + Base64 image for MCP clients)."""
    data_uri = EntityRadarCollector.generate_data_uri_image(
        entity_id, spokes, composite_d, cri, scale_mode=scale_mode
    )
    src_path = artifact_path if artifact_path else f"radar_{entity_id}.html"
    file_uri = src_path if src_path.startswith("file://") else f"file://{src_path}"
    return (
        f'<agent-embed src="{file_uri}"></agent-embed>\n'
        f'{data_uri}\n'
        f'[📊 Open 360° Risk Radar (SVG/HTML)]({file_uri})'
    )

  @staticmethod
  def generate_ascii_chart(
      entity_id: str,
      spokes: List[MetricSpoke],
      composite_d: float,
      cri: int,
      bar_width: int = 20,
  ) -> str:
    """Renders a clean, terminal-friendly ASCII horizontal bar chart for plain-text environments."""
    active_spokes = spokes if spokes else EntityRadarCollector.get_canonical_nominal_spokes()
    spokes = active_spokes

    is_anomalous = composite_d >= 3.0
    status_tag = "🚨 HIGH RISK ANOMALY" if is_anomalous else ("⚠️ ELEVATED" if composite_d >= 2.0 else "🟢 NOMINAL")
    header = f"360° BEHAVIORAL RISK RADAR: {entity_id} (D = {composite_d:.2f}σ | CRI {cri}/100 | {status_tag})"
    separator = "─" * max(len(header), 75)

    max_label_len = max(len(s.spoke_name) for s in spokes)
    lines = [header, separator]

    for s in spokes:
      z_val = max(0.0, s.z_score)
      capped_z = min(z_val, 4.0)
      filled = int(round((capped_z / 4.0) * bar_width))
      bar = "▰" * filled + "▱" * (bar_width - filled)
      outlier_icon = " 🚨" if s.z_score >= 3.0 else (" ⚠️" if s.z_score >= 2.0 else "   ")
      lines.append(
          f"{s.spoke_name:<{max_label_len}}  [{bar}]  +{s.z_score:>5.2f}σ  (CRI {s.cri_score:>3}/100){outlier_icon}"
      )

    lines.append(separator)
    lines.append(f"Perimeter Threshold: +3.00σ (CRI 50) | Monitored Sectors: {len(spokes)}")
    return "\n".join(lines)

  @staticmethod
  def generate_markdown_summary(
      entity_id: str,
      spokes: List[MetricSpoke],
      composite_d: float,
      cri: int,
  ) -> str:
    """Generates CommonMark table with Unicode magnitude progress bars."""
    is_anomalous = composite_d >= 3.0
    status_icon = "🚨" if is_anomalous else "🟢"
    status_text = "HIGH RISK ANOMALOUS FOOTPRINT" if is_anomalous else "NOMINAL BEHAVIORAL BASELINE"

    lines = [
        f"### {status_icon} 360° Entity Behavioral Risk Radar: `{entity_id}`",
        f"**Composite Threat Distance**: `D = {composite_d:.2f}σ` | **Calibrated Risk Index**: `CRI = {cri}/100` (`{status_text}`)",
        "",
        "| Telemetry Sector Spoke | 24h Observed | 30d Baseline (μ ± σ) | Z-Score | Spoke CRI | Visual Spoke Magnitude | Status |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    for s in spokes:
      z_val = max(0.0, s.z_score)
      bar_units = min(20, int(round(z_val / 0.2)))
      bar_str = "▰" * bar_units + "▱" * (20 - bar_units)

      status = "🚨 **Anomaly**" if s.z_score >= 3.0 else ("⚠️ Elevated" if s.z_score >= 2.0 else "🟢 Nominal")
      lines.append(
          f"| **{s.spoke_name}** ({s.sector}) | `{s.observed:,.0f} {s.unit}` | `{s.baseline_mean:,.1f} ± {s.baseline_stddev:,.1f}` | **`+{s.z_score:.2f}σ`** | `{s.cri_score}/100` | `{bar_str}` | {status} |"
      )

    lines.append("")
    lines.append("> [!NOTE]")
    lines.append(f"> Evaluated across **{len(spokes)} orthogonal telemetry sectors** using 30-day continuous Risk Analytics baselines (`period: 1d, window: 30d`).")
    lines.append("")
    lines.append("### 📐 Statistical & Mathematical Appendix (Step-by-Step Derivation)")
    lines.append("1. **Individual Spoke Z-Scores (Observed vs. 30-Day Historical Mean $\\pm$ StdDev)**:")
    lines.append("   $$Z_i = \\frac{\\text{Obs}_i - \\mu_{i, 30\\text{d}}}{\\sigma_{i, 30\\text{d}} + 1.0}$$")
    lines.append("   *Universal dispersion floor ($+1.0$) prevents division-by-zero on quiet accounts while bounding variance.*")
    lines.append("")
    lines.append("2. **Euclidean Composite Threat Distance ($D$) Across All Orthogonal Spokes**:")
    sq_terms = [f"({max(0.0, s.z_score):.2f})^2" for s in spokes]
    sq_str = " + ".join(sq_terms)
    lines.append(f"   $$D = \\sqrt{{\\sum_{{i=1}}^{{K}} \\max(0, Z_i)^2}} = \\sqrt{{{sq_str}}} = \\mathbf{{{composite_d:.2f}\\sigma}}$$")
    lines.append("")
    lines.append("3. **Calibrated Risk Index (CRI: 0–100 Logistic Sigmoid Mapping)**:")
    lines.append("   $$\\text{CRI} = \\text{round}\\left(\\frac{100}{1 + \\exp(-0.6 \\cdot (D - 3.0))}\\right)$$")
    lines.append(f"   $$\\text{{CRI}}({composite_d:.2f}) = \\mathbf{{{cri} / 100}} \\quad ({status_text})$$")
    return "\n".join(lines)

  @staticmethod
  def generate_chartjs_spec(
      entity_id: str,
      spokes: List[MetricSpoke],
      composite_d: float,
      cri: int,
  ) -> Dict[str, Any]:
    """Generates declarative Chart.js radar specification for web dashboards."""
    labels = [s.spoke_name for s in spokes]
    z_values = [max(0.0, s.z_score) for s in spokes]
    max_z = max(4.0, max(z_values) if z_values else 4.0)

    bg_color = "rgba(217, 48, 37, 0.25)" if composite_d >= 3.0 else ("rgba(249, 171, 0, 0.25)" if composite_d >= 2.0 else "rgba(26, 115, 232, 0.25)")
    border_color = "#d93025" if composite_d >= 3.0 else ("#f9ab00" if composite_d >= 2.0 else "#1a73e8")

    return {
        "type": "radar",
        "data": {
            "labels": labels,
            "datasets": [
                {
                    "label": f"{entity_id} (D = {composite_d:.2f}σ, CRI = {cri}/100)",
                    "data": z_values,
                    "backgroundColor": bg_color,
                    "borderColor": border_color,
                    "borderWidth": 2.5,
                    "pointBackgroundColor": border_color,
                    "pointRadius": 4,
                },
                {
                    "label": "Anomaly Boundary (+3.0σ)",
                    "data": [3.0] * len(labels),
                    "borderColor": "rgba(217, 48, 37, 0.6)",
                    "borderDash": [4, 4],
                    "borderWidth": 1.5,
                    "fill": False,
                    "pointRadius": 0,
                },
            ],
        },
        "options": {
            "responsive": True,
            "scales": {
                "r": {
                    "min": 0,
                    "max": math.ceil(max_z),
                    "ticks": {"stepSize": 1.0, "backdropColor": "transparent"},
                    "pointLabels": {"font": {"size": 11, "weight": "bold"}},
                }
            },
        },
    }


def main():
  """CLI entry point for deterministic visual generation and post-search collation."""
  parser = argparse.ArgumentParser(description="360° Entity Behavioral Risk Radar Generator")
  parser.add_argument("--entity", required=True, help="Entity identifier (user or hostname)")
  parser.add_argument(
      "--entity-type",
      default="USER",
      choices=["USER", "ASSET"],
      help="Entity type: USER or ASSET",
  )
  parser.add_argument(
      "--scores",
      help="Convenient comma-separated spoke deviations (e.g. 'auth=0.0,cloud=3.8,workspace=3.2,net=0.8,proc=10.8')",
  )
  parser.add_argument("--data", help="JSON string or file path containing spoke records")
  parser.add_argument(
      "--format",
      choices=["html", "svg", "data-uri", "dual", "ascii", "markdown", "json"],
      default="html",
      help="Output format: html (generative-ui embed), svg, data-uri (markdown image), dual (cross-client embed+data-uri), ascii (terminal), markdown (table), json",
  )
  parser.add_argument("--scale-mode", choices=["zscore", "cri"], default="zscore", help="Radar scale mode")
  parser.add_argument("--output", help="Optional output file path")
  args = parser.parse_args()

  spokes = []
  if args.scores:
    spokes = EntityRadarCollector.parse_scores_argument(args.scores, args.entity_type)
  elif args.data:
    raw_data = args.data.strip()
    if raw_data.startswith("[") or raw_data.startswith("{"):
      parsed = json.loads(raw_data)
      spoke_items = parsed if isinstance(parsed, list) else parsed.get("spokes", [])
    else:
      with open(raw_data, "r", encoding="utf-8") as f:
        parsed = json.load(f)
        spoke_items = parsed if isinstance(parsed, list) else parsed.get("spokes", [])

    for item in spoke_items:
      spokes.append(
          MetricSpoke(
              sector=item.get("sector", "General"),
              spoke_name=item.get("spoke_name", item.get("name", "Spoke")),
              metric_table=item.get("metric_table", "metrics.unknown"),
              observed=float(item.get("observed", 0.0)),
              baseline_mean=float(item.get("baseline_mean", item.get("mean", 0.0))),
              baseline_stddev=float(item.get("baseline_stddev", item.get("stddev", 0.0))),
              z_score=float(item.get("z_score", item.get("z", 0.0))),
              unit=item.get("unit", "events"),
              cri_score=int(item.get("cri_score", item.get("cri", 0))),
          )
      )
  else:
    spokes = EntityRadarCollector.get_canonical_nominal_spokes(args.entity_type)

  collector = EntityRadarCollector()
  payload = collector.build_radar_payload(args.entity, args.entity_type, spokes)

  if args.format == "html":
    out_str = payload["html_widget"]
  elif args.format == "svg":
    out_str = payload["svg_widget"]
  elif args.format == "data-uri":
    out_str = payload["data_uri_image"]
  elif args.format == "dual":
    out_str = EntityRadarCollector.generate_dual_surface_embed(
        args.entity, spokes, payload["composite_distance_d"], payload["calibrated_risk_index"], artifact_path=args.output
    )
  elif args.format == "ascii":
    out_str = payload["ascii_chart"]
  elif args.format == "markdown":
    out_str = payload["markdown_table"]
  elif args.format == "json":
    out_str = json.dumps(payload, indent=2)
  else:
    out_str = payload["html_widget"]

  if args.output:
    file_content = payload["html_widget"] if args.format == "dual" else out_str
    with open(args.output, "w", encoding="utf-8") as f:
      f.write(file_content)

    # Automatically generate companion file for seamless multi-surface rendering (.html <-> .svg)
    if args.output.endswith(".html"):
      companion_path = args.output[:-5] + ".svg"
      with open(companion_path, "w", encoding="utf-8") as f:
        f.write(payload["svg_widget"])
    elif args.output.endswith(".svg"):
      companion_path = args.output[:-4] + ".html"
      with open(companion_path, "w", encoding="utf-8") as f:
        f.write(payload["html_widget"])

  print(out_str)


if __name__ == "__main__":
  main()
