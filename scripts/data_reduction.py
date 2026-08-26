"""Data Reduction Layer to protect LLM context windows."""

__author__ = "Greg Kushmerek"
__version__ = "2.1.0"

from typing import Any, Dict, List


class DataReductionEngine:
  """Truncates large SecOps search payloads to statistical summaries and top N outliers."""

  @staticmethod
  def reduce(raw_results: List[Dict[str, Any]], top_n: int = 5) -> Dict[str, Any]:
    if not raw_results:
      return {
          "total_entities_evaluated": 0,
          "outlier_count": 0,
          "top_outliers": [],
      }

    sample = raw_results[0]
    score_key = "personal_z"
    for candidate in ["personal_z", "modified_z", "fano_factor", "poisson_z", "surge_ratio", "hourly_z_score"]:
      if candidate in sample:
        score_key = candidate
        break

    def get_score(record: Dict[str, Any]) -> float:
      try:
        return abs(float(record.get(score_key, 0)))
      except (ValueError, TypeError):
        return 0.0

    sorted_records = sorted(raw_results, key=get_score, reverse=True)

    return {
        "total_entities_evaluated": len(raw_results),
        "outlier_count": len(sorted_records),
        "primary_score_metric": score_key,
        "top_outliers": sorted_records[:top_n],
    }
