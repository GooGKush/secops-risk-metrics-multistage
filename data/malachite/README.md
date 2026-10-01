# Vendored Malachite catalog data

These files are the source of truth for which UDM filters each `metrics.*`
function accepts. The YARA-L compiler accepts a metric call only when the set of
dimensions its filter args map to exactly equals one `query_info` set for that
metric.

| File | Upstream (google3) | How copied |
| :--- | :--- | :--- |
| `config_dimensions.textproto` | `googlex/security/malachite/analytics/configs/config.textproto` | Reduced: only `metric_name` and `dimensions` are kept. `query`, `filter_string`, `shard_number` and `has_sum_measure` are dropped because they reference or embed baseline SQL. The upstream CL is recorded in the file header. |
| `dimension_field_mapping.textproto` | `googlex/security/malachite/rules/yl2/compiler/ueba/dimension_field_mapping.textproto` | Verbatim. Maps each dimension to the UDM fields that populate it. |
| `config.proto` | `googlex/security/malachite/analytics/configs/config.proto` | Verbatim. Schema of `config.textproto`. |
| `ueba_metric.proto` | `googlex/security/malachite/rules/proto/ueba_metric.proto` | Verbatim. Schema of the dimension mapping. |

Only textproto and proto files are vendored. No `.go` or `.sql` files are
copied. What the baseline SQL counts is recorded in prose in
`../metric_baseline_semantics.json`, together with how it was checked live.

## Keeping in sync

```bash
python3 -m scripts.sync_malachite_catalog --check --google3 /google/src/head/depot/google3
python3 -m scripts.sync_malachite_catalog --write --google3 /google/src/head/depot/google3 --cl <CL>
python3 scripts/generate_metric_sector_catalog.py   # regenerates references/metric-sector-catalog.md
python3 scripts/generate_references.py              # regenerates references/metrics-catalog.md
```

`tests/test_malachite_catalog.py` fails if the generated references drift from
these files. It also runs the google3 drift check when a google3 checkout is
present.

## Consumers

- `scripts/malachite_catalog.py`: parser and query API (valid sets, entity
  bindings, fusion pair checks, observed-filter gap checks).
- `scripts/preflight_validator.py`: `MALACHITE_SUPPORTED_FILTERS` and the
  `UNSUPPORTED_DIMENSION_SET` error.
- `scripts/template_router.py`: identifier rebinding and
  `build_sector_fusion_query`.
- `references/metric-sector-catalog.md` and `references/metrics-catalog.md`:
  the generated references the agent reads at hunt time.
