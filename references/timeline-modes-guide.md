# Timeline Modes: Fixed-Baseline (Mode B) vs. Per-Day Baseline (Mode C)

Load this guide whenever a hunt scores more than one day, or when the analyst asks how the 30-day baseline is applied across a timeline.

---

## 1. How the platform anchors the 30-day baseline

A `metrics.*(period: 1d, window: 30d, ...)` call resolves to **one baseline window per search request**, not one per scored day.

* **Rule** (Malachite query engine, `query_engine/qesql/ueba.go`: `metricWindowRange` → `dailyMetricWindowEnd`; bound once as `@thirty_day_ueba_metric_window_start` / `_end` in `daywindowedFromWhere`):
  1. `D0` = the request `startTime`, truncated to `00:00Z`.
  2. If `endTime − D0 < 4h`, move `D0` back one day (daily metrics are built after midnight and take about 4 hours).
  3. Baseline = `[D0 − 30d, D0)`.
* **Consequence**: every daily bucket in one request is scored against the same baseline. The search window decides **how many days are scored**, never which baseline a day receives.
* **Custom metrics** follow the same single-window pattern, anchored at the raw `startTime` (no day truncation, no 4-hour shift).
* **Fleet normalization stages stay per-day correct**: they group by `window_start`, so `fleet_sector_norm`-style means are computed per scored day even inside one request.
* **Search limit**: multi-stage searches accept at most 14 days per request (`multi-stage-metrics-guide.md` §9). One-day requests are well inside it.

| Request | `D0` | Baseline applied |
| :--- | :--- | :--- |
| Mode A (default), last complete UTC day (`yesterday 00:00Z` → `today 00:00Z`) | yesterday | 30 full days before yesterday (`[yesterday − 30d, yesterday)`); full day vs full-day `period: 1d` baseline |
| Mode A — Today So Far (`today 00:00Z` → now, `--today-so-far`), run after `04:00Z` | today | last 30 full days (partial UTC day vs full-day baseline — low-biased; never scale counts by elapsed fraction) |
| Mode A — Today So Far (`today 00:00Z` → now, `--today-so-far`), run before `04:00Z` | yesterday | 30 days ending yesterday `00:00Z` (yesterday excluded and partial UTC day low-biased; say so on the card and Pillar 3) |
| Mode B, 3 days ending today | first scored day | 30 days before the first scored day, reused for all 3 |
| Mode C shard for day `D` (`D 00:00Z` → `D+1 00:00Z`) | `D` | 30 days before `D` |

---

## 2. Mode B: Fixed-Baseline Timeline (2–3 days, one request)

* **Window**: `startTime` = first scored day `00:00Z`; `endTime` = now (or the day after the last scored day, `00:00Z`). Template `match:` stays `$entity, $ws by 1d`.
* **Card, Pillar 2 Provenance Stamp, and Pillar 5 Appendix must state the baseline dates**: `Baseline: <D0 − 30d> → <D0>, applied to all <N> scored days`.
* **Known bias** (state the relevant item in Pillar 3):
  1. **Sustained activity keeps scoring high.** A burst never enters the baseline, so day 3 of a burst scores like day 1. Useful for persistence; it inflates ranking.
  2. **Gradual drift is overstated** on later days.
  3. **Entities that first appear inside the window stay gated** (fewer than the minimum baseline days → sector Z = 0) for every scored day.
* **Magnitude**: in validation, a baseline 10 days stale overstated one entity's composite D about 15× (655.9σ vs. 44.5σ when re-scored against its own trailing 30 days).
* **Default & Cap**: 3 days (default 3 days, capped at 3 days). For longer (>3 days) or per-day-accurate timelines, redirect to Mode C when `run_command` is present (and offer Mode C explicitly). Without `run_command`, cap Mode B at 3 days and state: *"Per-day baselines and timelines longer than 3 days need a client that can run local scripts (`scripts/timeline_assembler.py`)."*
* **Exceptions & Multi-Day Longitudinal CUSUM (`WS6-01`)**:
  * **Longitudinal CUSUM** (**Mode A blocked** — single-day CUSUM raises an error because drift requires multiple days):
    1. **Lossless Prefilter**: `longitudinal_cusum_2stage.yl2` (`stage2_math_models/longitudinal_cusum.yl2`) computes the **Windowed Slack Sum** $W = \sum \max(0, z_t - 0.5)$ on mature entities (`$active_days >= 7`). Because Page's one-sided statistic satisfies $S_t \le W$, entities with $W < h$ cannot alarm.
    2. **Up to 14 days (`<=14d`)**: One start-anchored request (`templates/pipelines/longitudinal_cusum_series_3stage.yl2`) emits the ungated per-day series against that single fixed pre-window baseline; `scripts/cusum_helper.py` (`calculate_page_cusum_series`) reconstructs quiet `0`-event calendar days and runs Page's recursion ($k = 0.5$, ARL-calibrated $h = 4.0$ `BALANCED` [$\text{ARL}_0 \approx 336$], $5.0$ `HIGH_PRECISION` [$\text{ARL}_0 \approx 930$], $3.0$ `HIGH_RECALL`).
    3. **Longer than 14 days (`>14d`)**: Run ungated Mode C daily shards limited to candidate entities; `scripts/cusum_helper.py` re-standardizes every day against **Shard 1's fixed calendar-day baseline** (`rebuild_calendar_day_stats`, `WS1-05`) with explicit reference reset controls (`--reset-on`, `--reset-after-alarm`, `--reset-every-days`).
  * **MAD** (`mad_robust_z_4stage.yl2`) and **Quantile** (`quantile_iqr_skew_3stage.yl2`) build their robust/empirical baseline from the ~30d raw search window, not from `metrics.*`; their scored days follow the 2–3 day Mode B cap.

---

## 3. Mode C: Per-Day Baseline Timeline (shell-capable clients only)

### 3.1 Capability gate
Offer Mode C **only** when `run_command` is present (the same signal used for `<agent-embed>` rendering). Never offer it in MCP-only, webview, or agentapi clients; their context cannot hold many shard results.

### 3.2 Shard specification
* One shard per UTC day `D` in the requested range: `startTime = D T00:00:00Z`, `endTime = (D+1) T00:00:00Z`. Today's shard uses `endTime = now`.
* **Byte-identical query**: every shard runs the approved Turn 1 query unchanged. Only `startTime` / `endTime` differ.
* **360° Behavioral Radar in Mode C (Multi-Sector Shards)**:
  * Because a 360° Radar evaluates 6 decoupled sector micro-queries (`auth`, `cloud`, `workspace`, `egress`, `dns`, `web`), running all 6 across $N$ days blindly would dispatch $6 \times N$ queries.
  * **Active-Sector Pre-Screen**: First check which sectors have $>0$ events across the full `[first_day, last_day)` window (or run one Mode B multi-day pass per sector to identify active sectors/days). Sectors with 0 events across the entire window are assigned the deterministic nominal baseline ($Z = 0.00\sigma$) without running $N$ empty daily shards.
  * **Per-Day Sector Shards**: For each active sector, dispatch daily shards (`D T00:00:00Z` → `(D+1) T00:00:00Z`) and pass them to `scripts/timeline_assembler.py` using the `--shard YYYY-MM-DD:<sector>=<path>` syntax (e.g. `--shard 2026-08-29:cloud=<path> --shard 2026-08-29:workspace=<path>`). The collator fuses per-sector Z-scores on each day `D` into the composite Euclidean Threat Distance $D_t = \sqrt{\sum_s \max(0, Z_{s,t})^2}$.
* **Default cap**: 30 days. Above 30, state the shard count and estimated run time and require explicit confirmation. Practical ceiling is about one year: UDM retention, and each shard also needs the 30 days before it. Metrics retention has not been verified; if early shards return no baselines, report that instead of treating them as clean.
* **Freshness**: a today shard dispatched before `04:00Z` gets the baseline ending yesterday `00:00Z` (§1). Say so on the card.

### 3.3 Sustained-attack baseline absorption & fade caveat (D10)
* **Trailing baseline absorption**: Because each Mode C day `D` is scored against its own trailing 30-day baseline `[D − 30d, D)`, once an attack persists across consecutive days, earlier attack days enter subsequent days' 30-day baselines and absorb the sustained shift — primarily by inflating baseline `σ` (alongside raising `μ`).
* **Gaussian fade trajectory**: Under a Gaussian approximation over a 30-day baseline, a sustained `+3σ` shift reads `≈ 2.5σ` on day 2 (dropping below a `3.0σ` significance gate), and a sustained `+6σ` shift stays above `3.0σ` for only about `3 days` before fading below threshold.
* **Analytical guardrail (never read fade as "the attack stopped")**: Always state this caveat in **Pillar 3** of Mode C reports. An onset spike followed by declining daily Z-scores or `empty` shards does **not** mean *"the attack stopped"* — it is the expected statistical signature of per-day baseline absorption. Point analysts to **`LONGITUDINAL_CUSUM`** (`longitudinal_cusum_2stage.yl2` Windowed Slack Sum prefilter + `longitudinal_cusum_series_3stage.yl2` + `scripts/cusum_helper.py`, using one start-anchored baseline for `<=14d` or ungated candidate Mode C shards re-standardized against Shard 1's fixed calendar-day baseline for `>14d`) to measure sustained multi-day persistence. No guard band is applied (`D10`).

### 3.4 Clearance card additions
Add to the PRE-FLIGHT card (replacing the Mode A/B placeholder; never list Mode C on a card in a client without `run_command`): `• Evaluation Horizon Mode: Mode C — <N> daily shards, <first> → <last>, each vs. its own trailing 30d baseline`, plus the batch pacing summary and estimated run time (validation: 14 shards ≈ 4 minutes wall clock).

### 3.5 Dispatch & query pacing (D9)
* Dispatch shards through `udm_search` in parallel batches of at most 10, with a short (`~2s`) inter-batch pause between 10-shard batches to pace up to 30 daily shards without triggering backend rate limits.
* **Compiler, syntax, or permission error** on any shard: the query itself is bad. Stop all dispatch (Hard Stop on API Error) and surface the error.
* **Transient error** (`RESOURCE_EXHAUSTED`, `DEADLINE_EXCEEDED`, `UNAVAILABLE`): retry that shard once after a short pause. If it fails again, record it as a failed shard and continue. A failed shard is reported, never filled in or interpolated.

### 3.6 Collation (sanctioned script)
* Keep every shard result as a raw JSON file. The harness already saves large results to files; for results returned inline, write the raw JSON verbatim to `<scratch>/shard_<YYYY-MM-DD>.json`.
* **Never read raw shard files back into context.** Run the sanctioned collator and read only its output:

```bash
python3 scripts/timeline_assembler.py \
  --shard 2026-10-01=<path> --shard 2026-10-02=<path> ... \
  --failed 2026-10-05 \
  --markdown-out <scratch>/timeline.md --json-out <scratch>/timeline.json \
  --html-out <scratch>/timeline_ranked.html
```

* Register `<artifact_dir>/timeline_ranked.html` via `write_file` (`ArtifactMetadata` with `UserFacing: true`, `RequestFeedback: false`) using the HTML generated at `<scratch>/timeline_ranked.html`. Subprocess writes inside `run_command` do not register Jetski artifacts and will cause `<agent-embed>` to fail with `"invalid embed"`.
* The collator only reshapes Chronicle output (per-day counts, per-entity onset/persistence, peaks, escalation, lead/lag, sparse-baseline list). It computes no baselines or Z-scores. The one derived value is `D = √(composite_threat_norm_sq)` when a template emits only the squared norm, plus CRI via the canonical sigmoid.

### 3.7 Report (5 pillars, adapted)
* **Pillar 1 (`#### 1. Statistical Outlier Report ... — Executive Summary & Calibrated Risk Index (CRI)`)**: Executive headline, piecewise CRI badge, and `<agent-embed src="file:///<artifact_dir>/timeline_ranked.html"></agent-embed>` plus `[Open Visual Chart](file:///<artifact_dir>/timeline_ranked.html)` (`src` MUST use the `file:///` URI scheme and an explicit closing tag `</agent-embed>`, never a bare filesystem path or self-closing `<agent-embed ... />`).
* **Pillar 2 (`#### 2. Ranked Outlier Summary & Provenance Stamp`)**: The collator's per-day outlier summary table, provenance stamp, and the shard execution table (date, `startTime`, `endTime`, status, rows).
* **Pillar 3 (`#### 3. Forensic Vector Breakdown`)**: Persistence, onset, escalation, sector lead/lag, the sparse-baseline list (entities with real volume but too few baseline days to score), the **D10 sustained-attack fade caveat** (warning not to read a fading timeline as *"the attack stopped"* and pointing to `LONGITUDINAL_CUSUM` for persistence), and numbered `[1]`/`[2]`/`[3]` Agentic Next Steps.
* **Pillar 4 (`#### 4. Chronicle UI Manual Pivot`)**: Manual UDM pivot for the top entity and day inside a ```` ```text ```` code block.
* **Pillar 5 (`#### 5. Collapsible Technical Appendix (Statistical & Mathematical Appendix)`)**: Collapsible `<details>` block containing the verbatim executed multi-stage query (` ```yara `), the Mode C baseline anchoring note (`Each scored day D is compared to [D − 30d, D)`), and mathematical derivation.
* **All shards empty**: 2-pillar Clean Hunt Report (`#### 1. Executive Summary & Baseline Status (CRI: 0 / Nominal)` and `#### 2. Telemetry Provenance, Diagnostic Coverage & Next Steps`), with the shard table and collapsible `<details>` query in Section 2.

---

## 4. Choosing a mode

| Need | Mode |
| :--- | :--- |
| Active single-day triage (last complete UTC day by default; Today So Far on request) | A |
| Quick look at the last 2–3 days in any client | B (state the fixed-baseline bias) |
| Per-day accuracy, onset dating, or more than 3 days | C (`run_command` present only) |
| Specific single past date | A-style single-day request for that date (auto-bypass Mode B) |
