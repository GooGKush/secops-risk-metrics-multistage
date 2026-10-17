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
| Mode A, today `00:00Z` → now, run after `04:00Z` | today | last 30 full days |
| Mode A, run before `04:00Z` | yesterday | 30 days ending yesterday `00:00Z` (yesterday excluded; say so on the card) |
| Mode B, 7 days ending today | first scored day | 30 days before the first scored day, reused for all 7 |
| Mode C shard for day `D` (`D 00:00Z` → `D+1 00:00Z`) | `D` | 30 days before `D` |

---

## 2. Mode B: Fixed-Baseline Timeline (2–7 days, one request)

* **Window**: `startTime` = first scored day `00:00Z`; `endTime` = now (or the day after the last scored day, `00:00Z`). Template `match:` stays `$entity, $ws by 1d`.
* **Card and Pillar 6 must state the baseline dates**: `Baseline: <D0 − 30d> → <D0>, applied to all <N> scored days`.
* **Known bias** (state the relevant item in Pillar 4):
  1. **Sustained activity keeps scoring high.** A burst never enters the baseline, so day 5 of a burst scores like day 1. Useful for persistence; it inflates ranking.
  2. **Gradual drift is overstated** on later days.
  3. **Entities that first appear inside the window stay gated** (fewer than the minimum baseline days → sector Z = 0) for every scored day.
* **Magnitude**: in validation, a baseline 10 days stale overstated one entity's composite D about 15× (655.9σ vs. 44.5σ when re-scored against its own trailing 30 days).
* **Cap**: 7 days. For longer or per-day-accurate timelines, offer Mode C when `run_command` is present. Otherwise state: *"Per-day baselines and timelines longer than 7 days need a client that can run local scripts."*
* **Exceptions that keep one request**:
  * **Longitudinal CUSUM** (`longitudinal_cusum_2stage.yl2`) accumulates residuals across days and needs a fixed pre-window reference. The start-anchored baseline is exactly that, so CUSUM may use up to the 14-day search limit and is never split into Mode C shards.
  * **MAD** (`mad_robust_z_4stage.yl2`) builds its robust baseline from the raw search window, not from `metrics.*`; its scored days follow the 2–7 day Mode B cap.

---

## 3. Mode C: Per-Day Baseline Timeline (shell-capable clients only)

### 3.1 Capability gate
Offer Mode C **only** when `run_command` is present (the same signal used for `<agent-embed>` rendering). Never offer it in MCP-only, webview, or agentapi clients; their context cannot hold many shard results.

### 3.2 Shard specification
* One shard per UTC day `D` in the requested range: `startTime = D T00:00:00Z`, `endTime = (D+1) T00:00:00Z`. Today's shard uses `endTime = now`.
* **Byte-identical query**: every shard runs the approved Turn 1 query unchanged. Only `startTime` / `endTime` differ.
* **Default cap**: 30 days. Above 30, state the shard count and estimated run time and require explicit confirmation. Practical ceiling is about one year: UDM retention, and each shard also needs the 30 days before it. Metrics retention has not been verified; if early shards return no baselines, report that instead of treating them as clean.
* **Freshness**: a today shard dispatched before `04:00Z` gets the baseline ending yesterday `00:00Z` (§1). Say so on the card.

### 3.3 Clearance card additions
Add to the PRE-FLIGHT card (replacing the Mode A/B placeholder; never list Mode C on a card in a client without `run_command`): `• Evaluation Horizon Mode: Mode C — <N> daily shards, <first> → <last>, each vs. its own trailing 30d baseline`, plus the estimated run time (validation: 14 shards ≈ 4 minutes wall clock).

### 3.4 Dispatch
* Dispatch shards through `udm_search` in parallel batches of at most 10.
* **Compiler, syntax, or permission error** on any shard: the query itself is bad. Stop all dispatch (Hard Stop on API Error) and surface the error.
* **Transient error** (`RESOURCE_EXHAUSTED`, `DEADLINE_EXCEEDED`, `UNAVAILABLE`): retry that shard once after a short pause. If it fails again, record it as a failed shard and continue. A failed shard is reported, never filled in or interpolated.

### 3.5 Collation (sanctioned script)
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

### 3.6 Report (6 pillars, adapted)
* **Pillar 1**: `<agent-embed src="file:///<artifact_dir>/timeline_ranked.html"></agent-embed>` and `[Open Visual Chart](file:///<artifact_dir>/timeline_ranked.html)` (`src` MUST use the `file:///` URI scheme and an explicit closing tag `</agent-embed>`, never a bare filesystem path or self-closing `<agent-embed ... />`).
* **Pillar 2**: the approved query once, then a shard table (date, `startTime`, `endTime`, status, rows).
* **Pillar 3**: the collator's per-day table and top outliers.
* **Pillar 4**: persistence, onset, escalation, sector lead/lag, and the sparse-baseline list (entities with real volume but too few baseline days to score).
* **Pillar 5**: manual pivot for the top entity and day.
* **Pillar 6**: `Each scored day D is compared to [D − 30d, D)`.
* **All shards empty**: 2-section Clean Hunt Audit, with the shard table in Section 2.

---

## 4. Choosing a mode

| Need | Mode |
| :--- | :--- |
| Active triage, today only | A |
| Quick look at the last few days in any client | B (state the fixed-baseline bias) |
| Per-day accuracy, onset dating, or more than 7 days | C (`run_command` present only) |
| Specific single past date | A-style single-day request for that date (auto-bypass Mode B) |
