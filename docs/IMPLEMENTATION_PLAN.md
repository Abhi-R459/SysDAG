# SysDAG Implementation Plan — Closing the Gaps

Source of truth: `SysCall-DAG_Implementation_and_Claim_Gaps.docx` (§3 missing features,
§4 evaluation, §5 ablations, §7 recommended order). Phases follow the document's own
ordering so each stage produces evidence for exactly one claim family.

Status legend: `[ ]` todo · `[x]` done · effort `S/M/L` relative size.

| Item | Status | Notes |
|------|--------|-------|
| 1.1 Full baseline compatibility checks | `[x]` done 2026-08-23 | `CompatibilityReport` hard/soft split; schema/label/edge-policy/tracer/config-shape hard-fail; arch/kernel/version advisory; `--allow-mismatch` CLI→TUI threading |
| 1.2 Immutable provenance manifests | `[x]` done 2026-08-23 | `RunManifest` (self-checksummed, artifact sha256 map) written per run; `sysdag verify` CLI; `TrainingProvenance` on baselines; roundtrip+tamper integration test |
| 1.3 Capture-quality accounting | `[x]` done 2026-08-24 | Parse loss/unknown/malformed accounting flows into graph quality and decisions; degraded capture caps alerts at REVIEW; TUI/report badge and acceptance coverage. |
| 1.4 Privacy controls | `[x]` done 2026-08-24 | Token/hash path redaction, raw-line persistence opt-in, private local token map, and export-leakage acceptance test. |
| 2.1 Dataset management | `[x]` done 2026-08-24 | `sysdag dataset import` creates immutable copied datasets with per-run SHA-256, labels, host metadata, and deterministic run-level partitions. |
| 2.2 Threshold calibration | `[x]` done 2026-08-24 | `sysdag calibrate --dataset` trains on clean-train and freezes empirical validation FPR quantiles with provenance in the baseline. |
| 2.3 Metrics harness | `[x]` done 2026-08-24 | `sysdag evaluate --dataset --baseline` writes JSON + Markdown reports with confusion metrics, Wilson 95% CIs, latency percentiles, pipeline time/peak RSS, and capture-quality loss. |
| 2.4 Attack corpus | `[x]` done 2026-08-24 | Recorded labeled traces cover decoy traversal, file-to-socket exfiltration, shell spawn, dummy insertion, benign drift, and a boundary-flow case. |

---

## Phase 1 — Data quality, provenance, privacy *(docx §7.1)*

Goal: defensible artifacts. No behavioral change to detection.

### 1.1 Full baseline compatibility checks `[M]`
Current state: `BaselineManifest` (`src/detector.rs:29`) checks only target identity +
config digest (`detector.rs:79-93`).
- Add fields: `kernel_version`, `arch`, `tracer_version`, `schema_version` (event +
  graph), `edge_policy`, `resolved_config` (serialized `Config`, not just digest),
  `software_version`.
- New `CompatibilityReport { compatible: bool, mismatches: Vec<String> }`; monitor mode
  hard-fails on mismatch unless `--allow-mismatch`.
- Gate on existing `SCHEMA_VERSION` constants in `src/event.rs` / graph meta.

### 1.2 Immutable provenance manifests `[M]`
- `RunManifest` written next to every `run_dir`: config digest, pipeline/git digest,
  input file SHA-256, tracer/parser stats, thresholds used, timestamp, hostname.
- Extend `BaselineManifest` with: training-input digests, event counts, calibration
  provenance (which validation set produced frozen thresholds), threshold rationale string.
- All manifests content-addressed; loader verifies checksums before use.

### 1.3 Capture-quality accounting `[S]`
Current state: `ParseStats` (`src/event.rs:126`) tracks lines/events/rejected/signals/
exits but is never surfaced in decisions.
- Extend `ParseStats`: `unknown_syscalls`, `truncated_records`, `malformed_records`,
  `lost_events_estimate`.
- Thread into `RunReport` and each `DecisionRecord`; new degraded states:
  `DEGRADED_CAPTURE` when loss/malformed rate > config threshold → decision capped at
  `REVIEW` with an explicit reason.
- TUI overview shows a capture-quality badge.

### 1.4 Privacy controls `[S]`
Current state: raw trace lines persisted (`src/tracer.rs:207` sets `raw_line`,
`src/event.rs:37` stores it).
- Config: `[privacy] redact_paths = true|hash|off`, `persist_raw_lines = false` default.
- Path redaction maps real paths to stable tokens (`F1`, `F2`, …) or keyed SHA-256;
  mapping kept only in local run dir, never in exported JSON/DOT.
- `raw_line` dropped at parse time unless explicitly enabled.

Acceptance: `sysdag train && sysdag monitor` round-trips with zero plaintext paths in
exported artifacts when redaction is on; mismatched-kernel baseline refuses to load.

---

## Phase 2 — Experiment runner & threshold calibration *(docx §7.2)*

Goal: turn ad-hoc runs into reproducible measurement.

### 2.1 Dataset management `[M]`
- New `experiments/` layout: `datasets/<id>/{clean,attacks}/<run-id>/trace.strace`,
  each run-id = one complete execution.
- `sysdag dataset import <dir>` builds a manifest with digests + metadata
  (workload name, kernel, host).
- Splitting **by run**, never by window: `train` / `validation` / `test` partitions
  recorded in the dataset manifest.

### 2.2 Threshold calibration `[M]`
- New command `sysdag calibrate --dataset <id>`:
  trains on clean-train partition, scores every window of clean-validation, picks
  `threshold_review` / `threshold_alert` at configured FPR targets (e.g. 1%, 0.1%),
  freezes them into the baseline manifest with rationale + sample size.
- Monitor then uses manifest thresholds only; CLI flags cannot silently override.

### 2.3 Metrics harness `[L]`
- New module `src/eval.rs` + `sysdag evaluate --dataset <id> --baseline <b>`:
  - detection: FPR, precision, recall/TPR, F1, confusion matrix, Wilson CIs;
  - latency: decision latency p50/p95/p99 (events/sec, graphs/sec);
  - resources: peak RSS, CPU time of monitored workload vs untraced run;
  - capture quality from Phase 1.3 stats.
- Output: `results/<exp-id>/report.json` + markdown summary; experiment manifest pins
  hardware, kernel, versions, dataset id, config digest, seeds (docx §4 last item).

### 2.4 Attack corpus `[M]`
Extend `samples/`: decoy/traversal access, read→socket exfiltration, shell spawn,
dummy-call insertion, benign-update drift, window-boundary edge cases. Each attack gets
a ground-truth label file consumed by the harness.

---

## Phase 3 — Measure the current strace prototype *(docx §7.3)*

Goal: evidence baseline before touching the capture layer. **No new features** —
run the Phase 2 harness against the existing implementation.

Status: `[x]` done 2026-08-24 — `sysdag measure --dataset <id> --baseline <path>` writes a checksummed immutable experiment manifest and rejects any known-clean test run that is not `NORMAL`.

- Full metric suite over the Phase 2 datasets; store results immutably.
- Deliverable: measured numbers backing the claim *"reproducible, strace-based
  prototype evaluates whether typed DAGs improve controlled anomaly detection over a
  sequence baseline"* (docx §8).
- This phase also validates the harness itself (known-clean must score NORMAL).

---

## Phase 4 — Ablations *(docx §5, §7.4)*

Goal: which components actually contribute. All ablations share the Phase 2 harness.

### 4.1 Sequence n-gram baseline `[M]` *(required for the "more robust than sequences" claim)*
- New `src/baselines/ngram.rs`: same TraceEvent stream → per-window n-gram multiset
  (syscall-name n-grams, n ∈ {1,2,3}) → cosine/Jaccard similarity vs clean profile.
- Same decision API as `detector::score` so the harness treats both identically.
- Robustness probes: dummy-call insertion, benign drift, mimicry transformations —
  report graph-vs-sequence deltas.

Status: `[x]` done 2026-08-24 — `src/baselines/ngram.rs` supplies 1/2/3-gram multiset profiles and `DecisionRecord`-compatible scoring, with dummy-insertion coverage.

### 4.2 Representation ablations `[M]` — config-driven switches in `src/features.rs`
- node-only (drop edge types) vs full typed DAG;
- FD-only edges vs FD + buffer-flow;
- directed vs undirected WL;
- WL rounds 1..=5 sweep;
- window size × overlap grid;
- exact-fingerprint-only vs hybrid exact+similarity+risk.

Deliverable: one ablation table per §5 row, generated by
`sysdag ablate --dataset <id> --grid <toml>`.

Status: `[x]` done 2026-08-24 — encoding honors node-only, FD-only, directed/undirected, edge-typed/untyped, WL, window, and exact-only switches; TOML grids execute via `sysdag ablate` and write summaries.

---

## Phase 5 — Process semantics & buffer robustness *(docx §3 items 4–5)*

### 5.1 Descriptor-transfer semantics `[L]`
Current state: several dup paths handled; missing `fcntl(F_DUPFD/F_DUPFD_CLOEXEC)`,
`SCM_RIGHTS` fd-passing, inherited-fd modeling, TID/process-tree correlation.
- `src/graph.rs`: handle `fcntl` dup subcommands; parse `recvmsg` ancillary data for
  SCM_RIGHTS transfers; model inherited fds at `execve` from parent state.
- Process-tree correlation: maintain tid→tgid map from `clone`/`fork` events; attribute
  windows to the process, not the thread.

Status: `[x]` done 2026-08-24 — handles `fcntl(F_DUPFD*)`, parses and seeds `SCM_RIGHTS`, carries FD state across exec, and normalizes `CLONE_THREAD` events to a shared process group before graph construction.

### 5.2 Vector I/O & buffer confidence `[M]`
Current state: `readv/writev` treated as single ops (`src/graph.rs:292-296`,
`labels.rs:24`); no iov parsing.
- Parse iovcnt/iov bases from args; model per-buffer flows where addresses are visible.
- Address-reuse guard: invalidate stale buffer mappings on `mmap`/`munmap` of the range.
- Confidence field on BUFFER_FLOW edges; detector down-weights low-confidence motifs
  (configurable) — explicit confidence limits per docx.

---

## Phase 6 — Streaming ingestion *(docx §3 item 2)*

Status for 5.2: `[x]` done 2026-08-24 — parses and models all observable iovecs, invalidates stale writers on mapping changes, persists edge confidence, and down-weights heuristic buffer-to-network evidence.

Goal: bounded-memory incremental monitoring; prerequisite for any "real-time" wording.

Status: `[x]` done 2026-08-24 — `WindowBuilder` incrementally emits closed windows with a bounded queue and eviction capture-loss accounting. `sysdag monitor-live --format jsonl|strace --input <FIFO/file|tcp://host:port> --baseline <path>` scores completed windows before EOF, accepts stateful unfinished/resumed strace calls, and emits per-decision processing latency plus eviction counters. Offline p50/p95/p99 reporting remains part of the Phase 3 measurement harness rather than the live monitor.
- Refactor pipeline: `WindowBuilder` consumes `TraceEvent`s incrementally and emits
  closed windows + partial-state summaries; decision available before trace EOF.
- Live source: read strace output from FIFO/socket; batched decode.
- Backpressure bound: fixed max in-flight events; oldest-window eviction policy
  recorded as capture degradation (feeds Phase 1.3 accounting).
- Latency instrumentation lands here: event→decision timestamps feed the p50/p95/p99
  metrics of `src/eval.rs`.

## Phase 7 — eBPF collection path *(docx §3 item 1, §7.5–7.6)*

Goal: the intended production capture layer.

Status: `[ ]` implementation complete; runtime evidence pending 2026-08-24 — `ebpf/sysdag.bpf.c` correlates raw syscall enter/exit state in a bounded per-TID map and submits completed records through a ring buffer. The Linux aya loader (`collect-ebpf`) attaches both tracepoints and writes typed relay JSONL; `monitor-ebpf`, dataset evaluation, and the three-way overhead harness consume that output unchanged, with kernel map drops reaching `DEGRADED_CAPTURE`. Windows and WSL2 builds pass, but this session lacks Clang/BPF tooling and the privileges needed to compile/attach the object, so no immutable eBPF overhead/evaluation result exists and the low-overhead claim remains disabled.
- Rust eBPF loader (aya): tracepoints/raw tracepoints for the syscall classes already
  tracked; per-thread bounded state maps for entry/exit correlation.
- Ring-buffer delivery feeding the Phase 6 `WindowBuilder` unchanged.
- Explicit capture-loss counters from kernel map drops → DEGRADED_CAPTURE.
- Overhead comparison harness: identical workload × {no tracing, strace, eBPF}
  (docx "low overhead" claim); re-run Phase 3 evaluation suite on eBPF traces.
- strace remains the reference/fallback backend throughout.

---

## Dependency graph & sequencing

```
P1 ──► P2 ──► P3 ──► P4
       │             ▲
       └──► P5 ──► P6 ──► P7   (P5/P6 can proceed parallel to P3/P4)
```

Claim gates (docx §8):
- after P3 → "reproducible strace-based prototype evaluates typed DAG vs sequences"
- after P4 → "more robust than sequences" *if measurements support it*
- after P7 + re-eval → "low-overhead near-real-time eBPF monitoring" *if measurements support it*

Rule carried from the docx: nothing ships in README/report until the corresponding
number exists in an immutable results manifest.
