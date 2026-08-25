# SysCall-DAG

SysCall-DAG builds typed dependency DAGs from a process's Linux system calls,
fingerprints each window with directed Weisfeiler–Lehman refinement, and scores
it against a clean baseline. It is a research prototype: use `strace` as the
reference capture path, and treat eBPF performance claims as unverified until
the included measurement workflow has been run on a privileged Linux host.

## Highlights

- Typed syscall graphs with descriptor lifecycles, process relationships,
  vectored-I/O buffer flow, and Unix `SCM_RIGHTS` descriptor transfer.
- `NORMAL`, `REVIEW`, and `ANOMALOUS` decisions with score breakdowns and
  source-window evidence.
- Capture-quality accounting: parser/kernel loss and bounded-stream eviction
  flow into the degraded-capture safeguard rather than being silently ignored.
- Reproducible dataset import, calibration, evaluation, measurement, ablation,
  and a 1/2/3-gram sequence reference.
- Interactive TUI plus plain-text and JSON command-line modes.
- Incremental live monitoring from JSONL, strace, FIFO/file, TCP, or an eBPF
  relay stream.

## Requirements

- Rust stable.
- Docker Desktop / Docker for running programs inside the disposable Linux
  guest. Recorded traces do not need Docker.
- Linux or WSL2 for live `strace` and eBPF collection.

Install and validate:

```sh
cargo install --path .
cargo test
sysdag doctor
```

## Quick start

Open the TUI on a terminal:

```sh
sysdag
```

Enter a program or trace path and press Enter. The first run trains a baseline;
subsequent runs monitor against that baseline. Use `--plain` for a text-only
report or `--json` for machine-readable output.

```sh
# Train and monitor recorded traces
sysdag --plain --workdir .sysdag --id example train tests/fixtures/clean.strace
sysdag --plain --workdir .sysdag --id example monitor tests/fixtures/attack.strace

# Run the bundled clean-then-exfiltration demonstration (requires Docker)
sysdag demo

# Inspect a graph or its score breakdown
sysdag viz .sysdag/runs/<run-id>/graphs/w0000/graph.json
sysdag explain --baseline .sysdag/baselines/example.json \
  --graph .sysdag/runs/<run-id>/graphs/w0000/graph.json
```

Artifacts are written below `.sysdag/`: baselines, manifests, event streams,
graphs, decisions, and private path maps when redaction is enabled.

## Evaluation workflow

Import a corpus with run metadata, calibrate only from clean training runs, then
evaluate the frozen baseline on the test partition:

```sh
sysdag dataset import samples/corpus --id sample-corpus
sysdag calibrate --dataset sample-corpus
sysdag evaluate --dataset sample-corpus \
  --baseline .sysdag/baselines/dataset-sample-corpus.json
sysdag measure --dataset sample-corpus \
  --baseline .sysdag/baselines/dataset-sample-corpus.json
sysdag evaluate-ngram --dataset sample-corpus
```

`ablate --dataset <id> --grid <grid.toml>` runs configured representation and
window comparisons. See [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md)
for the claim gates and completed work.

## Live monitoring

`monitor-live` scores a completed window as soon as enough events arrive. It
accepts JSONL events or stateful strace lines from a file, FIFO, or TCP source:

```sh
sysdag monitor-live --format strace --input /tmp/sysdag.strace \
  --baseline .sysdag/baselines/example.json

sysdag monitor-live --format jsonl --input tcp://127.0.0.1:9000 \
  --baseline .sysdag/baselines/example.json
```

## Native eBPF collection (Linux/WSL2)

The repository includes a raw-syscall eBPF program and Aya loader. Build the
object, collect its ring-buffer relay, then monitor or evaluate its JSONL:

```sh
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -c ebpf/sysdag.bpf.c -o ebpf/sysdag.bpf.o
cargo build --release

sudo target/release/sysdag collect-ebpf --object ebpf/sysdag.bpf.o \
  --output /tmp/sysdag.ebpf.jsonl --duration-secs 30
target/release/sysdag monitor-ebpf --input /tmp/sysdag.ebpf.jsonl \
  --baseline .sysdag/baselines/example.json
```

Native attachment requires a BPF-capable kernel, Clang BPF toolchain, and
`CAP_BPF` plus `CAP_PERFMON` (normally `sudo`). Run the overhead comparison
before making low-overhead claims:

```sh
SYSDAG_BIN=target/release/sysdag scripts/measure_capture_overhead.sh \
  ebpf/sysdag.bpf.o -- /path/to/workload arg1
```

Detailed instructions: [docs/EBPF_BUILD_AND_MEASURE.md](docs/EBPF_BUILD_AND_MEASURE.md)
and [docs/EBPF_RELAY_PROTOCOL.md](docs/EBPF_RELAY_PROTOCOL.md).

## Safety and privacy

The program-execution path runs in a loopback-only guest. Bundled attack samples
read harmless decoys only. Configure path redaction before exporting artifacts;
the local token-to-path map is kept separate from exported events and graphs.

## Project map

```text
src/             parser, graph builder, detector, experiments, TUI, streaming
ebpf/            raw-syscall BPF program
samples/         reproducible clean/attack corpus and demo programs
tests/           unit and acceptance coverage
docs/            implementation plan, architecture, relay, and measurement docs
```
