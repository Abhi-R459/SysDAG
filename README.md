# SysCall-DAG

Rust CLI that turns a Linux process into **typed syscall dependency DAGs**, fingerprints each window with **directed Weisfeiler–Lehman refinement**, and scores it against a clean baseline.

```text
sysdag <file>
```

`<file>` may be:

- a **C / Python / shell** program — compiled or interpreted inside a disposable Linux micro-VM, then traced
- a Linux **ELF**
- a recorded **strace** log (or a directory of `strace -ff` files)

First run **trains** a baseline. Later runs **monitor** the same file against that baseline.

## What it does

1. Capture completed syscalls (`strace` in a 256 MiB loopback-only Alpine guest).
2. Track file-descriptor generations, buffer flow, and process edges.
3. Slice a sliding window (default W=100, overlap=20) into a DAG.
4. Encode neighborhoods with 3-round directed, edge-typed WL + SHA-256.
5. Decide `NORMAL` / `REVIEW` / `ANOMALOUS` with exact fingerprint lookup, weighted-Jaccard similarity, size deviation, and risk motifs.

An unseen hash is evidence, not a verdict. Every alert points back to window node IDs and source sequence numbers.

## Install

```bash
cargo install --path .
```

On macOS, **Docker Desktop** is required to execute programs (they run in a Linux guest). Trace files can be analyzed without Docker.

```bash
sysdag doctor
```

## Usage

```bash
# first run of a program: train
sysdag examples/workload.c clean

# later run: monitor
sysdag examples/workload.c attack

# explicit modes
sysdag train tests/fixtures/clean.strace
sysdag monitor tests/fixtures/attack.strace

# end-to-end clean-then-exfil demonstration (needs Docker)
sysdag demo

# Graphviz
sysdag viz .sysdag/runs/<id>/graphs/w0000/graph.json
```

Artifacts land in `.sysdag/` (baselines, traces, JSON graphs, DOT).

## Safety

The guest has **no external network** (`--network=none`). The bundled demo reads only a **harmless decoy** created for the experiment, never real credentials.

## Layout

```text
src/           CLI, parser, DAG, WL, detector, micro-VM runner
examples/      demo workload (C)
guest/         Alpine Dockerfile
tests/         golden traces and pipeline tests
configs/       default window / WL / score weights
```
