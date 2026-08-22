//! Resource-state machine and windowed typed event DAG construction.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use serde::{Deserialize, Serialize};

use crate::canonical::{digest, Canon};
use crate::config::Config;
use crate::event::TraceEvent;
use crate::labels::{is_fd_allocator, is_shell_path, label_digest, syscall_class};
use crate::{LABEL_SCHEMA_VERSION, SCHEMA_VERSION};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub source_seq: Option<u64>,
    pub label_fields: BTreeMap<String, String>,
    pub label_digest: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct GraphEdge {
    pub src: String,
    pub dst: String,
    #[serde(rename = "type")]
    pub edge_type: String,
    pub resource_class: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowMeta {
    pub start_seq: u64,
    pub end_seq: u64,
    pub w: usize,
    pub overlap: usize,
    pub complete: bool,
    pub window_id: String,
    pub event_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GraphQuality {
    pub capture_loss: u64,
    pub unknown_calls: u64,
    pub anchor_fraction: f64,
    pub rejected_lines: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphRecord {
    pub graph_schema: String,
    pub label_schema: String,
    pub graph_id: String,
    pub baseline_key: String,
    pub window: WindowMeta,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub quality: GraphQuality,
    pub graph_digest_before_wl: String,
}

#[derive(Clone)]
struct FdRes {
    generation: u64,
    kind: String,
    last_seq: u64,
}

#[derive(Clone, Default)]
struct BufferWriter {
    seq: u64,
    start: Option<u64>,
    end: Option<u64>,
}

struct ProcessState {
    fd: HashMap<i32, FdRes>,
    fd_gen: HashMap<i32, u64>,
    last_writer: Option<BufferWriter>,
    image_gen: u64,
    seeded: bool,
}

impl ProcessState {
    fn new() -> Self {
        Self {
            fd: HashMap::new(),
            fd_gen: HashMap::new(),
            last_writer: None,
            image_gen: 0,
            seeded: false,
        }
    }
}

pub fn build_windows(
    events: &[TraceEvent],
    cfg: &Config,
    run_id: &str,
    baseline_key: &str,
    quality: GraphQuality,
) -> Vec<GraphRecord> {
    let w = cfg.window.size.max(1);
    let o = cfg.window.overlap.min(w.saturating_sub(1));
    let mut buf: VecDeque<&TraceEvent> = VecDeque::new();
    let mut state: HashMap<i32, ProcessState> = HashMap::new();
    let mut out = Vec::new();
    let mut win_idx = 0u32;

    for ev in events {
        if cfg.window.flush_on_exec && ev.syscall.name.starts_with("execve") && ev.success() {
            if !buf.is_empty() {
                out.push(emit_window(
                    &buf.make_contiguous().to_vec(),
                    &state,
                    cfg,
                    run_id,
                    baseline_key,
                    win_idx,
                    false,
                    quality.clone(),
                ));
                win_idx += 1;
                buf.clear();
            }
            if let Some(ps) = state.get_mut(&ev.process.pid) {
                ps.image_gen += 1;
                ps.last_writer = None;
            }
        }

        buf.push_back(ev);
        apply_state(&mut state, ev, cfg);

        if buf.len() >= w {
            let slice: Vec<&TraceEvent> = buf.iter().copied().collect();
            out.push(emit_window(
                &slice,
                &state,
                cfg,
                run_id,
                baseline_key,
                win_idx,
                true,
                quality.clone(),
            ));
            win_idx += 1;
            let keep = o;
            while buf.len() > keep {
                buf.pop_front();
            }
        }
    }

    if cfg.window.include_incomplete_tail && !buf.is_empty() {
        let slice: Vec<&TraceEvent> = buf.iter().copied().collect();
        out.push(emit_window(
            &slice,
            &state,
            cfg,
            run_id,
            baseline_key,
            win_idx,
            slice.len() >= w,
            quality,
        ));
    }
    out
}

fn apply_state(state: &mut HashMap<i32, ProcessState>, ev: &TraceEvent, cfg: &Config) {
    let pid = ev.process.pid;
    let ps = state.entry(pid).or_insert_with(ProcessState::new);
    if cfg.graph.seed_stdio && !ps.seeded {
        for fd in 0..3 {
            ps.fd.insert(
                fd,
                FdRes {
                    generation: 0,
                    kind: "FILE".into(),
                    last_seq: 0,
                },
            );
        }
        ps.seeded = true;
    }

    let name = ev.syscall.name.as_str();
    if ev.success() && matches!(name, "clone" | "clone3" | "fork" | "vfork") {
        if let Some(child) = ev.args.child_pid {
            let snapshot = clone_state(ps);
            state.insert(child, snapshot);
        }
    }

    let ps = state.entry(pid).or_insert_with(ProcessState::new);

    if ev.success() && is_fd_allocator(name) {
        if let Some(fd) = ev.args.fd {
            if matches!(name, "dup" | "dup2" | "dup3") {
                if let Some(src) = ev.args.fd.filter(|_| name == "dup") {
                    if let Some(res) = ps.fd.get(&src).cloned() {
                        let target = ev.args.fd.unwrap_or(fd);
                        ps.fd.insert(
                            target,
                            FdRes {
                                generation: res.generation,
                                kind: res.kind,
                                last_seq: ev.seq,
                            },
                        );
                    }
                }
                if matches!(name, "dup2" | "dup3") {
                    if let (Some(old), Some(newfd)) = (ev.args.fd, ev.args.newfd) {
                        if let Some(res) = ps.fd.get(&old).cloned() {
                            ps.fd.insert(
                                newfd,
                                FdRes {
                                    generation: res.generation,
                                    kind: res.kind,
                                    last_seq: ev.seq,
                                },
                            );
                        }
                    }
                }
            } else {
                let gen = ps.fd_gen.entry(fd).or_insert(0);
                *gen += 1;
                let kind =
                    if syscall_class(name) == "network" || ev.labels.resource_kind == "SOCKET" {
                        "SOCKET"
                    } else {
                        "FILE"
                    };
                ps.fd.insert(
                    fd,
                    FdRes {
                        generation: *gen,
                        kind: kind.into(),
                        last_seq: ev.seq,
                    },
                );
            }
        }
    }

    if ev.success() && matches!(name, "pipe" | "pipe2") {
        if let Some((r, w)) = ev.args.pipe_fds {
            for fd in [r, w] {
                let gen = ps.fd_gen.entry(fd).or_insert(0);
                *gen += 1;
                ps.fd.insert(
                    fd,
                    FdRes {
                        generation: *gen,
                        kind: "PIPE".into(),
                        last_seq: ev.seq,
                    },
                );
            }
        }
    }

    if ev.success() {
        if let Some(fd) = ev.args.fd {
            if let Some(res) = ps.fd.get_mut(&fd) {
                if !is_fd_allocator(name) || matches!(name, "dup" | "dup2" | "dup3") {
                    // last-event-chain update for consumers
                    if !matches!(name, "dup" | "dup2" | "dup3" | "open" | "openat" | "socket") {
                        res.last_seq = ev.seq;
                    }
                }
            }
        }
    }

    if ev.success() && name == "close" {
        if let Some(fd) = ev.args.fd {
            if let Some(res) = ps.fd.get_mut(&fd) {
                res.last_seq = ev.seq;
            }
            ps.fd.remove(&fd);
        }
    }

    if cfg.graph.buffer_flow && ev.success() {
        let is_prod = matches!(
            name,
            "read" | "pread64" | "readv" | "recvfrom" | "recv" | "recvmsg"
        );
        let is_cons = matches!(
            name,
            "write" | "pwrite64" | "writev" | "sendto" | "send" | "sendmsg"
        );
        if is_prod {
            let n = ev.ret.filter(|v| *v > 0).unwrap_or(0) as u64;
            ps.last_writer = Some(BufferWriter {
                seq: ev.seq,
                start: ev.args.buffer_addr,
                end: ev.args.buffer_addr.map(|a| a.saturating_add(n)),
            });
        } else if is_cons {
            // consumer observed later when building edges
        }
    }
}

fn clone_state(ps: &ProcessState) -> ProcessState {
    ProcessState {
        fd: ps.fd.clone(),
        fd_gen: ps.fd_gen.clone(),
        last_writer: None,
        image_gen: ps.image_gen,
        seeded: true,
    }
}

fn emit_window(
    events: &[&TraceEvent],
    live: &HashMap<i32, ProcessState>,
    cfg: &Config,
    run_id: &str,
    baseline_key: &str,
    idx: u32,
    complete: bool,
    mut quality: GraphQuality,
) -> GraphRecord {
    let _ = live;
    let window_id = format!("{run_id}:w{idx:04}");
    let start_seq = events.first().map(|e| e.seq).unwrap_or(0);
    let end_seq = events.last().map(|e| e.seq).unwrap_or(0);
    let in_window: BTreeSet<u64> = events.iter().map(|e| e.seq).collect();

    let mut seq_to_id: HashMap<u64, String> = HashMap::new();
    let mut nodes = Vec::new();
    for (i, ev) in events.iter().enumerate() {
        let id = format!("n{i:04}");
        seq_to_id.insert(ev.seq, id.clone());
        let mut fields = BTreeMap::new();
        fields.insert("family".into(), ev.labels.family.clone());
        fields.insert("op".into(), ev.labels.op.clone());
        fields.insert("result".into(), ev.labels.result.clone());
        fields.insert("resource_kind".into(), ev.labels.resource_kind.clone());
        fields.insert("flags".into(), ev.labels.flags.clone());
        fields.insert("bytes".into(), ev.labels.bytes.clone());
        fields.insert("path_class".into(), ev.labels.path_class.clone());
        nodes.push(GraphNode {
            id,
            source_seq: Some(ev.seq),
            label_digest: label_digest(&ev.labels),
            label_fields: fields,
            kind: "event".into(),
        });
    }

    let mut anchors: HashMap<String, String> = HashMap::new();
    let mut edges: BTreeSet<GraphEdge> = BTreeSet::new();
    let mut replay: HashMap<i32, ProcessState> = HashMap::new();
    let mut last_writer: HashMap<i32, BufferWriter> = HashMap::new();

    let add_edge = |src_seq: Option<u64>,
                    dst_seq: u64,
                    etype: &str,
                    class: &str,
                    anchors: &mut HashMap<String, String>,
                    nodes: &mut Vec<GraphNode>,
                    edges: &mut BTreeSet<GraphEdge>,
                    seq_to_id: &HashMap<u64, String>| {
        let dst = match seq_to_id.get(&dst_seq) {
            Some(id) => id.clone(),
            None => return,
        };
        let src = match src_seq {
            Some(s) if in_window.contains(&s) => seq_to_id.get(&s).cloned(),
            Some(_) | None if cfg.graph.external_anchors => {
                let key = match class {
                    "SOCKET" => "EXTERNAL_SOCKET",
                    "PROCESS" => "EXTERNAL_PROCESS",
                    "FILE" | "PIPE" => "EXTERNAL_FILE",
                    _ => "UNKNOWN_PRODUCER",
                };
                Some(
                    anchors
                        .entry(key.into())
                        .or_insert_with(|| {
                            let id = format!("a:{key}");
                            let mut fields = BTreeMap::new();
                            fields.insert("family".into(), "anchor".into());
                            fields.insert("op".into(), key.into());
                            fields.insert("result".into(), "SUCCESS".into());
                            fields.insert("resource_kind".into(), class.into());
                            fields.insert("flags".into(), "NONE".into());
                            fields.insert("bytes".into(), "NONE".into());
                            fields.insert("path_class".into(), "NONE".into());
                            nodes.push(GraphNode {
                                id: id.clone(),
                                source_seq: None,
                                label_digest: digest(&Canon::str(key)),
                                label_fields: fields,
                                kind: "anchor".into(),
                            });
                            id
                        })
                        .clone(),
                )
            }
            _ => None,
        };
        let Some(src) = src else { return };
        if src == dst {
            return;
        }
        if let (Some(ss), _) = (src_seq, dst_seq) {
            if ss >= dst_seq {
                return;
            }
        }
        edges.insert(GraphEdge {
            src,
            dst,
            edge_type: etype.into(),
            resource_class: class.into(),
        });
    };

    for ev in events {
        let pid = ev.process.pid;
        let name = ev.syscall.name.as_str();
        let child_snapshot = {
            let ps = replay.entry(pid).or_insert_with(ProcessState::new);
            if cfg.graph.seed_stdio && !ps.seeded {
                for fd in 0..3 {
                    ps.fd.insert(
                        fd,
                        FdRes {
                            generation: 0,
                            kind: "FILE".into(),
                            last_seq: 0,
                        },
                    );
                }
                ps.seeded = true;
            }

            if ev.success() && matches!(name, "clone" | "clone3" | "fork" | "vfork") {
                add_edge(
                    None,
                    ev.seq,
                    "PROCESS_FLOW",
                    "PROCESS",
                    &mut anchors,
                    &mut nodes,
                    &mut edges,
                    &seq_to_id,
                );
            }

            if ev.success() && matches!(name, "execve" | "execveat") {
                add_edge(
                    None,
                    ev.seq,
                    "PROCESS_FLOW",
                    "PROCESS",
                    &mut anchors,
                    &mut nodes,
                    &mut edges,
                    &seq_to_id,
                );
                let _ = is_shell_path(ev.args.path.as_deref().unwrap_or(""));
            }

            if let Some(fd) = ev.args.fd {
                let prior = ps.fd.get(&fd).cloned();
                if let Some(res) = prior {
                    if res.last_seq != ev.seq {
                        add_edge(
                            if res.last_seq == 0 {
                                None
                            } else {
                                Some(res.last_seq)
                            },
                            ev.seq,
                            "FD_FLOW",
                            &res.kind,
                            &mut anchors,
                            &mut nodes,
                            &mut edges,
                            &seq_to_id,
                        );
                    }
                } else if !is_fd_allocator(name) {
                    add_edge(
                        None,
                        ev.seq,
                        "FD_FLOW",
                        &ev.labels.resource_kind,
                        &mut anchors,
                        &mut nodes,
                        &mut edges,
                        &seq_to_id,
                    );
                }
            }

            if ev.success() && is_fd_allocator(name) {
                if let Some(fd) = ev.args.fd {
                    if matches!(name, "dup2" | "dup3") {
                        if let (Some(old), Some(newfd)) = (ev.args.fd, ev.args.newfd) {
                            if let Some(res) = ps.fd.get(&old).cloned() {
                                ps.fd.insert(
                                    newfd,
                                    FdRes {
                                        generation: res.generation,
                                        kind: res.kind,
                                        last_seq: ev.seq,
                                    },
                                );
                            }
                        }
                    } else if name == "dup" {
                        if let Some(old) = ev.args.fd {
                            if let Some(res) = ps.fd.get(&old).cloned() {
                                ps.fd.insert(
                                    fd,
                                    FdRes {
                                        generation: res.generation,
                                        kind: res.kind,
                                        last_seq: ev.seq,
                                    },
                                );
                            }
                        }
                    } else {
                        let gen = ps.fd_gen.entry(fd).or_insert(0);
                        *gen += 1;
                        ps.fd.insert(
                            fd,
                            FdRes {
                                generation: *gen,
                                kind: ev.labels.resource_kind.clone(),
                                last_seq: ev.seq,
                            },
                        );
                    }
                }
            } else if ev.success() {
                if let Some(fd) = ev.args.fd {
                    if let Some(res) = ps.fd.get_mut(&fd) {
                        res.last_seq = ev.seq;
                    }
                }
            }

            if ev.success() && name == "close" {
                if let Some(fd) = ev.args.fd {
                    ps.fd.remove(&fd);
                }
            }

            if ev.success() && matches!(name, "pipe" | "pipe2") {
                if let Some((r, wfd)) = ev.args.pipe_fds {
                    for fd in [r, wfd] {
                        let gen = ps.fd_gen.entry(fd).or_insert(0);
                        *gen += 1;
                        ps.fd.insert(
                            fd,
                            FdRes {
                                generation: *gen,
                                kind: "PIPE".into(),
                                last_seq: ev.seq,
                            },
                        );
                    }
                }
            }

            if ev.success() && matches!(name, "clone" | "clone3" | "fork" | "vfork") {
                ev.args.child_pid.map(|child| (child, clone_state(ps)))
            } else {
                None
            }
        };
        if let Some((child, snap)) = child_snapshot {
            replay.insert(child, snap);
        }

        if cfg.graph.buffer_flow && ev.success() {
            let is_prod = matches!(
                name,
                "read" | "pread64" | "readv" | "recvfrom" | "recv" | "recvmsg"
            ) && ev.ret.unwrap_or(0) > 0;
            let is_cons = matches!(
                name,
                "write" | "pwrite64" | "writev" | "sendto" | "send" | "sendmsg"
            );
            if is_prod {
                let n = ev.ret.unwrap_or(0) as u64;
                last_writer.insert(
                    pid,
                    BufferWriter {
                        seq: ev.seq,
                        start: ev.args.buffer_addr,
                        end: ev.args.buffer_addr.map(|a| a + n),
                    },
                );
            } else if is_cons {
                if let Some(w) = last_writer.get(&pid).cloned() {
                    let overlap = match (w.start, w.end, ev.args.buffer_addr, ev.args.count) {
                        (Some(a0), Some(a1), Some(b0), Some(len)) if len > 0 => {
                            let b1 = b0 + len as u64;
                            a0 < b1 && b0 < a1
                        }
                        _ => cfg.graph.buffer_heuristic == "address_or_last_writer",
                    };
                    if overlap && w.seq < ev.seq {
                        add_edge(
                            Some(w.seq),
                            ev.seq,
                            "BUFFER_FLOW",
                            "BUFFER",
                            &mut anchors,
                            &mut nodes,
                            &mut edges,
                            &seq_to_id,
                        );
                    }
                }
            }
        }
    }

    nodes.sort_by(|a, b| a.id.cmp(&b.id));
    let edge_list: Vec<GraphEdge> = edges.into_iter().collect();
    let anchor_count = nodes.iter().filter(|n| n.kind == "anchor").count();
    quality.anchor_fraction = if nodes.is_empty() {
        0.0
    } else {
        anchor_count as f64 / nodes.len() as f64
    };

    let digest_src = Canon::map_from([
        (
            "nodes",
            Canon::List(
                nodes
                    .iter()
                    .map(|n| {
                        Canon::map_from([
                            ("id", Canon::str(&n.id)),
                            ("label", Canon::str(&n.label_digest)),
                            ("kind", Canon::str(&n.kind)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "edges",
            Canon::List(
                edge_list
                    .iter()
                    .map(|e| {
                        Canon::map_from([
                            ("src", Canon::str(&e.src)),
                            ("dst", Canon::str(&e.dst)),
                            ("type", Canon::str(&e.edge_type)),
                            ("class", Canon::str(&e.resource_class)),
                        ])
                    })
                    .collect(),
            ),
        ),
    ]);

    GraphRecord {
        graph_schema: SCHEMA_VERSION.into(),
        label_schema: LABEL_SCHEMA_VERSION.into(),
        graph_id: window_id.clone(),
        baseline_key: baseline_key.into(),
        window: WindowMeta {
            start_seq,
            end_seq,
            w: cfg.window.size,
            overlap: cfg.window.overlap,
            complete,
            window_id: window_id.clone(),
            event_count: events.len(),
        },
        graph_digest_before_wl: digest(&digest_src),
        nodes,
        edges: edge_list,
        quality,
    }
}

pub fn validate_graph(g: &GraphRecord) -> Result<(), String> {
    let ids: BTreeSet<_> = g.nodes.iter().map(|n| n.id.as_str()).collect();
    if ids.len() != g.nodes.len() {
        return Err("duplicate node ids".into());
    }
    let seqs: HashMap<_, _> = g
        .nodes
        .iter()
        .filter_map(|n| n.source_seq.map(|s| (n.id.as_str(), s)))
        .collect();
    for e in &g.edges {
        if !ids.contains(e.src.as_str()) || !ids.contains(e.dst.as_str()) {
            return Err("edge endpoint missing".into());
        }
        if let (Some(a), Some(b)) = (seqs.get(e.src.as_str()), seqs.get(e.dst.as_str())) {
            if a >= b {
                return Err("backward edge".into());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{CaptureInfo, EventArgs, ProcessRef, SyscallRef};
    use crate::labels::build_labels;

    fn ev(seq: u64, name: &str, path: &str, fd: Option<i32>, ret: i64) -> TraceEvent {
        let args = EventArgs {
            fd,
            path: if path.is_empty() {
                None
            } else {
                Some(path.into())
            },
            ..Default::default()
        };
        let labels = build_labels(name, path, "", "", "", Some(ret), None, Some(ret), "/app");
        TraceEvent::new(
            ProcessRef {
                pid: 1,
                tid: 1,
                start_ns: 0,
                image_gen: 0,
                comm: "t".into(),
            },
            seq,
            seq * 10,
            seq * 10 + 1,
            SyscallRef {
                nr: 0,
                name: name.into(),
                arch: "test".into(),
            },
            args,
            Some(ret),
            None,
            labels,
            CaptureInfo::default(),
        )
    }

    #[test]
    fn fd_chain_and_reuse() {
        let mut cfg = Config::default();
        cfg.window.size = 10;
        cfg.window.overlap = 0;
        cfg.labels.app_root = "/app".into();
        let events = vec![
            ev(1, "openat", "/app/a", Some(3), 3),
            ev(2, "read", "/app/a", Some(3), 8),
            ev(3, "close", "", Some(3), 0),
            ev(4, "openat", "/app/b", Some(3), 3),
            ev(5, "read", "/app/b", Some(3), 4),
        ];
        let graphs = build_windows(&events, &cfg, "t", "k", GraphQuality::default());
        assert_eq!(graphs.len(), 1);
        validate_graph(&graphs[0]).unwrap();
        assert!(graphs[0].edges.iter().any(|e| e.edge_type == "FD_FLOW"));
    }
}
