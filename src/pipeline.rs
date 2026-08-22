use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::canonical::digest_bytes;
use crate::config::Config;
use crate::detector::{
    find_baseline, load_baseline, save_baseline, score, train_baseline, BaselineManifest,
    DecisionRecord,
};
use crate::event::TraceEvent;
use crate::features::{encode, EncodedGraph};
use crate::graph::{build_windows, validate_graph, GraphQuality, GraphRecord};
use crate::sandbox::{
    file_sha256, prepare_run_dir, run_in_microvm, stage_demo_world, stage_target,
};
use crate::tracer::{looks_like_strace, parse_strace_path};
use crate::visualizer::{format_decision, write_graph_artifacts};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Auto,
    Train,
    Monitor,
}

#[derive(Debug, Clone)]
pub struct RunReport {
    pub mode: Mode,
    pub target_sha256: String,
    pub events: usize,
    pub graphs: Vec<GraphRecord>,
    pub encoded: Vec<EncodedGraph>,
    pub decisions: Vec<DecisionRecord>,
    pub baseline_path: Option<PathBuf>,
    pub run_dir: PathBuf,
}

pub enum InputKind {
    Strace,
    EventJsonl,
    Program,
}

pub fn classify_input(path: &Path) -> Result<InputKind> {
    if path.is_dir() {
        return Ok(InputKind::Strace);
    }
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if matches!(ext.as_str(), "c" | "py" | "sh" | "bash") {
        return Ok(InputKind::Program);
    }
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    if bytes.starts_with(b"\x7fELF") {
        return Ok(InputKind::Program);
    }
    // Mach-O cannot run in the Linux guest.
    if bytes.len() >= 4
        && matches!(
            &bytes[..4],
            b"\xcf\xfa\xed\xfe" | b"\xce\xfa\xed\xfe" | b"\xca\xfe\xba\xbe" | b"\xfe\xed\xfa\xce"
        )
    {
        bail!(
            "{} is a macOS binary and cannot run inside the Linux micro-VM.\n\
             Pass a .c / .py / .sh source file, a Linux ELF, or a strace log.",
            path.display()
        );
    }
    let text = String::from_utf8_lossy(&bytes);
    let first = text.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    if first.starts_with('{') && first.contains("schema_version") {
        return Ok(InputKind::EventJsonl);
    }
    if looks_like_strace(&text) {
        return Ok(InputKind::Strace);
    }
    Ok(InputKind::Program)
}

fn ingest(
    path: &Path,
    cfg: &Config,
    work_root: &Path,
    run_id: &str,
    target_args: &[String],
    app_root_override: Option<&str>,
) -> Result<(Vec<TraceEvent>, String, PathBuf, GraphQuality)> {
    let mut cfg = cfg.clone();
    if let Some(root) = app_root_override {
        cfg.labels.app_root = root.to_string();
    }
    match classify_input(path)? {
        InputKind::Strace => {
            let sha = if path.is_file() {
                file_sha256(path)?
            } else {
                digest_bytes(path.to_string_lossy().as_bytes())
            };
            let (events, stats) = parse_strace_path(path, &cfg)?;
            let quality = GraphQuality {
                capture_loss: 0,
                unknown_calls: 0,
                anchor_fraction: 0.0,
                rejected_lines: stats.rejected,
            };
            let run_dir = prepare_run_dir(work_root, run_id)?;
            Ok((events, sha, run_dir, quality))
        }
        InputKind::EventJsonl => {
            let sha = file_sha256(path)?;
            let text = fs::read_to_string(path)?;
            let mut events = Vec::new();
            for (i, line) in text.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                let ev: TraceEvent = serde_json::from_str(line)
                    .with_context(|| format!("{}:{}", path.display(), i + 1))?;
                events.push(ev);
            }
            let run_dir = prepare_run_dir(work_root, run_id)?;
            Ok((events, sha, run_dir, GraphQuality::default()))
        }
        InputKind::Program => {
            cfg.labels.app_root = "/guest/www".into();
            let run_dir = prepare_run_dir(work_root, run_id)?;
            stage_demo_world(&run_dir)?;
            let (_dest, sha) = stage_target(&run_dir, path)?;
            let rel = format!(
                "target/{}",
                path.file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("program")
            );
            let sandbox = run_in_microvm(&cfg, &run_dir, &rel, target_args)?;
            let (events, stats) = parse_strace_path(&sandbox.traces_dir, &cfg)?;
            let quality = GraphQuality {
                rejected_lines: stats.rejected,
                ..GraphQuality::default()
            };
            Ok((events, sha, run_dir, quality))
        }
    }
}

fn encode_all(
    events: &[TraceEvent],
    cfg: &Config,
    run_id: &str,
    key: &str,
    q: GraphQuality,
) -> Result<Vec<EncodedGraph>> {
    if events.is_empty() {
        bail!("no tracked syscall events (file/network/descriptor/process) were captured");
    }
    let graphs = build_windows(events, cfg, run_id, key, q);
    let mut encoded = Vec::new();
    for g in graphs {
        validate_graph(&g).map_err(|e| anyhow::anyhow!("graph invariant: {e}"))?;
        encoded.push(encode(g, cfg));
    }
    Ok(encoded)
}

pub fn analyze_path(
    path: &Path,
    mode: Mode,
    cfg: &Config,
    work_root: &Path,
    baseline_dir: &Path,
    target_args: &[String],
    write_artifacts: bool,
    identity: Option<&str>,
) -> Result<RunReport> {
    let run_id = new_run_id();
    let (events, file_sha, run_dir, quality) =
        ingest(path, cfg, work_root, &run_id, target_args, None)?;
    let target_sha =
        identity
            .map(|s| s.to_string())
            .unwrap_or_else(|| match classify_input(path) {
                Ok(InputKind::Program) => file_sha.clone(),
                _ => "strace-anonymous".into(),
            });
    let encoded = encode_all(&events, cfg, &run_id, &target_sha, quality)?;

    if write_artifacts {
        for (i, enc) in encoded.iter().enumerate() {
            write_graph_artifacts(&run_dir.join("graphs").join(format!("w{i:04}")), &enc.graph)?;
        }
        let jsonl: Vec<String> = events
            .iter()
            .map(|e| serde_json::to_string(e).unwrap_or_default())
            .collect();
        fs::write(run_dir.join("events.jsonl"), jsonl.join("\n"))?;
    }

    let existing = find_baseline(baseline_dir, &target_sha);
    let resolved = match mode {
        Mode::Train => Mode::Train,
        Mode::Monitor => Mode::Monitor,
        Mode::Auto => {
            if existing.is_some() {
                Mode::Monitor
            } else {
                Mode::Train
            }
        }
    };

    match resolved {
        Mode::Train => {
            let baseline = train_baseline(&encoded, &events, cfg, &target_sha, &target_sha);
            let path = save_baseline(baseline_dir, &baseline)?;
            if write_artifacts {
                fs::copy(&path, run_dir.join("baseline.json"))?;
            }
            Ok(RunReport {
                mode: Mode::Train,
                target_sha256: target_sha,
                events: events.len(),
                graphs: encoded.iter().map(|e| e.graph.clone()).collect(),
                encoded,
                decisions: vec![],
                baseline_path: Some(path),
                run_dir,
            })
        }
        Mode::Monitor => {
            let bp = existing.ok_or_else(|| {
                anyhow::anyhow!(
                    "no baseline for this file; run `sysdag train {}` first",
                    path.display()
                )
            })?;
            let baseline = load_baseline(&bp)?;
            baseline.compatibility_ok(cfg, &target_sha)?;
            let decisions: Vec<_> = encoded.iter().map(|e| score(e, &baseline, cfg)).collect();
            if write_artifacts {
                fs::write(
                    run_dir.join("decisions.json"),
                    serde_json::to_string_pretty(&decisions)?,
                )?;
            }
            Ok(RunReport {
                mode: Mode::Monitor,
                target_sha256: target_sha,
                events: events.len(),
                graphs: encoded.iter().map(|e| e.graph.clone()).collect(),
                encoded,
                decisions,
                baseline_path: Some(bp),
                run_dir,
            })
        }
        Mode::Auto => unreachable!(),
    }
}

pub fn run_demo(cfg: &Config, work_root: &Path, json: bool) -> Result<i32> {
    let demo_root = work_root.join("demo");
    fs::create_dir_all(&demo_root)?;
    let run_dir = prepare_run_dir(&demo_root, "world")?;
    stage_demo_world(&run_dir)?;
    let src = run_dir.join("target/workload.c");
    let mut train_cfg = cfg.clone();
    train_cfg.labels.app_root = "/guest/www".into();
    // Demo programs are short; a smaller window still exercises the full pipeline.
    if train_cfg.window.size > 32 {
        train_cfg.window.size = 32;
        train_cfg.window.overlap = 8;
    }

    let mut encoded_train = Vec::new();
    let mut last_sha = String::new();
    for (i, mode) in ["clean", "clean-alt"].iter().enumerate() {
        let id = format!("train-{i}");
        let rd = prepare_run_dir(&demo_root, &id)?;
        stage_demo_world(&rd)?;
        fs::copy(&src, rd.join("target/workload.c"))?;
        let sb = run_in_microvm(&train_cfg, &rd, "target/workload.c", &[mode.to_string()])?;
        last_sha = sb.target_sha256.clone();
        let (events, stats) = parse_strace_path(&sb.traces_dir, &train_cfg)?;
        let q = GraphQuality {
            rejected_lines: stats.rejected,
            ..Default::default()
        };
        encoded_train.extend(encode_all(&events, &train_cfg, &id, &last_sha, q)?);
    }
    let baseline = train_baseline(&encoded_train, &[], &train_cfg, &last_sha, &last_sha);
    let bdir = demo_root.join("baselines");
    let bpath = save_baseline(&bdir, &baseline)?;

    let monitor = |tag: &str, arg: &str| -> Result<Vec<DecisionRecord>> {
        let rd = prepare_run_dir(&demo_root, tag)?;
        stage_demo_world(&rd)?;
        fs::copy(&src, rd.join("target/workload.c"))?;
        let sb = run_in_microvm(&train_cfg, &rd, "target/workload.c", &[arg.to_string()])?;
        let (events, stats) = parse_strace_path(&sb.traces_dir, &train_cfg)?;
        let q = GraphQuality {
            rejected_lines: stats.rejected,
            ..Default::default()
        };
        let enc = encode_all(&events, &train_cfg, tag, &sb.target_sha256, q)?;
        for (i, e) in enc.iter().enumerate() {
            write_graph_artifacts(&rd.join("graphs").join(format!("w{i:04}")), &e.graph)?;
        }
        Ok(enc
            .iter()
            .map(|e| score(e, &baseline, &train_cfg))
            .collect())
    };

    let clean = monitor("heldout-clean", "clean")?;
    let attack = monitor("attack-exfil", "attack")?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "baseline": bpath,
                "clean": clean,
                "attack": attack,
            }))?
        );
    } else {
        println!("SysCall-DAG demo");
        println!("  baseline {}", bpath.display());
        println!("  clean windows:");
        for d in &clean {
            println!("    {}  {}", d.window_id, format_decision(d));
        }
        println!("  attack windows:");
        for d in &attack {
            println!("    {}  {}", d.window_id, format_decision(d));
        }
        let anomalous = attack
            .iter()
            .any(|d| d.decision == "ANOMALOUS" || d.decision == "REVIEW");
        if anomalous {
            println!("\nAttack window diverged from the clean file-root baseline (decoy read + network send).");
        } else {
            println!("\nWarning: attack did not cross the review threshold; inspect graphs under .sysdag/demo/");
        }
    }

    let failed_clean = clean.iter().any(|d| d.decision == "ANOMALOUS");
    let caught = attack
        .iter()
        .any(|d| d.decision == "ANOMALOUS" || d.decision == "REVIEW");
    Ok(if !failed_clean && caught { 0 } else { 2 })
}

pub fn print_report(report: &RunReport, json: bool) -> Result<i32> {
    if json {
        let v = serde_json::json!({
            "mode": format!("{:?}", report.mode),
            "target_sha256": report.target_sha256,
            "events": report.events,
            "windows": report.encoded.len(),
            "baseline": report.baseline_path,
            "run_dir": report.run_dir,
            "decisions": report.decisions,
        });
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        match report.mode {
            Mode::Train => {
                println!(
                    "trained baseline from {} events / {} windows",
                    report.events,
                    report.encoded.len()
                );
                if let Some(p) = &report.baseline_path {
                    println!("wrote {}", p.display());
                }
                println!("re-run `sysdag <file>` on a new workload to monitor");
            }
            Mode::Monitor => {
                println!(
                    "monitored {} events / {} windows",
                    report.events,
                    report.encoded.len()
                );
                for d in &report.decisions {
                    println!("  {}  {}", d.window_id, format_decision(d));
                }
            }
            Mode::Auto => {}
        }
        println!("artifacts {}", report.run_dir.display());
    }
    let anomalous = report.decisions.iter().any(|d| d.decision == "ANOMALOUS");
    Ok(if anomalous { 2 } else { 0 })
}

fn new_run_id() -> String {
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("run-{ns}")
}

pub fn monitor_events(
    events: Vec<TraceEvent>,
    cfg: &Config,
    baseline: &BaselineManifest,
    run_id: &str,
) -> Result<Vec<DecisionRecord>> {
    let sha = baseline.target_sha256.clone();
    let encoded = encode_all(&events, cfg, run_id, &sha, GraphQuality::default())?;
    Ok(encoded.iter().map(|e| score(e, baseline, cfg)).collect())
}
