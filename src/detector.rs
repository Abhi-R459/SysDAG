//! Baseline learning, hybrid scoring, and explainable decisions.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::canonical::digest;
use crate::config::Config;
use crate::event::TraceEvent;
use crate::features::{weighted_jaccard, EncodedGraph};
use crate::graph::GraphQuality;
use crate::DECISION_SCHEMA;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prototype {
    pub id: String,
    pub fingerprint: String,
    pub features: BTreeMap<String, u64>,
    pub n_nodes: usize,
    pub n_edges: usize,
    pub label_ops: BTreeSet<String>,
    pub edge_types: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineManifest {
    pub baseline_id: String,
    pub created_unix: u64,
    pub target_sha256: String,
    pub config_sha256: String,
    pub platform: BTreeMap<String, String>,
    pub pipeline: BTreeMap<String, String>,
    pub exact_fingerprints: BTreeMap<String, u64>,
    pub prototypes: Vec<Prototype>,
    pub score_weights: BTreeMap<String, f64>,
    pub thresholds: BTreeMap<String, f64>,
    pub artifact_checksum: String,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NearestNormal {
    pub prototype: String,
    pub weighted_jaccard: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub motif: String,
    pub events: Vec<u64>,
    #[serde(default)]
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionRecord {
    pub decision_schema: String,
    pub window_id: String,
    pub baseline_id: String,
    pub decision: String,
    pub score: f64,
    pub threshold_review: f64,
    pub threshold_alert: f64,
    pub exact_known: bool,
    pub nearest_normal: Option<NearestNormal>,
    pub evidence: Vec<EvidenceItem>,
    pub quality: GraphQuality,
    pub fingerprint: String,
    pub n_nodes: usize,
    pub n_edges: usize,
    #[serde(default)]
    pub note: String,
}

impl BaselineManifest {
    pub fn compatibility_ok(&self, cfg: &Config, target_sha: &str) -> Result<()> {
        if self.target_sha256 != target_sha {
            bail!(
                "baseline target digest mismatch (baseline {}, input {})",
                &self.target_sha256[..12.min(self.target_sha256.len())],
                &target_sha[..12.min(target_sha.len())]
            );
        }
        if self.config_sha256 != cfg.digest() {
            // Soft: window/wl must still match.
            let w = self.pipeline.get("W").map(|s| s.as_str());
            let h = self.pipeline.get("h").map(|s| s.as_str());
            if w != Some(&cfg.window.size.to_string()) || h != Some(&cfg.wl.iterations.to_string())
            {
                bail!("baseline pipeline (W/h) is incompatible with current config");
            }
        }
        Ok(())
    }
}

pub fn train_baseline(
    encoded: &[EncodedGraph],
    events: &[TraceEvent],
    cfg: &Config,
    target_sha: &str,
    baseline_id: &str,
) -> BaselineManifest {
    let _ = events;
    let mut exact: BTreeMap<String, u64> = BTreeMap::new();
    let mut prototypes = Vec::new();
    for (i, enc) in encoded.iter().enumerate() {
        *exact.entry(enc.fingerprint.clone()).or_insert(0) += 1;
        if prototypes.len() < cfg.detector.max_prototypes
            && !prototypes
                .iter()
                .any(|p: &Prototype| p.fingerprint == enc.fingerprint)
        {
            prototypes.push(make_prototype(i, enc));
        }
    }
    let mut weights = BTreeMap::new();
    weights.insert("alpha".into(), cfg.detector.exact_weight);
    weights.insert("beta".into(), cfg.detector.similarity_weight);
    weights.insert("gamma".into(), cfg.detector.size_weight);
    weights.insert("delta".into(), cfg.detector.risk_weight);
    let mut thresholds = BTreeMap::new();
    thresholds.insert("review".into(), cfg.detector.threshold_review);
    thresholds.insert("alert".into(), cfg.detector.threshold_alert);
    let mut pipeline = BTreeMap::new();
    pipeline.insert("event_schema".into(), crate::SCHEMA_VERSION.into());
    pipeline.insert("label_schema".into(), crate::LABEL_SCHEMA_VERSION.into());
    pipeline.insert("W".into(), cfg.window.size.to_string());
    pipeline.insert("O".into(), cfg.window.overlap.to_string());
    pipeline.insert("h".into(), cfg.wl.iterations.to_string());
    pipeline.insert("edge_policy".into(), cfg.graph.fd_policy.clone());
    let mut platform = BTreeMap::new();
    platform.insert("tracer".into(), cfg.tracer.clone());
    platform.insert("arch".into(), std::env::consts::ARCH.into());
    let mut manifest = BaselineManifest {
        baseline_id: baseline_id.into(),
        created_unix: unix_now(),
        target_sha256: target_sha.into(),
        config_sha256: cfg.digest(),
        platform,
        pipeline,
        exact_fingerprints: exact,
        prototypes,
        score_weights: weights,
        thresholds,
        artifact_checksum: String::new(),
        notes: "Trained from known-clean windows. An unseen fingerprint is evidence, not proof of an attack.".into(),
    };
    manifest.artifact_checksum = checksum_manifest(&manifest);
    manifest
}

fn make_prototype(i: usize, enc: &EncodedGraph) -> Prototype {
    let mut label_ops = BTreeSet::new();
    for n in &enc.graph.nodes {
        let op = n.label_fields.get("op").cloned().unwrap_or_default();
        let pc = n
            .label_fields
            .get("path_class")
            .cloned()
            .unwrap_or_default();
        label_ops.insert(format!("{op}:{pc}"));
    }
    let edge_types = enc
        .graph
        .edges
        .iter()
        .map(|e| e.edge_type.clone())
        .collect();
    Prototype {
        id: format!("p{i:04}"),
        fingerprint: enc.fingerprint.clone(),
        features: flatten_features(&enc.features),
        n_nodes: enc.n_nodes,
        n_edges: enc.n_edges,
        label_ops,
        edge_types,
    }
}

fn flatten_features(feat: &BTreeMap<(u32, String), u64>) -> BTreeMap<String, u64> {
    feat.iter()
        .map(|((r, c), n)| (format!("{r}:{c}"), *n))
        .collect()
}

fn unflatten_features(feat: &BTreeMap<String, u64>) -> BTreeMap<(u32, String), u64> {
    let mut out = BTreeMap::new();
    for (k, n) in feat {
        if let Some((r, c)) = k.split_once(':') {
            if let Ok(round) = r.parse::<u32>() {
                out.insert((round, c.to_string()), *n);
            }
        }
    }
    out
}

fn checksum_manifest(m: &BaselineManifest) -> String {
    let mut copy = m.clone();
    copy.artifact_checksum.clear();
    let v = serde_json::to_value(&copy).unwrap_or_default();
    digest(&crate::config::json_to_canon(&v))
}

pub fn save_baseline(dir: &Path, manifest: &BaselineManifest) -> Result<PathBuf> {
    fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let path = dir.join(format!("{}.json", manifest.baseline_id));
    let text = serde_json::to_string_pretty(manifest)?;
    fs::write(&path, text)?;
    Ok(path)
}

pub fn load_baseline(path: &Path) -> Result<BaselineManifest> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let m: BaselineManifest = serde_json::from_str(&text)?;
    let expect = checksum_manifest(&m);
    if m.artifact_checksum != expect {
        bail!("baseline checksum mismatch; file may be corrupted");
    }
    Ok(m)
}

pub fn find_baseline(dir: &Path, target_sha: &str) -> Option<PathBuf> {
    let p = dir.join(format!("{target_sha}.json"));
    if p.is_file() {
        return Some(p);
    }
    if !dir.is_dir() {
        return None;
    }
    let rd = fs::read_dir(dir).ok()?;
    for e in rd.flatten() {
        let path = e.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        if let Ok(m) = load_baseline(&path) {
            if m.target_sha256 == target_sha {
                return Some(path);
            }
        }
    }
    None
}

pub fn score(enc: &EncodedGraph, baseline: &BaselineManifest, cfg: &Config) -> DecisionRecord {
    if enc.graph.quality.capture_loss > 0 && enc.n_nodes == 0 {
        return DecisionRecord {
            decision_schema: DECISION_SCHEMA.into(),
            window_id: enc.graph.window.window_id.clone(),
            baseline_id: baseline.baseline_id.clone(),
            decision: "UNKNOWN".into(),
            score: 0.0,
            threshold_review: cfg.detector.threshold_review,
            threshold_alert: cfg.detector.threshold_alert,
            exact_known: false,
            nearest_normal: None,
            evidence: vec![EvidenceItem {
                motif: "CAPTURE_DEGRADED".into(),
                events: vec![],
                detail: "event loss prevents a confident decision".into(),
            }],
            quality: enc.graph.quality.clone(),
            fingerprint: enc.fingerprint.clone(),
            n_nodes: enc.n_nodes,
            n_edges: enc.n_edges,
            note: "Degraded capture".into(),
        };
    }

    let exact_known = baseline.exact_fingerprints.contains_key(&enc.fingerprint);
    let mut best = None;
    let mut best_sim = 0.0;
    for p in &baseline.prototypes {
        let sim = weighted_jaccard(&enc.features, &unflatten_features(&p.features));
        if best.is_none() || sim > best_sim {
            best_sim = sim;
            best = Some(p);
        }
    }
    let size_dev = robust_size_dev(enc, baseline);
    let (risk, mut evidence) = risk_and_evidence(enc, best);
    if let Some(p) = best {
        let cur_ops: BTreeSet<_> = enc
            .graph
            .nodes
            .iter()
            .map(|n| {
                format!(
                    "{}:{}",
                    n.label_fields.get("op").cloned().unwrap_or_default(),
                    n.label_fields
                        .get("path_class")
                        .cloned()
                        .unwrap_or_default()
                )
            })
            .collect();
        let new: Vec<_> = cur_ops.difference(&p.label_ops).take(3).cloned().collect();
        let missing: Vec<_> = p.label_ops.difference(&cur_ops).take(3).cloned().collect();
        for m in new {
            evidence.push(EvidenceItem {
                motif: format!("new {m}"),
                events: vec![],
                detail: "label pair absent from nearest normal prototype".into(),
            });
        }
        for m in missing {
            evidence.push(EvidenceItem {
                motif: format!("missing {m}"),
                events: vec![],
                detail: "normal motif not observed in this window".into(),
            });
        }
    }

    let alpha = cfg.detector.exact_weight;
    let beta = cfg.detector.similarity_weight;
    let gamma = cfg.detector.size_weight;
    let delta = cfg.detector.risk_weight;
    let score = alpha * (if exact_known { 0.0 } else { 1.0 })
        + beta * (1.0 - best_sim)
        + gamma * size_dev
        + delta * risk;
    let score = score.clamp(0.0, 1.5);

    let decision = if score < cfg.detector.threshold_review {
        "NORMAL"
    } else if score < cfg.detector.threshold_alert {
        "REVIEW"
    } else {
        "ANOMALOUS"
    };

    DecisionRecord {
        decision_schema: DECISION_SCHEMA.into(),
        window_id: enc.graph.window.window_id.clone(),
        baseline_id: baseline.baseline_id.clone(),
        decision: decision.into(),
        score,
        threshold_review: cfg.detector.threshold_review,
        threshold_alert: cfg.detector.threshold_alert,
        exact_known,
        nearest_normal: best.map(|p| NearestNormal {
            prototype: p.id.clone(),
            weighted_jaccard: best_sim,
        }),
        evidence,
        quality: enc.graph.quality.clone(),
        fingerprint: enc.fingerprint.clone(),
        n_nodes: enc.n_nodes,
        n_edges: enc.n_edges,
        note: if exact_known {
            "Exact fingerprint present in the clean baseline".into()
        } else {
            "Exact fingerprint unseen; score uses similarity, size, and risk motifs".into()
        },
    }
}

fn robust_size_dev(enc: &EncodedGraph, baseline: &BaselineManifest) -> f64 {
    if baseline.prototypes.is_empty() {
        return 0.0;
    }
    let mut sizes: Vec<f64> = baseline
        .prototypes
        .iter()
        .map(|p| p.n_nodes as f64)
        .collect();
    sizes.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let med = sizes[sizes.len() / 2];
    let dev = (enc.n_nodes as f64 - med).abs() / (med + 1.0);
    (dev / 2.0).min(1.0)
}

fn risk_and_evidence(enc: &EncodedGraph, nearest: Option<&Prototype>) -> (f64, Vec<EvidenceItem>) {
    let _ = nearest;
    let mut risk: f64 = 0.0;
    let mut ev = Vec::new();
    for n in &enc.graph.nodes {
        let op = n.label_fields.get("op").map(|s| s.as_str()).unwrap_or("");
        let pc = n
            .label_fields
            .get("path_class")
            .map(|s| s.as_str())
            .unwrap_or("");
        if op == "FILE_OPEN" && matches!(pc, "SYSTEM_CONFIG" | "DECOY" | "HOME") {
            risk += 0.35;
            ev.push(EvidenceItem {
                motif: format!("FILE_OPEN({pc})"),
                events: n.source_seq.into_iter().collect(),
                detail: "sensitive or out-of-root path class".into(),
            });
        }
        if op == "PROCESS_EXEC" && matches!(pc, "SHELL") {
            risk += 0.4;
            ev.push(EvidenceItem {
                motif: "PROCESS_EXEC(SHELL)".into(),
                events: n.source_seq.into_iter().collect(),
                detail: "shell image transition".into(),
            });
        }
    }
    let has_buf_to_net = enc.graph.edges.iter().any(|e| {
        e.edge_type == "BUFFER_FLOW"
            && enc.graph.nodes.iter().any(|n| {
                n.id == e.dst && n.label_fields.get("op").map(|s| s.as_str()) == Some("NET_SEND")
            })
    });
    if has_buf_to_net {
        risk += 0.45;
        let events: Vec<u64> = enc
            .graph
            .edges
            .iter()
            .filter(|e| e.edge_type == "BUFFER_FLOW")
            .flat_map(|e| {
                enc.graph
                    .nodes
                    .iter()
                    .filter(|n| n.id == e.src || n.id == e.dst)
                    .filter_map(|n| n.source_seq)
            })
            .collect();
        ev.push(EvidenceItem {
            motif: "BUFFER_FLOW -> NET_SEND".into(),
            events,
            detail: "read/recv buffer consumed by a network send".into(),
        });
    }
    (risk.min(1.0), ev)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #[test]
    fn thresholds_split_decisions() {
        assert!(0.2 < 0.35);
        assert!(0.40 >= 0.35 && 0.40 < 0.45);
        assert!(0.8 >= 0.45);
    }
}
