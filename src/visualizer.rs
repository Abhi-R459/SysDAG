use std::fs;
use std::path::Path;

use anyhow::Result;

use crate::detector::DecisionRecord;
use crate::graph::GraphRecord;

pub fn to_dot(graph: &GraphRecord) -> String {
    let mut out =
        String::from("digraph syscall_dag {\n  rankdir=LR;\n  node [shape=box,fontsize=10];\n");
    for n in &graph.nodes {
        let op = n.label_fields.get("op").map(|s| s.as_str()).unwrap_or("?");
        let pc = n
            .label_fields
            .get("path_class")
            .map(|s| s.as_str())
            .unwrap_or("");
        let color = if n.kind == "anchor" {
            "lightgrey"
        } else if matches!(pc, "DECOY" | "SYSTEM_CONFIG" | "HOME") {
            "lightcoral"
        } else if op.contains("NET_") {
            "lightgoldenrod"
        } else {
            "lightblue"
        };
        let seq = n.source_seq.map(|s| format!("#{s}")).unwrap_or_default();
        out.push_str(&format!(
            "  \"{id}\" [label=\"{id}\\n{op} {pc} {seq}\", style=filled, fillcolor={color}];\n",
            id = n.id
        ));
    }
    for e in &graph.edges {
        out.push_str(&format!(
            "  \"{}\" -> \"{}\" [label=\"{}\"];\n",
            e.src, e.dst, e.edge_type
        ));
    }
    out.push_str("}\n");
    out
}

pub fn write_graph_artifacts(dir: &Path, graph: &GraphRecord) -> Result<()> {
    fs::create_dir_all(dir)?;
    fs::write(dir.join("graph.json"), serde_json::to_string_pretty(graph)?)?;
    fs::write(dir.join("graph.dot"), to_dot(graph))?;
    Ok(())
}

pub fn format_decision(d: &DecisionRecord) -> String {
    let nearest = d
        .nearest_normal
        .as_ref()
        .map(|n| format!("{} sim={:.3}", n.prototype, n.weighted_jaccard))
        .unwrap_or_else(|| "-".into());
    let motifs: Vec<_> = d
        .evidence
        .iter()
        .take(3)
        .map(|e| e.motif.as_str())
        .collect();
    format!(
        "{:<10} score={:.3} exact={} nodes={} edges={} nearest={} {}",
        d.decision,
        d.score,
        if d.exact_known { "yes" } else { "no" },
        d.n_nodes,
        d.n_edges,
        nearest,
        motifs.join("; ")
    )
}
