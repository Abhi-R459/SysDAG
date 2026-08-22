//! SysCall-DAG: process-scoped syscall dependency graphs and WL fingerprints.

pub mod canonical;
pub mod config;
pub mod detector;
pub mod event;
pub mod features;
pub mod graph;
pub mod labels;
pub mod pipeline;
pub mod sandbox;
pub mod tracer;
pub mod visualizer;

pub use config::Config;
pub use pipeline::{analyze_path, Mode, RunReport};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SCHEMA_VERSION: &str = "1.0";
pub const LABEL_SCHEMA_VERSION: &str = "1.0";
pub const DECISION_SCHEMA: &str = "1.0";
pub const WL_VERSION: &str = "wl-directed-edge-typed-1";
