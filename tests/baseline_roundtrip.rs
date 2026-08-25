use std::path::PathBuf;

use sysdag::config::Config;
use sysdag::detector::load_baseline;
use sysdag::pipeline::{analyze_path, Mode};

fn cfg() -> Config {
    let mut c = Config::default();
    c.window.size = 16;
    c.window.overlap = 4;
    c.labels.app_root = "/guest/www".into();
    c
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn baseline_roundtrip() {
    let tmp = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/sysdag-roundtrip");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let cfg = cfg();
    let baselines = tmp.join("baselines");

    let train = analyze_path(
        &fixture("clean.strace"),
        Mode::Train,
        &cfg,
        &tmp,
        &baselines,
        &[],
        false,
        Some("fixture-roundtrip"),
    )
    .unwrap();
    assert!(train.baseline_path.is_some());
    let path = train.baseline_path.unwrap();

    // load_baseline validates checksum; this will fail if file corrupt
    let manifest = load_baseline(&path).unwrap();
    // compatibility_ok checks target/config pipelines; should succeed
    manifest
        .compatibility_ok(&cfg, &manifest.target_sha256)
        .unwrap();
}
