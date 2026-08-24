use std::path::PathBuf;
use sysdag::config::Config;
use sysdag::detector::{load_baseline, score_breakdown};
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
fn breakdown_sum_matches_score() {
    let tmp = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/sysdag-breakdown");
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
        Some("fixture-breakdown"),
    )
    .unwrap();
    let bp = train.baseline_path.unwrap();
    let baseline = load_baseline(&bp).unwrap();

    let mon = analyze_path(
        &fixture("attack.strace"),
        Mode::Monitor,
        &cfg,
        &tmp,
        &baselines,
        &[],
        false,
        Some("fixture-breakdown"),
    )
    .unwrap();
    for (enc, dec) in mon.encoded.iter().zip(mon.decisions.iter()) {
        let b = score_breakdown(enc, &baseline, &cfg);
        // total should equal decision.score within tolerance
        assert!((b.total - dec.score).abs() < 1e-6);
    }
}
