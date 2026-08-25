use sysdag::baselines::ngram;

#[test]
fn sequence_similarity_drops_when_dummy_calls_are_inserted() {
    let input =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/clean.strace");
    let cfg = sysdag::Config::default();
    let (clean, _) = sysdag::tracer::parse_strace_path(&input, &cfg).unwrap();
    let profile = ngram::train(&clean, vec![1, 2, 3], 0.1, 0.2);
    let mut altered = clean.clone();
    altered.insert(1, altered[0].clone());
    assert!(
        ngram::similarity(
            &ngram::window_ngrams(&altered, &[1, 2, 3]),
            &profile.profile
        ) < 1.0
    );
}
