use super::*;
use netdiag_core::ingest::ingest_trace;
use netdiag_core::ml::train_model_from_jsonl;
use std::fs;
use std::io::Write;

fn sample(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../data/samples")
        .join(format!("{name}.csv"))
}

fn path_str(path: &std::path::Path) -> &str {
    path.to_str().expect("test path is utf-8")
}

fn repo_file(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

fn provision_test_model(artifacts: &std::path::Path) {
    fs::create_dir_all(artifacts).expect("artifacts dir");
    let dataset_path = artifacts.join("training.jsonl");
    let mut dataset = fs::File::create(&dataset_path).expect("create dataset");
    for name in [
        "normal",
        "congestion",
        "random_loss",
        "dns_failure",
        "tls_failure",
        "udp_quic_blocked",
    ] {
        let ingest = ingest_trace(sample(name)).expect("sample ingest");
        let row = serde_json::json!({
            "label": name,
            "records": ingest.records,
        });
        writeln!(dataset, "{row}").expect("write training row");
    }
    train_model_from_jsonl(&dataset_path, artifacts.join("model")).expect("train model");
}

#[test]
fn top_level_pilot_command_dispatches_to_pilot_module() {
    let temp = tempfile::tempdir().expect("tempdir");
    provision_test_model(temp.path());
    let args = Args::parse_from([
        "netdiag",
        "pilot",
        "preflight",
        path_str(&repo_file("examples/pilots/connector-family-readonly.yaml")),
        "--artifacts",
        path_str(temp.path()),
    ]);

    run(args).expect("pilot preflight dispatch");
}
