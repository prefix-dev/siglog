use std::process::Command;

#[test]
fn repodata_export_is_deterministic_complete_and_atomic() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("repodata.json");
    let output = dir.path().join("entries.jsonl");
    let package = serde_json::json!({
        "name": "pkg", "version": "1.0", "build": "0", "build_number": 0,
        "sha256": "ab".repeat(32), "size": 123,
    });
    let mut repodata = serde_json::json!({
        "info": {"subdir": "noarch"},
        "packages": {"b.tar.bz2": package.clone()},
        "packages.conda": {"a.conda": package},
    });
    std::fs::write(&source, repodata.to_string()).unwrap();
    let run = |out: &std::path::Path| {
        Command::new(env!("CARGO_BIN_EXE_conda-log-ingest"))
            .arg("--file")
            .arg(&source)
            .args(["--subdir", "noarch", "--jsonl-out"])
            .arg(out)
            .output()
            .unwrap()
    };
    let result = run(&output);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let bytes = std::fs::read(&output).unwrap();
    let rows: Vec<serde_json::Value> = String::from_utf8(bytes.clone())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["filename"], "a.conda");
    assert_eq!(rows[1]["filename"], "b.tar.bz2");
    assert!(rows.iter().all(|row| row["subdir"] == "noarch"));
    assert!(
        !run(&output).status.success(),
        "never clobber a frozen export"
    );
    let second = dir.path().join("second.jsonl");
    assert!(run(&second).status.success());
    assert_eq!(bytes, std::fs::read(&second).unwrap());
    repodata["packages"]["b.tar.bz2"]
        .as_object_mut()
        .unwrap()
        .remove("sha256");
    std::fs::write(&source, repodata.to_string()).unwrap();
    let failed = dir.path().join("failed.jsonl");
    assert!(!run(&failed).status.success());
    assert!(!failed.exists(), "partial exports must not become visible");
    assert_eq!(bytes, std::fs::read(&output).unwrap());
}
