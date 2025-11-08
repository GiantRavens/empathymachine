#![cfg(unix)]

use std::{
    fs::{self, File},
    io::Write,
    path::PathBuf,
    process::Command,
};

use serde_json::Value;
use tempfile::tempdir;

use std::os::unix::fs::PermissionsExt;

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn ensure_wrapper_executable(wrapper: &PathBuf) {
    let mut perms = fs::metadata(wrapper)
        .expect("wrapper metadata")
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(wrapper, perms).expect("set wrapper permissions");
}

fn prepare_stub(temp_dir: &PathBuf) -> (PathBuf, PathBuf) {
    let stub_path = temp_dir.join("cargo_stub.py");
    let log_path = temp_dir.join("calls.log");

    let mut stub = File::create(&stub_path).expect("create stub");
    writeln!(
        stub,
        "{}",
        "#!/usr/bin/env python3\nimport os, sys, json\noutput = os.environ['EMPATHYMACHINE_STUB_OUTPUT']\nwith open(output, 'a') as f:\n    json.dump(sys.argv[1:], f)\n    f.write('\\n')\n"
    )
    .expect("write stub");
    drop(stub);

    let mut perms = fs::metadata(&stub_path)
        .expect("stub metadata")
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&stub_path, perms).expect("set stub permissions");

    (stub_path, log_path)
}

fn read_calls(log_path: &PathBuf) -> Vec<Vec<String>> {
    if !log_path.exists() {
        return Vec::new();
    }

    let contents = fs::read_to_string(log_path).expect("read log");
    contents
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            serde_json::from_str::<Value>(line)
                .expect("parse json line")
                .as_array()
                .expect("json array")
                .iter()
                .map(|value| value.as_str().expect("string").to_owned())
                .collect()
        })
        .collect()
}

fn run_wrapper(args: &[&str]) -> Vec<Vec<String>> {
    let root = project_root();
    let wrapper = root.join("bin/empathymachine");
    ensure_wrapper_executable(&wrapper);

    let temp = tempdir().expect("tempdir");
    let temp_path = temp.path().to_path_buf();
    let (stub_path, log_path) = prepare_stub(&temp_path);

    let status = Command::new(&wrapper)
        .args(args)
        .env("EMPATHYMACHINE_CARGO_CMD", &stub_path)
        .env("EMPATHYMACHINE_STUB_OUTPUT", &log_path)
        .current_dir(&root)
        .status()
        .expect("run wrapper");

    assert!(status.success(), "wrapper exited with failure: {:?}", status);

    read_calls(&log_path)
}

#[test]
fn start_without_update_invokes_cargo_once() {
    let calls = run_wrapper(&["start"]);
    assert_eq!(calls.len(), 1, "expected single cargo invocation");
    let args = &calls[0];
    assert!(args.starts_with(&["run".into(), "--manifest-path".into()]), "unexpected args: {:?}", args);
    assert!(args.contains(&"--".into()), "missing terminator in args: {:?}", args);
    assert!(args.iter().all(|arg| arg != "--refresh-blocklists"));
}

#[test]
fn start_with_update_lists_invokes_refresh_then_start() {
    let calls = run_wrapper(&["start", "--update-lists"]);
    assert_eq!(calls.len(), 2, "expected refresh then start invocations");

    let refresh_args = &calls[0];
    assert!(refresh_args.contains(&"--refresh-blocklists".into()));

    let start_args = &calls[1];
    assert!(start_args.iter().all(|arg| arg != "--refresh-blocklists"));
}

#[test]
fn refresh_blocklists_command_passes_flag() {
    let calls = run_wrapper(&["refresh-blocklists"]);
    assert_eq!(calls.len(), 1);
    assert!(calls[0].contains(&"--refresh-blocklists".into()));
}
