//! `mpc-vault --help` carries the non-production notice (Stage 2B, I-2), exits 0
//! without reading a config, key or the network, and leaves every other
//! invocation unchanged.
use std::process::{Command, Output, Stdio};

const CUSTODY_WARNING: &str = "Development build. Not production custody. Do not use with real funds.";

fn run(args: &[&str], cwd: &std::path::Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mpc-vault")).args(args).current_dir(cwd)
        .stdin(Stdio::null()).output().expect("run mpc-vault")
}

#[test]
fn help_prints_the_notice_and_exits_zero_without_side_effects() {
    let dir = tempfile::tempdir().unwrap();
    for flag in ["--help", "-h"] {
        let out = run(&[flag], dir.path());
        let stdout = String::from_utf8(out.stdout).unwrap();
        assert!(out.status.success(), "{flag}: {:?}", out.status);
        assert!(stdout.starts_with("mpc-vault\n"), "{flag}: {stdout}");
        assert!(stdout.contains("NOT PRODUCTION SOFTWARE. EXPERIMENTAL, UNAUDITED DEVELOPMENT SOURCE."));
        assert!(stdout.contains("Do not use it with real keys, funds, identities or secret shares."));
        assert!(stdout.contains(CUSTODY_WARNING));
        assert!(stdout.contains("mpc-vault serve --config <file>"), "usage missing: {stdout}");
        assert!(out.stderr.is_empty());
    }
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0, "help wrote a file");
}

#[test]
fn other_invocations_are_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    for args in [&[][..], &["no-such-command"][..], &["serve"][..]] {
        let out = run(args, dir.path());
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert!(stderr.starts_with("FAIL: usage:"), "{args:?}: {stderr}");
        assert!(out.stdout.is_empty(), "{args:?} printed the help");
    }
}
