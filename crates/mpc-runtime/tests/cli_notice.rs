//! `mpc-custody --help` carries the non-production notice (Stage 2B, I-2), exits
//! 0 without touching any file, and leaves every other invocation unchanged.
use std::process::{Command, Output, Stdio};

const CUSTODY_WARNING: &str = "Development build. Not production custody. Do not use with real funds.";

fn run(args: &[&str], cwd: &std::path::Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mpc-custody")).args(args).current_dir(cwd)
        .stdin(Stdio::null()).output().expect("run mpc-custody")
}

#[test]
fn help_prints_the_notice_and_exits_zero_without_side_effects() {
    let dir = tempfile::tempdir().unwrap();
    for flag in ["--help", "-h"] {
        let out = run(&[flag], dir.path());
        let stdout = String::from_utf8(out.stdout).unwrap();
        assert!(out.status.success(), "{flag}: {:?}", out.status);
        assert!(stdout.starts_with("mpc-custody\n"), "{flag}: {stdout}");
        assert!(stdout.contains("NOT PRODUCTION SOFTWARE. EXPERIMENTAL, UNAUDITED DEVELOPMENT SOURCE."));
        assert!(stdout.contains("Do not use it with real keys, funds, identities or secret shares."));
        assert!(stdout.contains(CUSTODY_WARNING));
        assert!(stdout.contains("mpc-custody verify <state-dir>"), "usage missing: {stdout}");
        assert!(out.stderr.is_empty());
    }
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0, "help wrote a file");
}

#[test]
fn other_invocations_are_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    for args in [&[][..], &["no-such-command"][..], &["verify"][..]] {
        let out = run(args, dir.path());
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert!(stderr.starts_with("FAIL: mpc-custody: usage:"), "{args:?}: {stderr}");
        assert!(out.stdout.is_empty(), "{args:?} printed the help");
    }
    // `--help` is only the first argument; elsewhere it is an ordinary argument.
    let missing = dir.path().join("absent");
    let out = run(&["verify", missing.to_str().unwrap(), "--help"], dir.path());
    assert_eq!(out.status.code(), Some(1));
    assert!(!String::from_utf8(out.stdout).unwrap().contains("NOT PRODUCTION SOFTWARE"));
}
