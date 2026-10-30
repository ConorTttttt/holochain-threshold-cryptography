#!/usr/bin/env python3
"""Offline release check: static checks, a from-scratch zome rebuild compared
byte for byte with the recorded hashes, and the native test suites.

Every cargo command runs with `--offline --locked`. Nothing here touches a
conductor, Lair, a sandbox under $HOME or the network. The WASM is built into a
fresh target directory, so a cached artifact can never satisfy the comparison.

Order (the brief's order, with the build moved ahead of the import audit
because `check:wasm-imports` reads the freshly built WASM):
  validator-tests, manifest, versions, wasm-build, wasm-imports, pack, identity,
  help-notices, native, lockfile

Exit status: 0 all steps pass, 1 any step failed, 2 a step was skipped.

Usage:
  python3 -I scripts/release_check.py [--skip-native] [--wasm-target-dir DIR]
  python3 -I scripts/release_check.py --record --confirm-record

`--record` rewrites scripts/release_hashes.json from a fresh build. It is an
operator action after reviewing a coordinator change; it never runs by default.
This is a reproducibility check, NOT a security audit or build attestation.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HASHES = ROOT / "scripts/release_hashes.json"
INVENTORY = ROOT / "scripts/release_inventory.json"
NOTICE_SOURCE = ROOT / "crates/mpc-dkg-worker/src/notice.rs"
# Extra line required of every binary the inventory marks `custody_warning`
# (it holds share custody or moves funds).
CUSTODY_WARNING = "Development build. Not production custody. Do not use with real funds."
SCHEMA = 1
RESULT = re.compile(r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tool_version(*cmd: str) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        return "unavailable"
    return out.strip().splitlines()[0] if out.strip() else "unavailable"


class Step:
    def __init__(self, name: str):
        self.name, self.status, self.detail, self.seconds = name, "SKIP", "", 0.0


class Runner:
    def __init__(self, log_dir: Path):
        self.log_dir = log_dir
        self.steps: list[Step] = []
        self.env = dict(os.environ, CARGO_NET_OFFLINE="true", CARGO_TERM_COLOR="never")

    def run(self, step: Step, cmd: list[str], env: dict | None = None, cwd: Path = ROOT) -> subprocess.CompletedProcess:
        log = self.log_dir / f"{step.name}.log"
        with log.open("ab") as out:
            out.write(f"$ {shlex.join(cmd)}\n".encode())
            out.flush()
            proc = subprocess.run(cmd, cwd=cwd, env=env or self.env, stdout=out,
                                  stderr=subprocess.STDOUT)
        return proc

    def log_text(self, step: Step) -> str:
        path = self.log_dir / f"{step.name}.log"
        return path.read_text(errors="replace") if path.exists() else ""


def cargo(args: list[str]) -> list[str]:
    """Insert --offline --locked after the cargo subcommand."""
    return ["cargo", args[0], "--offline", "--locked", *args[1:]]


def expand_script(scripts: dict, name: str, seen: tuple = ()) -> list[str]:
    """Flatten `npm run a && cargo ...` chains from package.json, so the suite
    list stays defined in exactly one place."""
    if name in seen:
        raise SystemExit(f"package.json script cycle at {name}")
    commands: list[str] = []
    for part in (p.strip() for p in scripts[name].split("&&")):
        if part.startswith("npm run "):
            commands += expand_script(scripts, part[len("npm run "):].strip(), seen + (name,))
        else:
            commands.append(part)
    return commands


def zome_rustflags(scripts: dict) -> str:
    m = re.search(r"RUSTFLAGS='([^']*)'", scripts["build:zomes"])
    if not m:
        raise SystemExit("cannot find RUSTFLAGS in package.json build:zomes")
    return m.group(1)


def rewrite_paths(manifest: Path, out: Path, replacements: dict[str, str]) -> None:
    text = manifest.read_text()
    for old, new in replacements.items():
        if old not in text:
            raise SystemExit(f"{manifest}: expected path {old!r} not found")
        text = text.replace(old, new)
    out.write_text(text)


def build_artifacts(r: Runner, scripts: dict, wasm_dir: Path, stage: Path) -> dict:
    """Fresh WASM build, then pack the .dna/.happ from staged manifests."""
    out: dict = {}
    s = Step("wasm-build")
    r.steps.append(s)
    t0 = time.time()
    if wasm_dir.exists():
        shutil.rmtree(wasm_dir)
    env = dict(r.env, CARGO_TARGET_DIR=str(wasm_dir), RUSTFLAGS=zome_rustflags(scripts))
    proc = r.run(s, cargo(["build", "--release", "--target", "wasm32-unknown-unknown",
                           "-p", "mpc_integrity", "-p", "mpc"]), env=env)
    wasm = wasm_dir / "wasm32-unknown-unknown/release"
    out["integrity_wasm"], out["coordinator_wasm"] = wasm / "mpc_integrity.wasm", wasm / "mpc.wasm"
    s.seconds = time.time() - t0
    if proc.returncode or not all(p.is_file() for p in (out["integrity_wasm"], out["coordinator_wasm"])):
        s.status, s.detail = "FAIL", "cargo build failed (see log)"
        return out
    s.status, s.detail = "PASS", "fresh target dir, offline, locked"

    s = Step("wasm-imports")
    r.steps.append(s)
    t0 = time.time()
    proc = r.run(s, [sys.executable, "-I", "scripts/check_wasm_imports.py",
                     str(out["coordinator_wasm"]), str(out["integrity_wasm"])])
    s.seconds = time.time() - t0
    s.status = "FAIL" if proc.returncode else "PASS"
    s.detail = (r.log_text(s).strip().splitlines() or [""])[-1][:90]

    s = Step("pack")
    r.steps.append(s)
    t0 = time.time()
    if stage.exists():
        shutil.rmtree(stage)
    (stage / "dna").mkdir(parents=True)
    (stage / "app").mkdir()
    rewrite_paths(ROOT / "dnas/mpc/workdir/dna.yaml", stage / "dna/dna.yaml", {
        "../../../target/wasm32-unknown-unknown/release/mpc_integrity.wasm": str(out["integrity_wasm"]),
        "../../../target/wasm32-unknown-unknown/release/mpc.wasm": str(out["coordinator_wasm"])})
    rewrite_paths(ROOT / "workdir/happ.yaml", stage / "app/happ.yaml", {
        "../dnas/mpc/workdir/mpc.dna": "../dna/mpc.dna"})
    ok = r.run(s, ["hc", "dna", "pack", str(stage / "dna")]).returncode == 0
    ok = ok and r.run(s, ["hc", "app", "pack", str(stage / "app")]).returncode == 0
    out["dna"], out["happ"] = stage / "dna/mpc.dna", stage / "app/holochain-mpc-core.happ"
    s.seconds = time.time() - t0
    if not ok or not out["dna"].is_file() or not out["happ"].is_file():
        s.status, s.detail = "FAIL", "hc pack failed (see log)"
        return out
    proc = subprocess.run(["hc", "dna", "hash", str(out["dna"])], capture_output=True, text=True)
    out["dna_hash"] = proc.stdout.strip().splitlines()[-1] if proc.returncode == 0 and proc.stdout.strip() else ""
    s.status, s.detail = ("PASS", f"dna hash {out['dna_hash']}") if out["dna_hash"] else ("FAIL", "hc dna hash failed")
    return out


def measured(built: dict) -> dict:
    return {
        "integrity_wasm_sha256": sha256(built["integrity_wasm"]),
        "coordinator_wasm_sha256": sha256(built["coordinator_wasm"]),
        "dna_sha256": sha256(built["dna"]),
        "happ_sha256": sha256(built["happ"]),
        "dna_hash": built["dna_hash"],
    }


def compare_identity(r: Runner, built: dict) -> None:
    s = Step("identity")
    r.steps.append(s)
    t0 = time.time()
    if not all(k in built for k in ("dna", "happ", "dna_hash")) or not built.get("dna_hash"):
        s.status, s.detail = "FAIL", "no complete build to compare"
        return
    try:
        recorded = json.loads(HASHES.read_text())
    except (OSError, ValueError) as e:
        s.status, s.detail = "FAIL", f"cannot read {HASHES.name}: {e}"
        return
    if recorded.get("schema") != SCHEMA:
        s.status, s.detail = "FAIL", f"{HASHES.name} schema is not {SCHEMA}"
        return
    now = measured(built)
    problems = []
    # The integrity WASM and DNA hash are frozen by limitation L2. Anything else
    # differing is a coordinator change (or a toolchain change) to be reviewed.
    for key, label in (("integrity_wasm_sha256", "FROZEN integrity WASM (L2)"),
                       ("dna_hash", "FROZEN DNA hash (L2)"),
                       ("coordinator_wasm_sha256", "coordinator WASM"),
                       ("dna_sha256", ".dna bundle"),
                       ("happ_sha256", ".happ bundle")):
        if now[key] != recorded.get(key):
            problems.append(label)
    rustc = tool_version("rustc", "-V")
    note = "" if rustc == recorded.get("rustc") else f"; rustc is {rustc!r}, recorded {recorded.get('rustc')!r}"
    s.seconds = time.time() - t0
    if problems:
        s.status = "FAIL"
        s.detail = "differs from recorded: " + ", ".join(problems) + note
        for key in now:
            print(f"  identity {key}: built {now[key]}  recorded {recorded.get(key)}", file=sys.stderr)
    else:
        s.status, s.detail = "PASS", "WASM, .dna, .happ and DNA hash match the recorded values" + note


def record(built: dict) -> None:
    now = measured(built)
    old = json.loads(HASHES.read_text()) if HASHES.exists() else {}
    doc = {
        "schema": SCHEMA,
        "note": ("Hashes of a from-scratch offline build (scripts/release_check.py --record). "
                 "integrity_wasm_sha256 and dna_hash are frozen by limitation L2; the other "
                 "values change with any coordinator change and must be re-recorded after review."),
        "rustc": tool_version("rustc", "-V"),
        "cargo": tool_version("cargo", "-V"),
        "hc": tool_version("hc", "--version"),
        **now,
    }
    HASHES.write_text(json.dumps(doc, indent=2) + "\n")
    for key in now:
        change = "" if old.get(key) == now[key] else f"  (was {old.get(key)})"
        print(f"recorded {key}: {now[key]}{change}")


def canonical_notice(source: str) -> str:
    """The text of `NOTICE` in notice.rs, with Rust's `\\n\\` line continuations applied."""
    m = re.search(r'(?:pub )?const NOTICE: &str = "(.*?)";', source, re.S)
    if not m:
        raise ValueError("no NOTICE constant in notice.rs")
    return re.sub(r"\\\n\s*", "", m.group(1)).replace("\\n", "\n")


def shipped_binaries(metadata: dict) -> dict[str, str]:
    """{binary: package} for every `bin` target of every workspace package
    (explicit [[bin]] tables and auto-discovered src/main.rs, src/bin/*.rs)."""
    members = set(metadata["workspace_members"])
    return {t["name"]: p["name"] for p in metadata["packages"] if p["id"] in members
            for t in p["targets"] if "bin" in t["kind"]}


def binary_problems(found: dict[str, str], approved: dict) -> list[str]:
    problems = []
    for name, info in sorted(approved.items()):
        if name not in found:
            problems.append(f"approved binary {name} ({info['package']}) is not built by the workspace")
        elif found[name] != info["package"]:
            problems.append(f"{name}: built by {found[name]}, approved {info['package']}")
    for name in sorted(set(found) - set(approved)):
        problems.append(f"unexpected binary {name} ({found[name]}): not in {INVENTORY.name}")
    return problems


def help_problems(name: str, flag: str, rc: int, stdout: str, notice: str, custody: bool) -> list[str]:
    problems = []
    if rc != 0:
        problems.append(f"{name} {flag}: exit {rc}")
    if notice not in stdout:
        problems.append(f"{name} {flag}: canonical non-production notice missing")
    if custody and CUSTODY_WARNING not in stdout:
        problems.append(f"{name} {flag}: custody warning missing")
    return problems


def check_help_notices(r: Runner) -> None:
    """Every shipped binary is in the approved inventory, and its --help and -h
    exit 0 and print the canonical notice of notice.rs; binaries that hold
    custody or move funds also print CUSTODY_WARNING."""
    s = Step("help-notices")
    r.steps.append(s)
    t0 = time.time()
    try:
        approved = json.loads(INVENTORY.read_text())["binaries"]
        notice = canonical_notice(NOTICE_SOURCE.read_text())
    except (OSError, ValueError, KeyError) as e:
        s.status, s.detail = "FAIL", f"cannot read the binary inventory or notice: {e}"
        return
    meta = subprocess.run(cargo(["metadata", "--no-deps", "--format-version", "1"]), cwd=ROOT, env=r.env,
                          capture_output=True, text=True)
    bad = ["cargo metadata failed"] if meta.returncode else binary_problems(shipped_binaries(json.loads(meta.stdout)), approved)
    packages: dict[str, list[str]] = {}
    for info in approved.values():
        packages.setdefault(info["package"], info.get("features", []))
    for package, features in packages.items():
        flags = ["--features", ",".join(features)] if features else []
        if r.run(s, cargo(["build", "-p", package, *flags, "--bins"])).returncode:
            bad.append(f"build of {package} failed")
    for name, info in sorted(approved.items()) if not bad else []:
        for flag in ("--help", "-h"):
            try:
                out = subprocess.run([str(ROOT / "target/debug" / name), flag], stdin=subprocess.DEVNULL,
                                     capture_output=True, text=True, timeout=30, cwd=ROOT)
            except (OSError, subprocess.SubprocessError):
                bad.append(f"{name} {flag}: did not run")
                continue
            bad += help_problems(name, flag, out.returncode, out.stdout, notice, info.get("custody_warning", False))
    s.seconds = time.time() - t0
    s.status = "FAIL" if bad else "PASS"
    custody = sum(1 for i in approved.values() if i.get("custody_warning"))
    s.detail = ("; ".join(bad) if bad else
                f"{len(approved)} approved binaries, none extra; all print the notice for --help and -h and exit 0; "
                f"{custody} also print the custody warning")


def run_validator_tests(r: Runner) -> None:
    s = Step("validator-tests")
    r.steps.append(s)
    t0 = time.time()
    proc = r.run(s, [sys.executable, "-I", "-m", "unittest", "discover", "-s", "scripts/tests", "-t", "scripts"])
    s.seconds = time.time() - t0
    s.status = "FAIL" if proc.returncode else "PASS"
    m = re.search(r"Ran (\d+) tests?", r.log_text(s))
    s.detail = f"{m.group(1) if m else '?'} release-validator tests" + ("" if s.status == "PASS" else " (see log)")


def run_native(r: Runner, scripts: dict) -> None:
    s = Step("native")
    r.steps.append(s)
    t0 = time.time()
    commands = expand_script(scripts, "test:native")
    passed = failed = ignored = groups = 0
    bad: list[str] = []
    # Tests bind Unix sockets under their temp dir; a long $TMPDIR exceeds
    # SUN_LEN (about 107 bytes). Use /tmp for the native suites in that case.
    env = dict(r.env)
    if len(env.get("TMPDIR", "/tmp")) > 40:
        print(f"  native: TMPDIR is too long for Unix sockets, using /tmp", file=sys.stderr)
        env["TMPDIR"] = "/tmp"
    for command in commands:
        tokens = shlex.split(command)
        if tokens[:2] != ["cargo", "test"]:
            bad.append(f"unexpected command {command!r}")
            continue
        log_before = len(r.log_text(s))
        print(f"  native: {command[:110]}", file=sys.stderr)
        proc = r.run(s, cargo(tokens[1:]), env=env)
        text = r.log_text(s)[log_before:]
        for outcome, p, f, i in RESULT.findall(text):
            groups += 1
            passed, failed, ignored = passed + int(p), failed + int(f), ignored + int(i)
        if proc.returncode:
            bad.append(command[:90])
    s.seconds = time.time() - t0
    s.status = "FAIL" if bad or failed or groups == 0 else "PASS"
    s.detail = f"{len(commands)} commands, {groups} result groups: {passed} passed, {failed} failed, {ignored} ignored"
    if bad:
        s.detail += "; failed: " + "; ".join(bad)


def print_table(steps: list[Step]) -> None:
    rows = [("step", "result", "seconds", "detail")] + [
        (s.name, s.status, f"{s.seconds:.0f}", s.detail) for s in steps]
    widths = [max(len(row[i]) for row in rows) for i in range(3)]
    for n, row in enumerate(rows):
        print(f"{row[0]:<{widths[0]}}  {row[1]:<{widths[1]}}  {row[2]:>{widths[2]}}  {row[3]}")
        if n == 0:
            print("-" * (sum(widths) + 6 + 20))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--skip-native", action="store_true", help="skip test:native (result becomes incomplete)")
    ap.add_argument("--wasm-target-dir", type=Path, default=ROOT / "target/release-check",
                    help="fresh cargo target dir for the WASM build (deleted first)")
    ap.add_argument("--record", action="store_true", help="rewrite scripts/release_hashes.json from a fresh build")
    ap.add_argument("--confirm-record", action="store_true", help="required with --record")
    args = ap.parse_args()
    if args.record and not args.confirm_record:
        print("refusing: --record needs --confirm-record", file=sys.stderr)
        return 1

    scripts = json.loads((ROOT / "package.json").read_text())["scripts"]
    wasm_dir = args.wasm_target_dir.resolve()
    log_dir = ROOT / "target/release-check-logs"
    shutil.rmtree(log_dir, ignore_errors=True)
    log_dir.mkdir(parents=True)
    r = Runner(log_dir)
    lock_before = sha256(ROOT / "Cargo.lock")

    run_validator_tests(r)
    for name, cmd in (("manifest", [sys.executable, "-I", "scripts/check_release.py"]),
                      ("versions", [sys.executable, "-I", "scripts/check_holochain_versions.py"])):
        s = Step(name)
        r.steps.append(s)
        t0 = time.time()
        proc = r.run(s, cmd)
        s.seconds = time.time() - t0
        s.status = "FAIL" if proc.returncode else "PASS"
        lines = r.log_text(s).strip().splitlines()
        s.detail = (lines[-1] if lines else "")[:90]

    built = build_artifacts(r, scripts, wasm_dir, wasm_dir.parent / "release-check-stage")

    if args.record:
        if all(s.status == "PASS" for s in r.steps):
            record(built)
        else:
            print("not recording: an earlier step failed", file=sys.stderr)
    else:
        compare_identity(r, built)

    if not args.record:
        check_help_notices(r)

    if args.skip_native or args.record:
        r.steps.append(Step("native"))
    else:
        run_native(r, scripts)

    s = Step("lockfile")
    s.status = "PASS" if sha256(ROOT / "Cargo.lock") == lock_before else "FAIL"
    s.detail = "Cargo.lock unchanged by the run" if s.status == "PASS" else "Cargo.lock was modified"
    r.steps.append(s)

    print()
    print_table(r.steps)
    print(f"\nlogs: {log_dir}")
    failed = [s.name for s in r.steps if s.status == "FAIL"]
    skipped = [s.name for s in r.steps if s.status == "SKIP"]
    if failed:
        print("RESULT: FAIL (" + ", ".join(failed) + ")")
        return 1
    if skipped:
        print("RESULT: INCOMPLETE, skipped " + ", ".join(skipped))
        return 2
    print("RESULT: PASS (development evidence only, not a security audit or build attestation)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
