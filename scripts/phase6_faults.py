#!/usr/bin/env python3
"""Phase 6/8 FAULT INJECTION on the DISPOSABLE three-conductor rehearsal.

Kills, stalls and partitions nodes during DKG and during 2-of-3 signing, and records
what the product does. See docs/V040_PHASE6_FAULT_TESTS.md for the scenarios, the
expected outcome of each (stated before the run) and the observed results.

DISPOSABLE ONLY: every scenario builds a fresh run directory under
~/mpc-phase6-rehearsal/faults-<id>-<UTC>-<pid>/ with a fresh network seed and a random
throwaway Lair passphrase (typed through a pseudo-terminal, as in
scripts/phase6_rehearsal.py). The persistent ~/mpc-phase5b-sandbox and
~/mpc-phase5c-sandbox are refused. No product code is changed; the binaries in
target/debug are used as built.

Usage (from Holonix or with the Nix-store 0.7.1 tools present):
  python3 -I scripts/phase6_faults.py --list
  python3 -I scripts/phase6_faults.py --scenario dkg-kill-r2 [--scenario ...] [--keep]
  python3 -I scripts/phase6_faults.py --suite [--keep] [--jobs N]
  python3 -I scripts/phase6_faults.py --self-check

Partition scenarios need unprivileged user + network namespaces (`unshare
--map-current-user -n`, nsenter, ip, nft). Only the conductors run in them; the custody
stack stays in the host namespaces as this user, so its refusal to run as root still
applies. They do not need root and never touch the host network; if the kernel refuses
them the scenario is SKIPPED with the reason.
"""
from __future__ import annotations
import argparse, datetime, json, os, subprocess, sys, time, traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))  # helpers live next to this script (python -I drops it)

import faults_env as fe          # noqa: E402
import faults_scenarios as sc    # noqa: E402


def list_scenarios() -> None:
    print(f"{'id':<26} {'#':<4} {'net':<4} title")
    for s in sc.REGISTRY.values():
        print(f"{s.id:<26} {s.number:<4} {'ns' if s.netns else '-':<4} {s.title}")
        print(f"{'':<35}expected: {s.expected}")


def run_ids(ids: list[str], keep: bool, out_dir: Path | None) -> int:
    """Run scenarios one after another in ONE environment (a group shares one DKG);
    a single id is a group of one."""
    scs = [sc.REGISTRY[i] for i in ids]
    label = scs[0].group if len(ids) > 1 and scs[0].group else scs[0].id
    env = fe.Env(label, netns=any(s.netns for s in scs), polls=max(s.polls for s in scs))
    results, broken = [], None
    try:
        for s in scs:
            started = time.time()
            ctx = sc.Ctx(env)
            status, error = "PASS", None
            fe.log(f"=== scenario {s.id} (#{s.number}): {s.title}")
            fe.log(f"    expected: {s.expected}")
            if broken:
                status, error = "HARNESS-ERROR", f"not run: the shared environment failed earlier ({broken})"
            else:
                try:
                    s.fn(ctx)
                    failed = [c for c in ctx.checks if c["result"] == "FAIL"]
                    differs = [c for c in ctx.checks if c["result"] == "DIFFERS"]
                    status = "FAIL" if failed else ("FINDING" if differs else "PASS")
                except fe.SkipScenario as e:
                    status, error, broken = "SKIP", str(e), str(e)
                    fe.log(f"SKIP {s.id}: {e}")
                except fe.HarnessError as e:
                    status, error, broken = "HARNESS-ERROR", str(e), str(e)
                    fe.log(f"HARNESS-ERROR {s.id}: {e}")
                except BaseException as e:  # keep the evidence, then report
                    status, error = "HARNESS-ERROR", "".join(traceback.format_exception_only(type(e), e)).strip()
                    broken = error
                    fe.log("HARNESS-ERROR " + traceback.format_exc())
                try:
                    if "journals" not in ctx.evidence:
                        sc.record_evidence(ctx, env)
                except BaseException:
                    pass
            results.append({"id": s.id, "number": s.number, "title": s.title, "expected": s.expected,
                            "status": status, "error": error, "checks": ctx.checks, "notes": ctx.notes,
                            "evidence": ctx.evidence, "run_dir": str(env.run.root),
                            "seconds": round(time.time() - started),
                            "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat()})
            (env.run.root / f"RESULT-{s.id}.json").write_text(json.dumps(results[-1], indent=2) + "\n")
            if out_dir:
                (out_dir / f"{s.id}.json").write_text(json.dumps(results[-1], indent=2) + "\n")
            fe.log(f"{status}: {s.id} ({results[-1]['seconds']}s)")
    finally:
        env.stop()
    if all(r["status"] in ("PASS", "FINDING", "SKIP") for r in results) and not keep:
        env.compact()
    fe.log(f"run directory {env.run.root}")
    return 0 if all(r["status"] in ("PASS", "FINDING", "SKIP") for r in results) else 1


def jobs_for(ids: list[str]) -> list[list[str]]:
    """Scenarios of one group share an environment; the others run alone."""
    jobs, groups = [], {}
    for sid in ids:
        g = sc.REGISTRY[sid].group
        if g is None:
            jobs.append([sid])
        elif g not in groups:
            groups[g] = [sid]
            jobs.append(groups[g])
        else:
            groups[g].append(sid)
    return jobs


def spawn(job: list[str], keep: bool, out: Path) -> subprocess.Popen:
    # Every child runs in the host namespaces; a partition scenario builds its private
    # network itself (faults_env.Net) and places only the conductors in it.
    child = [sys.executable, "-I", str(Path(__file__).resolve()), "--child", "--result-dir", str(out)]
    for sid in job:
        child += ["--scenario", sid]
    if keep:
        child.append("--keep")
    log = open(out / f"{job[0]}.log", "w")
    return subprocess.Popen(child, stdout=log, stderr=subprocess.STDOUT, env=dict(os.environ))


def suite(ids: list[str], keep: bool, jobs: int) -> int:
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = fe.BASE / f"faults-suite-{stamp}"
    out.mkdir(mode=0o700, parents=True)
    plan = jobs_for(ids)
    fe.log(f"{len(ids)} scenarios in {len(plan)} environments, {jobs} at a time; results in {out}")
    pending, running, results = list(plan), {}, {}
    while pending or running:
        while pending and len(running) < jobs:
            job = pending.pop(0)
            running[tuple(job)] = spawn(job, keep, out)
            fe.log(f"started environment for {', '.join(job)}")
        for job, p in list(running.items()):
            if p.poll() is not None:
                del running[job]
                for sid in job:
                    path = out / f"{sid}.json"
                    results[sid] = json.loads(path.read_text()) if path.exists() else {
                        "id": sid, "status": "HARNESS-ERROR", "error": f"child exited {p.returncode} without a result",
                        "checks": [], "notes": []}
                    fe.log(f"finished {sid}: {results[sid]['status']}")
        time.sleep(2)
    (out / "SUMMARY.json").write_text(json.dumps({"scenarios": results}, indent=2) + "\n")
    print("\n" + "\n".join(f"{results[sid]['status']:<14} {sid}" for sid in ids))
    bad = [sid for sid in ids if results[sid]["status"] not in ("PASS", "FINDING", "SKIP")]
    print(f"\n{len(ids) - len(bad)}/{len(ids)} scenarios completed as documented; summary {out / 'SUMMARY.json'}")
    return 1 if bad else 0


def self_check() -> int:
    ok = True
    try:
        fe.rh.tool_path()
        print("pinned 0.7.1 tools: found")
    except BaseException:
        ok = False
    for exe in ("openssl",):
        import shutil
        found = shutil.which(exe) is not None
        print(f"{exe}: {'found' if found else 'MISSING'}")
        ok &= found
    for b in ("mpc-node", "mpc-relay-service", "mpc-lair-signer", "mpc-sign", "mpc-phase5c-provision", "mpc-phase5b-bootstrap"):
        found = (fe.REPO / "target/debug" / b).is_file()
        print(f"target/debug/{b}: {'found' if found else 'MISSING'}")
        ok &= found
    print(f"workdir/holochain-mpc-core.happ: {'found' if (fe.REPO / 'workdir/holochain-mpc-core.happ').is_file() else 'MISSING'}")
    netns_ok, why = fe.Net.available()
    print(f"network namespaces for partition scenarios: {'available' if netns_ok else 'UNAVAILABLE'} ({why})")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--scenario", action="append", default=[])
    ap.add_argument("--suite", action="store_true", help="every scenario except 'control'")
    ap.add_argument("--with-control", action="store_true", help="include the control scenario in --suite")
    ap.add_argument("--jobs", type=int, default=1, help="scenarios to run at once in --suite")
    ap.add_argument("--keep", action="store_true", help="keep conductor databases after a pass")
    ap.add_argument("--self-check", action="store_true")
    ap.add_argument("--child", action="store_true", help="internal: run the given scenarios in this process")
    ap.add_argument("--result-dir", type=Path, help="internal")
    a = ap.parse_args()
    if a.list:
        list_scenarios()
        return 0
    if a.self_check:
        return self_check()
    for sid in a.scenario:
        if sid not in sc.REGISTRY:
            ap.error(f"unknown scenario {sid!r}; try --list")
    if a.suite:
        ids = [s for s in sc.REGISTRY if s != "control" or a.with_control]
        return suite(ids, a.keep, a.jobs)
    if a.child:
        return run_ids(a.scenario, a.keep, a.result_dir)
    if a.scenario:
        # one process per environment, so a partition scenario gets its own namespaces
        return suite(a.scenario, a.keep, a.jobs)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
