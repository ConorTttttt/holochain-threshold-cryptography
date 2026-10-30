#!/usr/bin/env python3
"""Scenario registry for scripts/phase6_faults.py. See docs/V040_PHASE6_FAULT_TESTS.md.

Each scenario states its expected outcome first (the `expected` text, taken from
docs/agent-briefs/03-fault-injection.md). Checks written with `ctx.check` assert the
expectation. When a run showed the product behaves differently, the check is written
with `ctx.differs(finding, ...)`: it asserts the OBSERVED behaviour, is reported as
DIFFERS and links a finding in the doc, and the scenario fails if that behaviour
changes. Nothing here modifies product code."""
from __future__ import annotations
import json, os, re, signal, subprocess, threading, time
from pathlib import Path

import faults_env as fe
import faults_signing as fs
from faults_env import Env, Trigger, hfail, log, snapshot, dkg_state, dkg_revision

REGISTRY: dict[str, "Scenario"] = {}


class Scenario:
    def __init__(self, sid, number, title, expected, fn, netns=False, polls=60, group=None):
        self.id, self.number, self.title, self.expected = sid, number, title, expected
        self.fn, self.netns, self.polls, self.group = fn, netns, polls, group


def scenario(sid, number, title, expected, netns=False, polls=60, group=None):
    def wrap(fn):
        REGISTRY[sid] = Scenario(sid, number, title, expected, fn, netns, polls, group)
        return fn
    return wrap


class Ctx:
    def __init__(self, env: Env):
        self.env, self.checks, self.notes, self.evidence = env, [], [], {}

    def check(self, name: str, ok: bool, detail: str = ""):
        self.checks.append({"name": name, "result": "ok" if ok else "FAIL", "detail": detail})
        log(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))
        return ok

    def differs(self, finding: str, name: str, observed_ok: bool, detail: str):
        """The brief's expectation does not hold. `observed_ok` says the documented
        deviation still holds; if it does not, the scenario fails."""
        self.checks.append({"name": name, "result": "DIFFERS" if observed_ok else "FAIL", "finding": finding,
                            "detail": detail})
        log(f"  [{'DIFFERS ' + finding if observed_ok else 'FAIL'}] {name} -- {detail}")
        return observed_ok

    def note(self, text: str):
        self.notes.append(text)
        log(f"  note: {text}")


# ------------------------------------------------------------------ helpers --

def snaps(env: Env) -> list[dict]:
    return [snapshot(n.state_dir) for n in env.nodes]


def descriptor_exists(env: Env, i: int) -> bool:
    return (env.nodes[i].state_dir / "group-descriptor.json").exists()


def tail(text: str, n: int = 2) -> str:
    lines = [l.strip() for l in text.strip().splitlines() if l.strip()]
    return " | ".join(lines[-n:])[:300]


def fail_line(text: str) -> str:
    """The decisive 'FAIL:'/'mpc-node:' line of a refused command."""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(("FAIL:", "mpc-node:", "mpc-sign:")):
            return line[:300]
    return tail(text, 1)


def budget_s(env: Env) -> float:
    return env.polls * env.poll_ms / 1000


def record_evidence(ctx: Ctx, env: Env):
    ctx.evidence["journals"] = {n.name: snapshot(n.state_dir) for n in env.nodes}
    ctx.evidence["descriptors"] = {n.name: descriptor_exists(env, n.i) for n in env.nodes}
    ctx.evidence["proxy_traces"] = {n.name: {k: p.trace() for k, p in n.proxies.items()} for n in env.nodes}


def cls(rc) -> str:
    return "still running" if rc is None else f"exit {rc}"


def run_short(env: Env, i: int, name: str, argv: list, timeout: float = 60) -> tuple:
    """Run a command that is expected to end quickly; returns (rc, output). rc is None
    if it was still running at the timeout (it is then killed)."""
    p = env.proc(i, name, argv)
    try:
        rc = p.proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(p.proc.pid, signal.SIGKILL)
        p.proc.wait(10)
        rc = None
    p.thread.join(timeout=5)
    return rc, p.text()


def kill_node_stack(env: Env, i: int):
    """SIGKILL every process of one node: conductor, Lair, worker, signers, relay."""
    env.signal_node(i, signal.SIGKILL)
    for p in env.nodes[i].procs.values():
        try:
            p.proc.wait(10)
        except Exception:
            pass
    log(f"SIGKILL entire stack of {env.nodes[i].name}")


def kill_worker_at(env: Env, victim: int, round_: int, nth: int) -> Trigger:
    """When the victim's relay asks its signer for the nth `send_protocol_message` of
    DKG round `round_`, SIGKILL the victim's mpc-node worker and drop that request.
    nth=1 kills before any round-`round_` message is published; nth=2 after exactly one
    of the two peers has received it."""
    def match(event, history):
        return event.operation == "send_protocol_message" and event.round == round_

    def action(event):
        env.kill(victim, f"mpc-node-{victim + 1}")
        return "drop"
    return env.nodes[victim].proxies["dkg"].add(
        Trigger(f"SIGKILL worker before round-{round_} send #{nth}", match, action, nth))


def no_completion(ctx: Ctx, env: Env, allow: tuple = ()):
    """No sealed share, no group descriptor and no 'completed' journal outside `allow`."""
    for i, n in enumerate(env.nodes):
        if i in allow:
            continue
        s = snapshot(n.state_dir)
        ctx.check(f"{n.name}: no sealed share, no group descriptor, journal not completed",
                  s.get("secrets", 0) == 0 and not descriptor_exists(env, i) and dkg_state(s) != "completed",
                  f"state={dkg_state(s)} secrets={s.get('secrets')} descriptor={descriptor_exists(env, i)}")


def journal_state(ctx: Ctx, env: Env, i: int, expected: str, known: dict[str, str], what: str):
    """Brief expectation for a surviving node's journal; `known` maps a documented
    deviating state to its finding id."""
    got = dkg_state(snapshot(env.nodes[i].state_dir))
    name = f"{env.nodes[i].name}: {what} journals state '{expected}'"
    if got == expected:
        ctx.check(name, True, f"state={got}")
    elif got in known:
        ctx.differs(known[got], name, True, f"observed state '{got}', brief expects '{expected}'")
    else:
        ctx.check(name, False, f"state={got}")


def require_admitted(env: Env, who: str = "every node"):
    """All three workers journaled DKG admission (Init). If a relay lost a start-up race
    its node never joined, and an 'abort' observed afterwards would prove nothing."""
    missing = [n.name for n in env.nodes if dkg_revision(snapshot(n.state_dir)) < 1]
    if missing:
        hfail(f"environment problem, not a product result: {', '.join(missing)} never admitted the DKG "
              f"(relay start-up race?); see the relay logs")


def start_and_wait_dkg(env: Env, timeout: float):
    env.start_relays()
    return env.wait_relays([0, 1, 2], timeout)


def ensure_dkg(ctx: Ctx):
    """Build the environment and complete one DKG (once per Env)."""
    env = ctx.env
    if env.flags.get("dkg"):
        return
    env.bring_up()
    env.provision()
    env.start_dkg()
    codes = start_and_wait_dkg(env, 600)
    if not all(c == 0 for c in codes.values()):
        hfail(f"baseline DKG did not complete: {codes}")
    if not all(dkg_state(s) == "completed" and s["secrets"] == 1 for s in snaps(env)):
        hfail("baseline DKG did not journal completion on every node")
    env.flags["dkg"] = True
    log("baseline DKG complete on all three nodes")


def ensure_active(ctx: Ctx):
    env = ctx.env
    ensure_dkg(ctx)
    if not env.flags.get("active"):
        fs.activate_group(env)
        env.flags["active"] = True


def prepare_op(ctx: Ctx, tag: str, signers=(0, 2)):
    """New plan: wait for activation, approve on each signer, start each plan-pinned
    signing signer behind its proxy. mpc-sign is NOT started."""
    env = ctx.env
    ensure_active(ctx)
    plan = fs.make_plan(env, tag, list(signers))
    for i in signers:
        fs.wait_activated(env, plan, i)
    for i in signers:
        fs.approve(env, plan, i)
    for i in signers:
        fs.start_signer(env, plan, i)
    return plan


def wait_procs(procs, timeout):
    deadline = time.time() + timeout
    while any(p.proc.poll() is None for p in procs) and time.time() < deadline:
        time.sleep(0.5)
    return [p.proc.poll() for p in procs]


# ------------------------------------------------------------------ control --

@scenario("control", "0", "Control: rehearsal flow through the harness (DKG, activation, 1 signature)",
          "DKG completes on all three nodes; nodes 1 and 3 sign; OpenSSL verifies; no fault is injected. "
          "Proves the harness (per-node conductors, signer proxies) reproduces the Phase 6/8 rehearsal.")
def control(ctx: Ctx):
    env = ctx.env
    env.bring_up()
    env.provision()
    env.start_dkg()
    t0 = time.time()
    codes = start_and_wait_dkg(env, 600)
    ctx.check("all three relays exit 0 (DKG complete)", all(c == 0 for c in codes.values()),
              f"{codes} in {time.time() - t0:.0f}s")
    ctx.check("every node journals 'completed' with one sealed share",
              all(dkg_state(s) == "completed" and s["secrets"] == 1 for s in snaps(env)), json.dumps(snaps(env)))
    ctx.check("every node wrote a group descriptor", all(descriptor_exists(env, i) for i in range(3)))
    env.flags["dkg"] = True
    ensure_active(ctx)
    plan = prepare_op(ctx, "ctl")
    procs = [fs.start_sign(env, plan, i) for i in plan.signers]
    codes = wait_procs(procs, 600)
    ctx.check("both signing services exit 0", all(c == 0 for c in codes), str(codes))
    files = fs.artifacts(env, plan, 0)
    ok, why = fs.openssl_verify(plan, files, env.run.root / "verify")
    ctx.check("OpenSSL verifies the group signature", ok, why)
    ctx.check("both signers produced the same signature",
              files.get("signature.bin") is not None and files.get("signature.bin") == fs.artifacts(env, plan, 2).get("signature.bin"))
    ctx.check("the unselected node reserved no nonce", snapshot(env.nodes[1].state_dir)["nonces"] == [])
    record_evidence(ctx, env)


# ------------------------------------------------- DKG: kill a worker (1) ----

def dkg_kill(ctx: Ctx, round_: int, nth: int = 1, victim: int = 1):
    env = ctx.env
    env.bring_up()
    env.provision()
    env.start_dkg()
    trigger = kill_worker_at(env, victim, round_, nth)
    survivors = [i for i in range(3) if i != victim]
    codes = start_and_wait_dkg(env, budget_s(env) + 240)
    require_admitted(env)
    ctx.check("fault fired: victim's worker SIGKILLed at its round-%d send #%d" % (round_, nth), trigger.fired)
    ctx.check("victim's mpc-node worker is dead", not env.alive(victim, f"mpc-node-{victim + 1}"))
    ctx.check("victim's relay failed closed (non-zero exit)", codes[victim] not in (0, None), cls(codes[victim]))
    for s in survivors:
        text = env.relay_text(s)
        ctx.check(f"{env.nodes[s].name}: relay aborted (non-zero exit), no completion",
                  codes[s] not in (0, None) and "PASS: DKG completed" not in text,
                  f"{cls(codes[s])}: {tail(text)}")
        ctx.check(f"{env.nodes[s].name}: abort is the documented clean failure, not a crash",
                  "FAIL: relay service terminated" in text and "panicked" not in text, tail(text, 1))
    for s in survivors:
        journal_state(ctx, env, s, "aborted", {"running": "F1"}, "after its relay aborted, the surviving node")
    no_completion(ctx, env)
    record_evidence(ctx, env)
    return codes


def _register_kill(round_: int):
    ids = {1: "dkg-kill-r1", 2: "dkg-kill-r2", 3: "dkg-kill-r3"}
    desc = {1: "round 1 (announce/echo), before any announcement reaches a peer",
            2: "round 2 (attestation), before any attestation reaches a peer",
            3: "round 3 (encrypted shares), before any share reaches a peer"}
    scenario(ids[round_], "1", f"DKG: SIGKILL one worker in {desc[round_]}",
             "Both surviving nodes abort cleanly; no sealed share anywhere; no group descriptor on any node; "
             "every surviving node's journal records the abort.")(lambda ctx, r=round_: dkg_kill(ctx, r))


for _r in (1, 2, 3):
    _register_kill(_r)


@scenario("dkg-kill-r3-partial", "1+", "DKG: SIGKILL a worker in round 3 after ONE peer received its share (partial broadcast)",
          "(not in the brief; probes L1 'no finality') Scenario 1's 'no node completes' is expected NOT to hold here: the peer "
          "that received the share finishes its DKG while the other aborts. The group must still be unusable because "
          "activation needs every member.")
def dkg_kill_partial(ctx: Ctx):
    env = ctx.env
    victim, survivors = 1, [0, 2]
    codes = dkg_kill_prefix(ctx, 3, 2, victim)
    done = [s for s in survivors if codes[s] == 0]
    ctx.differs("F2", "a member is killed mid-round-3: no node completes (scenario-1 expectation)", len(done) == 1,
                f"exactly one surviving node completed (the one that received the victim's share); relay exits {codes}")
    if len(done) != 1:
        record_evidence(ctx, env)
        return
    d, other = done[0], next(s for s in survivors if s != done[0])
    st = snapshot(env.nodes[d].state_dir)
    ctx.check(f"{env.nodes[d].name}: journal 'completed', one sealed share, descriptor written",
              dkg_state(st) == "completed" and st["secrets"] == 1 and descriptor_exists(env, d), json.dumps(st))
    ctx.check(f"{env.nodes[other].name} and the victim: no sealed share, no descriptor",
              all(snapshot(env.nodes[x].state_dir).get("secrets", 0) == 0 and not descriptor_exists(env, x) for x in (other, victim)))
    # The half-complete group must not become usable: activation needs all three attestations.
    run_short(env, d, "activate-partial", [env.prov, "activate-group", *env.app(d), "--record", env.nodes[d].ops / "ceremony.json",
                                           "--state-dir", env.nodes[d].state_dir, "--confirm-activation-write"], 120)
    plan = fs.make_plan(env, "par", [d, other])
    p = env.proc(d, "signing-status-partial", [env.prov, "signing-status", *env.app(d), "--record",
                 env.nodes[d].ops / "ceremony.json", "--plan", plan.path])
    fe.guarded(p.wait, 60)
    ctx.check("the group stays inactive (activated=false) after the completing node attests", "activated=false" in p.text(), tail(p.text(), 2))
    ctx.note("one node holds a completed share of a group that two other members never finalised; "
             "operators must treat any DKG with an aborted member as dead and start a fresh proposal")
    record_evidence(ctx, env)


def dkg_kill_prefix(ctx, round_, nth, victim):
    """dkg_kill without the brief's no-completion checks; returns relay exit codes."""
    env = ctx.env
    env.bring_up()
    env.provision()
    env.start_dkg()
    trigger = kill_worker_at(env, victim, round_, nth)
    codes = start_and_wait_dkg(env, budget_s(env) + 240)
    require_admitted(env)
    ctx.check("fault fired: victim's worker SIGKILLed after one round-%d send" % round_, trigger.fired)
    ctx.check("victim's relay failed closed (non-zero exit)", codes[victim] not in (0, None), cls(codes[victim]))
    return codes


# ------------------------------------------------- DKG: stall a node (2) -----

@scenario("dkg-stop", "2", "DKG: SIGSTOP a whole node past the deadline, then SIGCONT",
          "The survivors abort at their deadline; the resumed node cannot complete (no late acceptance): no sealed "
          "share, no descriptor, no 'completed' journal anywhere, and the survivors' journals do not change after the resume.")
def dkg_stop(ctx: Ctx):
    env = ctx.env
    env.bring_up()
    env.provision()
    env.start_dkg()
    victim, survivors = 1, [0, 2]
    seen = {}

    def match(event, history):
        return event.operation == "send_protocol_message" and event.round == 2

    def action(event):
        env.signal_node(victim, signal.SIGSTOP)
        seen["stopped_at"] = time.time()
        log(f"SIGSTOP entire {env.nodes[victim].name} (relay, worker, signer, conductor, Lair)")
        codes = env.wait_relays(survivors, budget_s(env) + 240)
        time.sleep(3)
        seen["codes_at_resume"] = codes
        seen["journals_at_resume"] = {i: snapshot(env.nodes[i].state_dir) for i in survivors}
        env.signal_node(victim, signal.SIGCONT)
        seen["resumed_at"] = time.time()
        log(f"SIGCONT {env.nodes[victim].name} after {seen['resumed_at'] - seen['stopped_at']:.0f}s frozen")
        return "forward"
    trigger = env.nodes[victim].proxies["dkg"].add(Trigger("SIGSTOP node at its first round-2 send", match, action))
    env.start_relays()
    final = env.wait_relays([0, 1, 2], budget_s(env) + 300)
    require_admitted(env)
    ctx.check("fault fired: node frozen at its first round-2 send, then resumed", trigger.fired and "resumed_at" in seen)
    at = seen.get("codes_at_resume", {})
    ctx.check("both survivors had aborted (non-zero exit) before the node was resumed",
              all(at.get(s) not in (0, None) for s in survivors), str(at))
    ctx.check("survivors failed with the clean abort message, no completion",
              all("FAIL: relay service terminated" in env.relay_text(s) and "PASS: DKG completed" not in env.relay_text(s)
                  for s in survivors), " / ".join(tail(env.relay_text(s), 1) for s in survivors))
    if final[victim] is None:
        env.kill(victim, f"relay-{victim + 1}")
        ctx.note("the resumed node's relay was still polling at the end of the observation window and was killed")
    ctx.check("resumed node did not complete (no 'PASS: DKG completed')", "PASS: DKG completed" not in env.relay_text(victim),
              f"{cls(final[victim])}: {tail(env.relay_text(victim))}")
    no_completion(ctx, env)
    same = all(snapshot(env.nodes[i].state_dir) == seen.get("journals_at_resume", {}).get(i) for i in survivors)
    ctx.check("no late acceptance: the survivors' journals are identical before and after the resume", same)
    for s in survivors:
        journal_state(ctx, env, s, "aborted", {"running": "F1"}, "after its relay aborted, the surviving node")
    record_evidence(ctx, env)


@scenario("dkg-stop-short", "2+", "DKG: SIGSTOP a whole node for 8 s (inside every deadline), then SIGCONT",
          "(contrast for scenario 2) A stall shorter than the signer (15 s) and polling (20 s) deadlines is tolerated: "
          "all three nodes complete the DKG.")
def dkg_stop_short(ctx: Ctx):
    env = ctx.env
    env.bring_up()
    env.provision()
    env.start_dkg()
    victim = 1

    def action(event):
        env.signal_node(victim, signal.SIGSTOP)
        log(f"SIGSTOP entire {env.nodes[victim].name} for 8s")
        time.sleep(8)
        env.signal_node(victim, signal.SIGCONT)
        return "forward"
    trigger = env.nodes[victim].proxies["dkg"].add(Trigger(
        "freeze node-2 for 8s at its first round-2 send",
        lambda e, h: e.operation == "send_protocol_message" and e.round == 2, action))
    codes = start_and_wait_dkg(env, budget_s(env) + 240)
    ctx.check("fault fired: node frozen for 8 s then resumed", trigger.fired)
    ctx.check("all three relays still complete the DKG", all(c == 0 for c in codes.values()), str(codes))
    ctx.check("every node journals 'completed' with one sealed share",
              all(dkg_state(x) == "completed" and x["secrets"] == 1 for x in snaps(env)))
    record_evidence(ctx, env)


# ------------------------------------------- partition: isolation evidence --

CUSTODY = ("mpc-node-", "signer-", "signing-signer-", "relay-", "mpc-sign-")
NO_CAPS = "0" * 16


def isolation_checks(ctx: Ctx, env: Env, ids: dict):
    """Where each process ran at the moment of the cut (`ids`, from env.identities()),
    and a control showing the custody root refusal is still enforced. Custody must run
    in the host user and network namespaces as a nonzero euid without capabilities;
    each conductor in its own node network namespace, also without capabilities."""
    net = env.net
    ctx.evidence["identities_at_cut"] = ids
    ctx.evidence["namespaces"] = net.ns
    custody = {k: v for k, v in ids.items() if v and k.split("/")[1].startswith(CUSTODY)}
    conductors = {k: v for k, v in ids.items() if v and k.split("/")[1].startswith("conductor-")}
    ctx.check("custody processes run as this user (nonzero euid), without capabilities, in the host user and "
              "network namespaces",
              bool(custody) and all(v["euid"] == os.geteuid() != 0 and v["cap_eff"] == NO_CAPS and
                                    v["user_ns"] == net.host_ns["user"] and v["net_ns"] == net.host_ns["net"]
                                    for v in custody.values()),
              "; ".join(f"{k} euid={v['euid']} caps={v['cap_eff']} {v['user_ns']} {v['net_ns']}"
                        for k, v in sorted(custody.items())))
    ctx.check("each conductor runs in its own node network namespace as this user, without capabilities",
              len(conductors) == len(env.nodes) and
              all(v["euid"] == os.geteuid() and v["cap_eff"] == NO_CAPS and v["user_ns"] == net.ns["hub_user"] and
                  v["net_ns"] == net.ns[k.split("/")[0].replace("-", "") + "_net"] for k, v in conductors.items()),
              "; ".join(f"{k} euid={v['euid']} caps={v['cap_eff']} {v['net_ns']}" for k, v in sorted(conductors.items())))
    probe = env.run.root / "root-control"
    probe.mkdir(mode=0o700)
    ids0 = env.nodes[0].ids
    r = subprocess.run(["unshare", "--map-root-user", str(env.run.bin / "mpc-node"), "provision", str(probe / "node"),
                        ids0["AGENT_HEX"], ids0["PROPOSAL_HEX"], ids0["SESSION_HEX"]], capture_output=True, text=True)
    ctx.check("control: the same mpc-node run as namespace root (unshare --map-root-user) is refused and writes nothing",
              r.returncode != 0 and "custody must not run as root" in r.stderr and not (probe / "node").exists(),
              f"exit {r.returncode}: {r.stderr.strip()[:200]}")


def cut_checks(ctx: Ctx, env: Env, blocked: list, open_: list):
    """While the partition is still in place: every (from, to, port) in `blocked` gets no
    TCP answer at all, every one in `open_` connects or is actively refused (the path
    is up). `from` is a node index or None for the hub."""
    def where(i):
        return "hub" if i is None else env.nodes[i].name
    seen = {f"{where(i)} -> {h}:{p}": env.net.reach(i, h, p) for i, h, p in blocked + open_}
    ctx.evidence["reachability_during_cut"] = seen
    cut = [f"{where(i)} -> {h}:{p}" for i, h, p in blocked]
    up = [f"{where(i)} -> {h}:{p}" for i, h, p in open_]
    ctx.check("partition applied: the cut paths carry no traffic (TCP probes time out or are unreachable)",
              all(seen[k] in ("timeout", "unreachable") for k in cut), "; ".join(f"{k}: {seen[k]}" for k in cut))
    ctx.check("partition is selective: the other paths stay up", all(seen[k] in ("connected", "refused") for k in up),
              "; ".join(f"{k}: {seen[k]}" for k in up))


# ------------------------------------------------- DKG: partition (3) -------

@scenario("dkg-partition", "3", "DKG: partition one node from every peer during round 2 (rootless netns)",
          "Every node aborts (the isolated node's sends fail; the others time out); no sealed share, no descriptor; "
          "healing the partition afterwards does not revive the ceremony.", netns=True)
def dkg_partition(ctx: Ctx):
    env = ctx.env
    env.bring_up()
    env.provision()
    env.start_dkg()
    victim, survivors = 1, [0, 2]
    seen = {}

    def match(event, history):
        return event.operation == "send_protocol_message" and event.round == 2

    def action(event):
        env.net.cut(victim)
        seen["cut_at"] = time.time()
        seen["ids"] = env.identities()
        return "forward"
    trigger = env.nodes[victim].proxies["dkg"].add(Trigger("partition node-2 at its first round-2 send", match, action))
    env.start_relays()
    codes = env.wait_relays([0, 1, 2], budget_s(env) + 240)
    require_admitted(env)
    ctx.check("fault fired: node-2 isolated at its first round-2 send", trigger.fired)
    ctx.check("isolated node's relay failed closed", codes[victim] not in (0, None), f"{cls(codes[victim])}: {tail(env.relay_text(victim))}")
    for s in survivors:
        ctx.check(f"{env.nodes[s].name}: relay aborted at its deadline, no completion",
                  codes[s] not in (0, None) and "PASS: DKG completed" not in env.relay_text(s),
                  f"{cls(codes[s])}: {tail(env.relay_text(s))}")
    if trigger.fired:
        isolation_checks(ctx, env, seen["ids"])
        ctx.check("partition applied: node-2's hub-side veth is down", env.net.link_state(victim) == "DOWN",
                  env.net.link_state(victim))
        hub, port = "10.77.0.1", env.bootstrap_port
        cut_checks(ctx, env, blocked=[(victim, hub, port), (0, env.net.ip_of(victim), 9), (2, env.net.ip_of(victim), 9)],
                   open_=[(0, hub, port), (2, hub, port), (0, env.net.ip_of(2), 9)])
    before = {i: snapshot(env.nodes[i].state_dir) for i in range(3)}
    env.net.heal()
    time.sleep(30)
    after = {i: snapshot(env.nodes[i].state_dir) for i in range(3)}
    ctx.check("after the partition heals, no journal changes (the aborted ceremony is not revived)", before == after)
    no_completion(ctx, env)
    for s in survivors:
        journal_state(ctx, env, s, "aborted", {"running": "F1"}, "after its relay aborted, the surviving node")
    ctx.note("tool: a rootless user namespace mapping only this user (`unshare --map-current-user -n`) with a network "
             "namespace per conductor and veth pairs; the node is cut off with `ip link set down` on its hub-side "
             "veth; the custody stack runs in the host namespaces as this user; no root")
    record_evidence(ctx, env)


# ------------------------------------------------- DKG: kill during seal (4) -

def other_descriptor_plan(ctx: Ctx, tag: str, holder: int, victim: int) -> "fs.Plan":
    """A plan built from a node that did complete; its public descriptor equals the victim's."""
    return fs.make_plan(ctx.env, tag, [holder, victim])


def recovery_probe(env: Env, i: int, plan: "fs.Plan", name: str):
    """Run mpc-sign far enough to reach recover_share, then stop: the signer socket does not
    exist, so a successful recovery ends at the signer check, before any nonce, deadline
    or conductor call. Returns (recovered, rc, output)."""
    n = env.nodes[i]
    node_plan = n.ops / f"plan-{plan.tag}.json"
    if not node_plan.exists():
        import shutil
        shutil.copyfile(plan.path, node_plan)
        os.chmod(node_plan, 0o600)
    out = n.ops / f"probe-{plan.tag}"
    out.mkdir(mode=0o700, exist_ok=True)
    rc, text = run_short(env, i, name, [env.run.bin / "mpc-sign", "--state-dir", n.state_dir, "--plan-file", node_plan,
                         "--app-socket", f"127.0.0.1:{n.app_port}", "--origin", f"http://localhost:{n.app_port}",
                         "--app-token-file", n.ops / "app-token", "--installed-app-id", fe.APP_ID,
                         "--dna-hex", (n.ops / "dna-hex").read_text().strip(),
                         "--signer-socket", env.run.ops / "none" / "x.sock", "--out-dir", out], 60)
    return "cannot reopen this node's share" not in text and rc not in (0,), rc, text


def seal_kill(ctx: Ctx, point: str):
    env = ctx.env
    env.bring_up()
    env.provision()
    env.start_dkg()
    victim, survivors = 1, [0, 2]
    db = env.nodes[victim].state_dir / "journal.sqlite"
    hit = {}

    def on_hit(snap):
        hit["snap"] = snap
        env.kill(victim, f"mpc-node-{victim + 1}")
    if point == "before":  # share sealed, completion not yet journaled
        pred = lambda s: s["secrets"] >= 1 and dkg_state(s) == "running"
    else:  # sealed AND journaled completed
        pred = lambda s: s["secrets"] >= 1 and dkg_state(s) == "completed"
    watcher = threading.Thread(target=lambda: fe.gate(db, pred, on_hit, budget_s(env) + 240), daemon=True)
    watcher.start()
    codes = start_and_wait_dkg(env, budget_s(env) + 240)
    watcher.join(timeout=5)
    snap = hit.get("snap")
    ctx.check("fault fired: worker SIGKILLed " + ("after the share was sealed but BEFORE completion was journaled"
              if point == "before" else "after the share was sealed AND completion journaled"), snap is not None, json.dumps(snap))
    ctx.check("survivors completed the DKG (they already had every share)", all(codes[s] == 0 for s in survivors),
              f"{codes}")
    after = snapshot(env.nodes[victim].state_dir)
    if point == "before":
        ctx.check("victim journal: sealed share present but state still 'running' (never 'completed')",
                  after["secrets"] == 1 and dkg_state(after) == "running", json.dumps(after))
        ctx.check("victim has no group descriptor and its relay failed closed",
                  not descriptor_exists(env, victim) and codes[victim] not in (0, None), cls(codes[victim]))
    else:
        ctx.check("victim journal: sealed share and state 'completed'", after["secrets"] == 1 and dkg_state(after) == "completed",
                  json.dumps(after))
        ctx.note(f"victim relay: {cls(codes[victim])}; descriptor written: {descriptor_exists(env, victim)}")
    # Restart. The worker restart must be refused for BOTH points ...
    rc, text = run_short(env, victim, "restart-node-2", [env.run.bin / "mpc-node", "serve", env.nodes[victim].state_dir], 30)
    ctx.check("restarting the victim's mpc-node worker is refused (existing DKG journal)",
              rc not in (0, None) and "previously started DKG state" in text, f"{cls(rc)}: {fail_line(text)}")
    # ... but recovery of the SHARE is allowed only for the completed journal.
    plan = other_descriptor_plan(ctx, "rec", survivors[0], victim)
    recovered, rc, text = recovery_probe(env, victim, plan, "recover-victim")
    if point == "before":
        ctx.check("recover_completed_share REFUSES the sealed-but-uncompleted share",
                  not recovered and "DKG did not complete; no share is recoverable" in text, f"{cls(rc)}: {fail_line(text)}")
        p = env.proc(victim, "activate-victim", [env.prov, "activate-group", *env.app(victim), "--record",
                     env.nodes[victim].ops / "ceremony.json", "--state-dir", env.nodes[victim].state_dir, "--confirm-activation-write"])
        fe.guarded(p.wait, 120)
        ctx.check("the victim cannot attest the group (no descriptor, no recoverable share)", p.proc.returncode != 0,
                  tail(p.text(), 1))
    else:
        ctx.check("recover_completed_share ACCEPTS the completed share (mpc-sign passes recovery and stops at the signer check)",
                  recovered, f"{cls(rc)}: {fail_line(text)}")
    ctx.check("the probe reserved no nonce and registered no deadline",
              snapshot(env.nodes[victim].state_dir)["nonces"] == [] and snapshot(env.nodes[victim].state_dir)["lifecycles"] == [])
    record_evidence(ctx, env)


scenario("dkg-seal-kill-before", "4", "DKG: SIGKILL the worker after its share is sealed, BEFORE completion is journaled",
         "Restart is refused, and the sealed share is NOT recoverable (recover_completed_share requires a completed journal); "
         "the node never gets a descriptor and cannot attest the group.")(lambda ctx: seal_kill(ctx, "before"))
scenario("dkg-seal-kill-after", "4", "DKG: SIGKILL the worker after the share is sealed AND completion is journaled",
         "Restart of the worker is refused, but the share IS recoverable from the completed journal "
         "(recover_completed_share accepts the peer-supplied descriptor).")(lambda ctx: seal_kill(ctx, "after"))


# ------------------------------------------------- DKG: no re-run (5) --------

@scenario("dkg-restart-refused", "5", "DKG: restart every node's worker and relay after an aborted DKG",
          "Every restart is refused (existing journal); nothing is signed or published under the old context; "
          "journals do not change; the provisioned directory cannot be re-provisioned.")
def dkg_restart_refused(ctx: Ctx):
    env = ctx.env
    env.bring_up()
    env.provision()
    env.start_dkg()
    victim = 1
    trigger = kill_worker_at(env, victim, 2, 1)
    codes = start_and_wait_dkg(env, budget_s(env) + 240)
    require_admitted(env)
    ctx.check("setup: DKG aborted on all three nodes after SIGKILL of a worker in round 2",
              trigger.fired and all(c not in (0, None) for c in codes.values()), str(codes))
    before = snaps(env)
    events_before = {n.name: len(n.proxies["dkg"].history) for n in env.nodes}
    ctx.note("journal states before restart: " + json.dumps({n.name: [dkg_state(b), dkg_revision(b)] for n, b in zip(env.nodes, before)}))
    for i, n in enumerate(env.nodes):
        rc, text = run_short(env, i, f"restart-worker-{i + 1}", [env.run.bin / "mpc-node", "serve", n.state_dir], 30)
        ctx.check(f"{n.name}: restarting mpc-node serve is refused", rc not in (0, None) and "previously started DKG state" in text,
                  f"{cls(rc)}: {fail_line(text)}")
        pinned = json.loads((n.state_dir / "node.json").read_text())["context"]
        hx = lambda v: bytes(v).hex()
        rc, text = run_short(env, i, f"reprovision-{i + 1}", [env.run.bin / "mpc-node", "provision", n.state_dir,
                             hx(pinned["worker_agent"]), hx(pinned["proposal_action"]), hx(pinned["session_id"])], 30)
        ctx.check(f"{n.name}: re-provisioning the same directory with its real identity is refused (directory exists)",
                  rc not in (0, None) and "File exists" in text, f"{cls(rc)}: {fail_line(text)}")
        rc, text = run_short(env, i, f"restart-relay-{i + 1}", [env.run.bin / "mpc-relay-service", "--state-dir", n.state_dir,
                             "--binding-file", n.ops / "binding.json", "--app-socket", f"127.0.0.1:{n.app_port}",
                             "--origin", f"http://localhost:{n.app_port}", "--app-token-file", n.ops / "app-token",
                             "--installed-app-id", fe.APP_ID, "--dna-hex", (n.ops / "dna-hex").read_text().strip(),
                             "--signer-socket", n.ops / "px-dkg" / "s.sock", "--poll-ms", "500", "--max-polls", "20"], 60)
        ctx.check(f"{n.name}: restarting the relay finds no worker and fails closed", rc not in (0, None) and "PASS" not in text,
                  f"{cls(rc)}: {tail(text, 1)}")
    after = snaps(env)
    ctx.check("no journal changed (state and revision identical) after all restart attempts", before == after)
    ctx.check("no signing request reached any node's signer during the restart attempts",
              {n.name: len(n.proxies['dkg'].history) for n in env.nodes} == events_before)
    no_completion(ctx, env)
    record_evidence(ctx, env)


# ------------------------------------------------- signing (6, 7, 8) ---------

def op_rows(env: Env, i: int, plan: "fs.Plan") -> dict:
    s = snapshot(env.nodes[i].state_dir)
    return {"nonces": [x["state"] for x in s["nonces"] if x["operation"] == plan.op8],
            "lifecycle": [(x["state"], x["reason"]) for x in s["lifecycles"] if x["operation"] == plan.op8]}


def sign_kill(ctx: Ctx, point: str):
    env = ctx.env
    tag = {"reserved": "s6a", "commit": "s6b", "share": "s6c", "aggregate": "s6d"}[point]
    plan = prepare_op(ctx, tag)
    victim, survivor = 0, 2
    vname = f"mpc-sign-{victim + 1}-{tag}"
    proxy = env.nodes[victim].proxies[f"sign-{tag}"]
    fired = {}

    def kill_and_drop(event):
        env.kill(victim, vname)
        fired["at"] = event.label()
        return "drop"
    if point == "commit":   # the victim's round-4 commitment was published; kill at its next request
        proxy.add(Trigger("SIGKILL mpc-sign after its commitment publish",
                          lambda e, h: any(x.operation == "send_protocol_message" and x.round == 4 for x in h), kill_and_drop))
    elif point == "share":  # the victim's round-6 share was published; kill at its next request
        proxy.add(Trigger("SIGKILL mpc-sign after its share publish",
                          lambda e, h: any(x.operation == "send_protocol_message" and x.round == 6 for x in h), kill_and_drop))
    elif point == "aggregate":  # it aggregated and verified in memory; kill as it asks to publish the result
        proxy.add(Trigger("SIGKILL mpc-sign after aggregation, before result publish",
                          lambda e, h: e.operation == "publish_result_commitment", kill_and_drop))
    gate_thread = None
    if point == "reserved":  # nonce slot reserved, commitment not yet authorised/published
        db = env.nodes[victim].state_dir / "journal.sqlite"

        def on_hit(snap):
            fired["at"] = "nonce reserved"
            env.kill(victim, vname)
        pred = lambda s: any(x["operation"] == plan.op8 and x["state"] == "reserved" for x in s["nonces"])
        gate_thread = threading.Thread(target=lambda: fe.gate(db, pred, on_hit, budget_s(env) + 120), daemon=True)
        gate_thread.start()
    procs = {i: fs.start_sign(env, plan, i) for i in plan.signers}
    codes = wait_procs(list(procs.values()), budget_s(env) + 240)
    if gate_thread:
        gate_thread.join(timeout=5)
    ctx.check(f"fault fired: selected signer node-1 SIGKILLed ({point})", "at" in fired, str(fired))
    vrows, srows = op_rows(env, victim, plan), op_rows(env, survivor, plan)
    want_nonce = {"reserved": "reserved"}.get(point, "published")
    ctx.check(f"victim's journal: exactly one nonce slot for the operation, state '{want_nonce}' (never reset)",
              vrows["nonces"] == [want_nonce], str(vrows))
    # Restart: the same operation must be refused before any nonce is touched.
    restart = fs.start_sign(env, plan, victim, name=f"mpc-sign-1-{tag}-restart", polls=20)
    rc = wait_procs([restart], 120)[0]
    text = restart.text()
    ctx.check("restarted signer is refused: 'deadline already registered'",
              rc not in (0, None) and "deadline already registered" in text, f"{cls(rc)}: {tail(text, 2)}")
    ctx.check("restart reserved no second nonce and left the first untouched", op_rows(env, victim, plan)["nonces"] == [want_nonce],
              str(op_rows(env, victim, plan)))
    ctx.check("restart produced no output files", fs.artifacts(env, plan, victim) == {})
    survivor_files = fs.artifacts(env, plan, survivor)
    if point in ("reserved", "commit"):
        ctx.check("surviving signer produced NO signature without the second share",
                  codes[1] not in (0, None) and "signature.bin" not in survivor_files, f"{cls(codes[1])}: {tail(procs[survivor].text(), 1)}")
        ctx.check("surviving signer journaled the abort and burned its nonce",
                  srows["lifecycle"] and srows["lifecycle"][0][0] == "aborted" and srows["nonces"] == ["burned"], str(srows))
    else:
        ctx.check("the victim's share had already reached the survivor, so the survivor completes",
                  codes[1] == 0 and "signature.bin" in survivor_files, f"{cls(codes[1])}: {tail(procs[survivor].text(), 1)}")
        ok, why = fs.openssl_verify(plan, survivor_files, env.run.root / f"verify-{tag}")
        ctx.check("the survivor's signature verifies under OpenSSL (RFC 8032)", ok, why)
    ctx.check("victim wrote no output files", fs.artifacts(env, plan, victim) == {})
    record_evidence(ctx, env)


for _p, _num, _t, _exp in (
    ("reserved", "6", "Signing: SIGKILL a selected signer after nonce reservation (before the commitment is released)",
     "Restart refused ('deadline already registered'); the nonce slot stays used; the surviving signer cannot sign without "
     "the second commitment and aborts with its nonce burned."),
    ("commit", "6", "Signing: SIGKILL a selected signer after its commitment was published",
     "Restart refused; nonce stays used; the survivor never produces a signature without the victim's share and aborts."),
    ("share", "6", "Signing: SIGKILL a selected signer after its signature share was published",
     "Restart refused; nonce stays used; the survivor already holds both shares so it may complete, and its signature verifies."),
    ("aggregate", "6", "Signing: SIGKILL a selected signer after it aggregated, before publishing the result",
     "Restart refused; nonce stays used; the victim leaves no output; the survivor completes with a verifying signature."),
):
    scenario(f"sign-kill-{_p}", _num, _t, _exp, group="signing")(lambda ctx, p=_p: sign_kill(ctx, p))


@scenario("sign-recover-new-op", "6+", "Signing: after the kills, the same two nodes sign a NEW operation",
          "(contrast for scenario 6) Only the killed operation is dead: a new plan and operation id signs normally with the "
          "restarted node, and the old operation's nonce slot stays used.", group="signing")
def sign_recover_new_op(ctx: Ctx):
    env = ctx.env
    plan = prepare_op(ctx, "s6e")
    before = snapshot(env.nodes[0].state_dir)["nonces"]
    procs = [fs.start_sign(env, plan, i) for i in plan.signers]
    codes = wait_procs(procs, budget_s(env) + 240)
    ctx.check("both signers complete the new operation", all(c == 0 for c in codes), str(codes))
    ok, why = fs.openssl_verify(plan, fs.artifacts(env, plan, 0), env.run.root / "verify-s6e")
    ctx.check("the new signature verifies under OpenSSL", ok, why)
    after = snapshot(env.nodes[0].state_dir)["nonces"]
    ctx.check("node-1 now has one more nonce row; every earlier row is unchanged",
              len(after) == len(before) + 1 and all(r in after for r in before), f"{len(before)} -> {len(after)} rows")
    if any(r["state"] == "reserved" for r in before):
        ctx.check("the nonce slot reserved by the killed signer is still 'reserved' (never reused or revived)",
                  any(r["state"] == "reserved" for r in after))
    record_evidence(ctx, env)


@scenario("sign-unselected-mid", "7", "Signing: SIGKILL the unselected node's entire stack mid-signing",
          "No effect on the two selected signers (they complete, signature verifies); the unselected node reserved no nonce.",
          group="signing")
def sign_unselected_mid(ctx: Ctx):
    env = ctx.env
    plan = prepare_op(ctx, "s7b")
    proxy = env.nodes[0].proxies["sign-s7b"]
    trigger = proxy.add(Trigger("kill node-2's whole stack after node-1's commitment publish",
                                lambda e, h: any(x.operation == "send_protocol_message" and x.round == 4 for x in h),
                                lambda e: (kill_node_stack(env, 1), "forward")[1]))
    procs = [fs.start_sign(env, plan, i) for i in plan.signers]
    codes = wait_procs(procs, budget_s(env) + 240)
    ctx.check("fault fired: unselected node-2 killed mid-signing", trigger.fired)
    ctx.check("both selected signers complete (exit 0)", all(c == 0 for c in codes), str(codes))
    ok, why = fs.openssl_verify(plan, fs.artifacts(env, plan, 0), env.run.root / "verify-s7b")
    ctx.check("signature verifies under OpenSSL", ok, why)
    s = snapshot(env.nodes[1].state_dir)
    ctx.check("the unselected node reserved no nonce and registered no deadline", s["nonces"] == [] and s["lifecycles"] == [], json.dumps(s))
    record_evidence(ctx, env)


@scenario("sign-unselected-early", "7", "Signing: SIGKILL the unselected node's entire stack before signing starts",
          "No effect on the two selected signers (they complete, signature verifies); the unselected node reserved no nonce.")
def sign_unselected_early(ctx: Ctx):
    env = ctx.env
    plan = prepare_op(ctx, "s7a")
    kill_node_stack(env, 1)
    procs = [fs.start_sign(env, plan, i) for i in plan.signers]
    codes = wait_procs(procs, budget_s(env) + 240)
    ctx.check("both selected signers complete (exit 0) with the unselected node dead", all(c == 0 for c in codes), str(codes))
    ok, why = fs.openssl_verify(plan, fs.artifacts(env, plan, 0), env.run.root / "verify-s7a")
    ctx.check("signature verifies under OpenSSL", ok, why)
    s = snapshot(env.nodes[1].state_dir)
    ctx.check("the unselected node reserved no nonce and registered no deadline", s["nonces"] == [] and s["lifecycles"] == [], json.dumps(s))
    record_evidence(ctx, env)


@scenario("sign-partition", "8", "Signing: partition the two selected signers from each other, node-2 still reachable (rootless netns)",
          "Both signers time out or fail their sends and abort; no signature; nonces burned; the repeated operation is refused.",
          netns=True)
def sign_partition(ctx: Ctx):
    env = ctx.env
    plan = prepare_op(ctx, "s8")
    proxy = env.nodes[0].proxies["sign-s8"]

    seen = {}

    def cut(event):
        env.net.cut(0, 2, relay_port=env.bootstrap_port)  # node-1 <-> node-3 only; node-2 stays reachable from both
        seen["ids"] = env.identities()
        return "forward"
    trigger = proxy.add(Trigger("partition node-1 from node-3 at node-1's round-4 send",
                                lambda e, h: e.operation == "send_protocol_message" and e.round == 4, cut))
    procs = {i: fs.start_sign(env, plan, i) for i in plan.signers}
    codes = wait_procs(list(procs.values()), budget_s(env) + 240)
    ctx.check("fault fired: node-1 <-> node-3 partitioned at node-1's round-4 send", trigger.fired)
    ctx.check("neither signer produced a signature (both exit non-zero)", all(c not in (0, None) for c in codes), str(codes))
    ctx.check("no signature files on either signer", all(fs.artifacts(env, plan, i) == {} for i in plan.signers))
    for i in plan.signers:
        r = op_rows(env, i, plan)
        ctx.check(f"{env.nodes[i].name}: abort journaled, nonce burned",
                  r["lifecycle"] and r["lifecycle"][0][0] == "aborted" and r["nonces"] == ["burned"], f"{r}; {tail(procs[i].text(), 1)}")
    if trigger.fired:
        isolation_checks(ctx, env, seen["ids"])
        drops = env.net.drop_counters()  # read before the probes add their own packets
        ctx.evidence["nft_drop_rules"] = drops
        packets = sum(int(m) for d in drops for m in re.findall(r"packets (\d+)", d))
        ctx.check("partition applied: the hub's drop rules dropped real conductor traffic (nft counters)",
                  len(drops) == 6 and packets > 0, f"{packets} packets; " + "; ".join(drops))
        hub, port, ip = "10.77.0.1", env.bootstrap_port, env.net.ip_of
        cut_checks(ctx, env, blocked=[(0, ip(2), 9), (2, ip(0), 9), (0, hub, port), (2, hub, port)],
                   open_=[(1, hub, port), (0, ip(1), 9), (1, ip(2), 9)])
    env.net.heal()
    again = fs.start_sign(env, plan, 0, name="mpc-sign-1-s8-again", polls=20)
    rc = wait_procs([again], 120)[0]
    ctx.check("after healing, a repeat of the same operation is refused ('deadline already registered')",
              rc not in (0, None) and "deadline already registered" in again.text(), f"{cls(rc)}: {tail(again.text(), 1)}")
    ctx.note("tool: a rootless user namespace mapping only this user (`unshare --map-current-user -n`) with a network "
             "namespace per conductor and veth pairs; the pair is cut with nft drop rules in the hub (direct traffic, "
             "and both nodes' traffic to the relay port); the custody stack runs in the host namespaces as this "
             "user; no root")
    record_evidence(ctx, env)
