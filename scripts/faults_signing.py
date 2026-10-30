#!/usr/bin/env python3
"""Signing helpers for scripts/phase6_faults.py: activation, plans, approvals, per-plan
signing-profile signers behind a SignerProxy, `mpc-sign` services and OpenSSL
verification. Mirrors phase8() in scripts/phase6_rehearsal.py, split into steps so a
scenario can inject a fault between them."""
from __future__ import annotations
import base64, os, re, shutil, subprocess, time
from pathlib import Path

import faults_env as fe
from faults_env import Env, SignerProxy, guarded, hfail, log


class Plan:
    def __init__(self, tag: str, signers: list[int], path: Path, message: bytes, operation: str):
        self.tag, self.signers, self.path, self.message, self.operation = tag, signers, path, message, operation

    @property
    def op8(self) -> str:
        return self.operation[:8].upper()


class SigningService:
    def __init__(self, i: int, plan: Plan, out: Path, proxy: SignerProxy):
        self.i, self.plan, self.out, self.proxy = i, plan, out, proxy


def activate_group(env: Env):
    for i, n in enumerate(env.nodes):
        env.step(i, f"activate-{i + 1}", [env.prov, "activate-group", *env.app(i), "--record", n.ops / "ceremony.json",
                 "--state-dir", n.state_dir, "--confirm-activation-write"])


def make_plan(env: Env, tag: str, signers: list[int]) -> Plan:
    message = f"fault-injection {tag}: approve test transfer (no value)\n".encode()
    mfile = env.run.ops / f"message-{tag}.txt"
    mfile.write_bytes(message)
    sel = env.run.ops / f"selected-{tag}.txt"
    sel.write_text("\n".join(env.agents[i] for i in signers) + "\n")
    path = env.run.ops / f"plan-{tag}.json"
    out = env.step(signers[0], f"make-intent-{tag}", [env.prov, "make-intent", "--state-dir", env.nodes[signers[0]].state_dir,
                   "--message-file", mfile, "--selected-file", sel, "--out", path])
    operation = re.findall(r"operation_id=([0-9a-f]{64})", out)[0]
    return Plan(tag, signers, path, message, operation)


def wait_activated(env: Env, plan: Plan, i: int):
    n = env.nodes[i]
    for attempt in range(40):
        p = env.proc(i, f"signing-status-{i + 1}-{plan.tag}-{attempt}", [env.prov, "signing-status", *env.app(i),
                     "--record", n.ops / "ceremony.json", "--plan", plan.path])
        if guarded(p.wait, 60) == 0 and "activated=true" in p.text():
            return
        time.sleep(5)
    hfail(f"{n.name} never saw the full group activation")


def approve(env: Env, plan: Plan, i: int):
    n = env.nodes[i]
    own = n.ops / f"message-{plan.tag}.txt"
    shutil.copyfile(env.run.ops / f"message-{plan.tag}.txt", own)
    env.step(i, f"approve-{i + 1}-{plan.tag}", [env.prov, "approve-intent", *env.app(i), "--record", n.ops / "ceremony.json",
             "--plan", plan.path, "--message-file", own, "--confirm-approval-write"])


def start_signer(env: Env, plan: Plan, i: int) -> SignerProxy:
    """Plan-pinned signing-profile Lair signer plus a proxy in front of it."""
    n = env.nodes[i]
    node_plan = n.ops / f"plan-{plan.tag}.json"
    shutil.copyfile(plan.path, node_plan)
    os.chmod(node_plan, 0o600)
    real = n.ops / f"ss-{plan.tag}"
    real.mkdir(mode=0o700)
    env.step(i, f"signing-policy-{i + 1}-{plan.tag}", [env.prov, "write-signing-policy", "--record", n.ops / "ceremony.json",
             "--plan", node_plan, "--state-dir", n.state_dir, "--caps-dir", n.ops / "caps",
             "--out", n.ops / f"signing-policy-{plan.tag}.json"])
    signer = env.start(i, f"signing-signer-{i + 1}-{plan.tag}", [env.run.bin / "mpc-lair-signer", "--signing-profile",
                       "--policy-file", n.ops / f"signing-policy-{plan.tag}.json",
                       "--signer-socket", real / "sign.sock", "--lair-root", env.run.state / n.name / "ks"])
    guarded(signer.wait_for, r"Lair signer ready", 1, 60)
    proxy = SignerProxy(i, n.ops / f"px-{plan.tag}" / "s.sock", real / "sign.sock")
    n.proxies[f"sign-{plan.tag}"] = proxy
    return proxy


def sign_argv(env: Env, plan: Plan, i: int, out: Path, polls: int | None = None) -> list:
    n = env.nodes[i]
    return [env.run.bin / "mpc-sign", "--state-dir", n.state_dir, "--plan-file", n.ops / f"plan-{plan.tag}.json",
            "--app-socket", f"127.0.0.1:{n.app_port}", "--origin", f"http://localhost:{n.app_port}",
            "--app-token-file", n.ops / "app-token", "--installed-app-id", fe.APP_ID,
            "--dna-hex", (n.ops / "dna-hex").read_text().strip(),
            "--signer-socket", n.ops / f"px-{plan.tag}" / "s.sock",
            "--poll-ms", str(env.poll_ms), "--max-polls", str(polls or env.polls), "--out-dir", out]


def start_sign(env: Env, plan: Plan, i: int, name: str | None = None, polls: int | None = None) -> "fe.rh.Proc":
    n = env.nodes[i]
    out = n.ops / f"signed-{plan.tag}"
    if not out.exists():
        out.mkdir(mode=0o700)
    return env.start(i, name or f"mpc-sign-{i + 1}-{plan.tag}", sign_argv(env, plan, i, out, polls))


def artifacts(env: Env, plan: Plan, i: int) -> dict:
    out = env.nodes[i].ops / f"signed-{plan.tag}"
    return {f.name: f.read_bytes() for f in out.iterdir()} if out.exists() else {}


def openssl_verify(plan: Plan, files: dict, workdir: Path) -> tuple[bool, str]:
    """RFC 8032 check by OpenSSL, as in the rehearsal; also rejects a tampered message."""
    need = {"group-public-key.bin", "signature.bin", "signed-message.bin"}
    if not need <= files.keys():
        return False, f"missing output files: {sorted(need - files.keys())}"
    workdir.mkdir(mode=0o700, exist_ok=True)
    der = bytes.fromhex("302a300506032b6570032100") + files["group-public-key.bin"]
    pem = workdir / "group-public-key.pem"
    pem.write_text("-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(der).decode() + "\n-----END PUBLIC KEY-----\n")
    (workdir / "m.bin").write_bytes(files["signed-message.bin"])
    (workdir / "s.bin").write_bytes(files["signature.bin"])
    ok = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(pem), "-rawin",
                         "-in", str(workdir / "m.bin"), "-sigfile", str(workdir / "s.bin")], capture_output=True, text=True)
    if ok.returncode != 0 or "Signature Verified Successfully" not in ok.stdout:
        return False, "OpenSSL rejected the signature"
    (workdir / "t.bin").write_bytes(files["signed-message.bin"] + b"!")
    bad = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(pem), "-rawin",
                          "-in", str(workdir / "t.bin"), "-sigfile", str(workdir / "s.bin")], capture_output=True, text=True)
    if bad.returncode == 0:
        return False, "OpenSSL accepted a tampered message"
    return True, "verified; tampered message rejected"
