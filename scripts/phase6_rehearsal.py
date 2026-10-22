#!/usr/bin/env python3
"""Phase 6 REHEARSAL: autonomous 2-of-3 FROST DKG across three independently
launched Holochain 0.7.1 conductors, each with its own Lair keystore, Lair
signer, private mpc-node and relay service.

DISPOSABLE ONLY. Everything lives in a fresh ~/mpc-phase6-rehearsal/run-<UTC>
directory with a fresh network seed, so its DNA hash and DHT space differ from
every persistent sandbox. It refuses to run if a path would touch
~/mpc-phase5b-sandbox or ~/mpc-phase5c-sandbox. A random THROWAWAY Lair
passphrase is generated, stored 0600 in the run directory and typed into each
prompt through a pseudo-terminal. Never point this at real keys.

The sequence mirrors docs/V040_PHASE5C_B_PROVISIONING.md with three agents,
then starts every node's services together and waits for each relay to report
`PASS: DKG completed`. Each mpc-node seals its completed share (Phase 7).
Writes are never retried: any failure stops the run and leaves state for
inspection.

After the DKG it rehearses Phase 8 unless --dkg-only is given: every node
attests the group, nodes 1 and 3 approve one plan and sign it with two
independent `mpc-sign` services, and OpenSSL verifies the signature.

Usage (from Holonix or with the Nix-store 0.7.1 tools present):
  python3 -I scripts/phase6_rehearsal.py [--keep-running] [--dkg-only]
"""
from __future__ import annotations
import datetime, fcntl, glob, json, os, re, secrets, select, shutil, signal, socket
import subprocess, sys, termios, threading, time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
HOME = Path.home()
FORBIDDEN = [HOME / "mpc-phase5b-sandbox", HOME / "mpc-phase5c-sandbox", HOME / ".local/state/mpc-phase5c"]
APP_ID = "mpc-phase6"
NODES = ["node-1", "node-2", "node-3"]
TOOLS = {"holochain": "holochain-0.7.1", "hc": "hc-0.7.1", "lair-keystore": "lair-keystore-0.7.1",
         "kitsune2-bootstrap-srv": "kitsune2-bootstrap-srv-0.5.1"}
PROMPT = re.compile(rb"passphrase[^\n]*[:>]\s*$", re.IGNORECASE)


def log(msg: str) -> None:
    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def fail(msg: str) -> None:
    log(f"FAIL: {msg}")
    raise SystemExit(1)


def tool_path() -> str:
    """Prefer the pinned Nix-store 0.7.1 tools over whatever is on PATH."""
    dirs = []
    for exe, store in TOOLS.items():
        found = sorted(glob.glob(f"/nix/store/*-{store}/bin/{exe}"))
        if found:
            dirs.append(str(Path(found[-1]).parent))
        elif not shutil.which(exe):
            fail(f"{exe} ({store}) not found; run inside the Holonix shell")
    return os.pathsep.join(dirs + [os.environ.get("PATH", "")])


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Proc:
    """A child on its own pseudo-terminal (its controlling tty), so Lair
    passphrase prompts that read /dev/tty can be answered. Output is logged
    with the passphrase redacted."""

    def __init__(self, name: str, argv: list[str], run: "Run", cwd: Path | None = None,
                 env: dict | None = None):
        self.name, self.run = name, run
        self.logfile = run.logs / f"{name}.log"
        master, slave = os.openpty()
        attrs = termios.tcgetattr(slave)
        attrs[3] &= ~termios.ECHO  # never echo what we type
        termios.tcsetattr(slave, termios.TCSANOW, attrs)

        def ctty():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        self.proc = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave, cwd=cwd,
                                     env=env or run.env, preexec_fn=ctty, close_fds=True)
        os.close(slave)
        self.master, self.buffer, self.lock = master, b"", threading.Lock()
        self.thread = threading.Thread(target=self._pump, daemon=True)
        self.thread.start()
        log(f"started {name}: {' '.join(Path(argv[0]).name if i == 0 else a for i, a in enumerate(argv))}")

    def _pump(self):
        pending = b""
        with open(self.logfile, "ab") as out:
            while True:
                try:
                    ready, _, _ = select.select([self.master], [], [], 0.2)
                    if not ready:
                        if self.proc.poll() is not None:
                            break
                        continue
                    chunk = os.read(self.master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                pending += chunk
                out.write(chunk.replace(self.run.passphrase.encode(), b"<redacted>"))
                out.flush()
                with self.lock:
                    self.buffer += chunk
                if PROMPT.search(pending):
                    os.write(self.master, self.run.passphrase.encode() + b"\n")
                    pending = b""
                elif b"\n" in pending:
                    pending = pending.rsplit(b"\n", 1)[1]

    def text(self) -> str:
        with self.lock:
            return self.buffer.decode(errors="replace").replace(self.run.passphrase, "<redacted>")

    def wait(self, timeout: float) -> int:
        try:
            code = self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.stop()
            fail(f"{self.name} timed out after {timeout:.0f}s; see {self.logfile}")
        self.thread.join(timeout=5)
        return code

    def wait_for(self, pattern: str, count: int = 1, timeout: float = 180) -> list[str]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            found = re.findall(pattern, self.text())
            if len(found) >= count:
                return found
            if self.proc.poll() is not None:
                break
            time.sleep(0.5)
        fail(f"{self.name}: expected {count}x /{pattern}/; see {self.logfile}")

    def stop(self):
        if self.proc.poll() is None:
            os.killpg(self.proc.pid, signal.SIGTERM)
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(self.proc.pid, signal.SIGKILL)


class Run:
    def __init__(self):
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.root = HOME / "mpc-phase6-rehearsal" / f"run-{stamp}"
        for path in FORBIDDEN:
            if path == self.root or path in self.root.parents:
                fail(f"refusing to touch {path}")
        os.umask(0o077)  # every file the tools create stays private to this user
        self.root.mkdir(mode=0o700, parents=True)
        self.state, self.ops, self.logs = (self.root / d for d in ("state", "ops", "logs"))
        for d in (self.state, self.ops, self.logs):
            d.mkdir(mode=0o700)
        self.passphrase = secrets.token_urlsafe(24)
        (self.root / "THROWAWAY-passphrase").write_text(self.passphrase + "\n")
        os.chmod(self.root / "THROWAWAY-passphrase", 0o600)
        self.env = dict(os.environ, PATH=tool_path())
        self.background: list[Proc] = []
        self.seed = f"mpc-phase6-rehearsal-{stamp}"
        self.bin = REPO / "target" / "debug"

    def step(self, name: str, argv: list[str], timeout: float = 120, cwd: Path | None = None) -> str:
        p = Proc(name, [str(a) for a in argv], self, cwd)
        code = p.wait(timeout)
        if code != 0:
            fail(f"{name} exited {code}; see {p.logfile}")
        return p.text()

    def start(self, name: str, argv: list[str], cwd: Path | None = None, env: dict | None = None) -> Proc:
        p = Proc(name, [str(a) for a in argv], self, cwd, env)
        self.background.append(p)
        return p

    def stop_all(self):
        for p in reversed(self.background):
            p.stop()


def accept_until_committed(run: "Run", i: int, accept: list, status: list, agent: str) -> None:
    """One acceptance write. The ONLY repeat allowed is after the conductor
    reports DepMissingFromDht with "could not be completed", a definitive
    non-commit while the proposal is not yet a usable validation dependency.
    Before each repeat, status must still show this agent as pending."""
    for attempt in range(12):
        p = Proc(f"accept-{i+1}-{attempt}", [str(a) for a in accept], run)
        if p.wait(120) == 0:
            return
        out = p.text()
        if "DepMissingFromDht" not in out or "could not be completed" not in out:
            fail(f"accept on {NODES[i]} failed; inspect the chain before any action; see {p.logfile}")
        time.sleep(10)
        s = Proc(f"accept-{i+1}-{attempt}-recheck", [str(a) for a in status], run)
        if s.wait(60) != 0 or not re.search(rf"pending\s+{re.escape(agent)}", s.text()):
            fail(f"cannot confirm {NODES[i]} acceptance is uncommitted; stopping; see {s.logfile}")
    fail(f"{NODES[i]} still lacks the proposal as a validation dependency")


def phase8(run: "Run", prov: Path, app, ops: list, agents: list, app_ports: list) -> dict:
    """Activate the group, approve one plan on nodes 1 and 3, sign it with two
    independent signing services, then verify with OpenSSL (RFC 8032)."""
    for i in range(len(NODES)):
        run.step(f"activate-{i+1}", [prov, "activate-group", *app(i), "--record", ops[i] / "ceremony.json",
                 "--state-dir", ops[i] / "node", "--confirm-activation-write"])
    signers = [0, 2]  # any two of three
    message = run.ops / "message.txt"
    message.write_text("Phase 8 rehearsal: approve test transfer #1 (no value)\n")
    selected = run.ops / "selected.txt"
    selected.write_text("\n".join(agents[i] for i in signers) + "\n")
    plan = run.ops / "plan.json"
    out = run.step("make-intent", [prov, "make-intent", "--state-dir", ops[0] / "node", "--message-file", message,
                   "--selected-file", selected, "--out", plan])
    operation = re.findall(r"operation_id=([0-9a-f]{64})", out)[0]
    for i in signers:
        for attempt in range(30):  # read-only: wait until every member's attestation is visible here
            p = Proc(f"signing-status-{i+1}-{attempt}", [str(a) for a in [prov, "signing-status", *app(i),
                     "--record", ops[i] / "ceremony.json", "--plan", plan]], run)
            if p.wait(60) == 0 and "activated=true" in p.text():
                break
            time.sleep(5)
        else:
            fail(f"{NODES[i]} never saw the full group activation")
        # Each operator approves against their own copy of the message.
        own = ops[i] / "message.txt"
        shutil.copyfile(message, own)
        tampered = ops[i] / "tampered-plan.json"
        tampered.write_text(plan.read_text().replace('"message":[', '"message":[33,', 1))
        bad = Proc(f"approve-tampered-{i+1}", [str(a) for a in [prov, "approve-intent", *app(i), "--record",
                   ops[i] / "ceremony.json", "--plan", tampered, "--message-file", own,
                   "--confirm-approval-write"]], run)
        if bad.wait(60) == 0 or "differs from your --message-file" not in bad.text():
            fail("approve-intent did not refuse a plan whose message was altered")
        run.step(f"approve-{i+1}", [prov, "approve-intent", *app(i), "--record", ops[i] / "ceremony.json",
                 "--plan", plan, "--message-file", own, "--confirm-approval-write"])
    services = []
    for i in signers:
        node_plan = ops[i] / "plan.json"
        shutil.copyfile(plan, node_plan)
        os.chmod(node_plan, 0o600)
        (ops[i] / "signer-sign").mkdir(mode=0o700)
        (ops[i] / "signed").mkdir(mode=0o700)
        run.step(f"signing-policy-{i+1}", [prov, "write-signing-policy", "--record", ops[i] / "ceremony.json",
                 "--plan", node_plan, "--state-dir", ops[i] / "node", "--caps-dir", ops[i] / "caps",
                 "--out", ops[i] / "signing-policy.json"])
        signer = run.start(f"signing-signer-{i+1}", [run.bin / "mpc-lair-signer", "--signing-profile",
                           "--policy-file", ops[i] / "signing-policy.json",
                           "--signer-socket", ops[i] / "signer-sign" / "sign.sock",
                           "--lair-root", run.state / NODES[i] / "ks"])
        signer.wait_for(r"Lair signer ready", timeout=60)
    for i in signers:
        services.append(run.start(f"mpc-sign-{i+1}", [run.bin / "mpc-sign", "--state-dir", ops[i] / "node",
            "--plan-file", ops[i] / "plan.json", "--app-socket", f"127.0.0.1:{app_ports[i]}",
            "--origin", f"http://localhost:{app_ports[i]}", "--app-token-file", ops[i] / "app-token",
            "--installed-app-id", APP_ID, "--dna-hex", (ops[i] / "dna-hex").read_text().strip(),
            "--signer-socket", ops[i] / "signer-sign" / "sign.sock", "--poll-ms", "1000", "--max-polls", "300",
            "--out-dir", ops[i] / "signed"]))
    deadline = time.time() + 600
    while any(s.proc.poll() is None for s in services):
        failed = [s for s in services if s.proc.poll() not in (None, 0)]
        if failed:
            fail(f"{failed[0].name} aborted signing (exit {failed[0].proc.poll()}); see {failed[0].logfile}")
        if time.time() > deadline:
            fail("signing did not finish within 10 minutes")
        time.sleep(1)
    signatures = {(ops[i] / "signed" / "signature.bin").read_bytes() for i in signers}
    if len(signatures) != 1:
        fail("the two independent aggregators produced different signatures")
    signed = ops[signers[0]] / "signed"
    der = bytes.fromhex("302a300506032b6570032100") + (signed / "group-public-key.bin").read_bytes()
    pem = signed / "group-public-key.pem"
    import base64
    pem.write_text("-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(der).decode() + "\n-----END PUBLIC KEY-----\n")
    check = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(pem), "-rawin",
                            "-in", str(signed / "signed-message.bin"), "-sigfile", str(signed / "signature.bin")],
                           capture_output=True, text=True)
    if check.returncode != 0 or "Signature Verified Successfully" not in check.stdout:
        fail(f"OpenSSL rejected the group signature: {check.stdout} {check.stderr}")
    tampered = signed / "tampered-message.bin"
    tampered.write_bytes((signed / "signed-message.bin").read_bytes() + b"!")
    negative = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(pem), "-rawin",
                               "-in", str(tampered), "-sigfile", str(signed / "signature.bin")],
                              capture_output=True, text=True)
    if negative.returncode == 0:
        fail("OpenSSL accepted the signature over a tampered message")
    # Live negative checks: no second signature for the same operation, and no
    # signing policy for a member the plan did not select.
    first = signers[0]
    (ops[first] / "signed-again").mkdir(mode=0o700)
    again = Proc(f"mpc-sign-{first+1}-again", [str(a) for a in [run.bin / "mpc-sign", "--state-dir", ops[first] / "node",
        "--plan-file", ops[first] / "plan.json", "--app-socket", f"127.0.0.1:{app_ports[first]}",
        "--origin", f"http://localhost:{app_ports[first]}", "--app-token-file", ops[first] / "app-token",
        "--installed-app-id", APP_ID, "--dna-hex", (ops[first] / "dna-hex").read_text().strip(),
        "--signer-socket", ops[first] / "signer-sign" / "sign.sock", "--poll-ms", "500", "--max-polls", "20",
        "--out-dir", ops[first] / "signed-again"]], run)
    if again.wait(120) == 0 or any((ops[first] / "signed-again").iterdir()):
        fail("a second signing run for the same operation was not refused")
    outsider = next(i for i in range(len(NODES)) if i not in signers)
    shutil.copyfile(plan, ops[outsider] / "plan.json")
    refused = Proc(f"signing-policy-{outsider+1}-refused", [str(a) for a in [prov, "write-signing-policy",
        "--record", ops[outsider] / "ceremony.json", "--plan", ops[outsider] / "plan.json",
        "--state-dir", ops[outsider] / "node", "--caps-dir", ops[outsider] / "caps",
        "--out", ops[outsider] / "signing-policy.json"]], run)
    if refused.wait(60) == 0:
        fail("a non-selected member obtained a signing policy")
    log("PASS: a repeated signing run and a non-selected member were both refused")
    sig_hex = next(iter(signatures)).hex()
    log(f"PASS: nodes {signers[0]+1} and {signers[1]+1} produced one approved 2-of-3 Ed25519 signature; "
        f"OpenSSL verifies it (RFC 8032) and rejects a tampered message")
    return {"operation_id": operation, "signers": [agents[i] for i in signers], "signature": sig_hex,
            "group_public_key": (signed / "group-public-key.bin").read_bytes().hex(), "openssl": "verified"}


def build():
    log("building worker binaries (lair-signer features)")
    r = subprocess.run(["cargo", "build", "--locked", "-p", "holochain-mpc-dkg-worker",
                        "--features", "lair-signer", "--bins"], cwd=REPO)
    if r.returncode != 0:
        fail("cargo build failed")
    if not (REPO / "workdir/holochain-mpc-core.happ").is_file():
        fail("workdir/holochain-mpc-core.happ missing; run npm run build:happ")


def main(keep_running: bool, skip_signing: bool) -> None:
    build()
    run = Run()
    log(f"run directory {run.root} (THROWAWAY passphrase in THROWAWAY-passphrase)")
    prov, boot = run.bin / "mpc-phase5c-provision", run.bin / "mpc-phase5b-bootstrap"
    try:
        bootstrap = free_port()
        app_ports = [free_port() for _ in NODES]
        admin = [free_port() for _ in NODES]
        run.start("bootstrap-srv", ["kitsune2-bootstrap-srv", "--listen", f"127.0.0.1:{bootstrap}"])
        time.sleep(2)
        url = f"http://127.0.0.1:{bootstrap}"
        conductors = run.start("conductors", [
            "hc", "sandbox", f"--force-admin-ports={','.join(map(str, admin))}", "generate",
            "--app-id", APP_ID, "--root", run.state,
            f"-d={','.join(NODES)}", "-n", str(len(NODES)), "--network-seed", run.seed,
            f"--run={','.join(map(str, app_ports))}", REPO / "workdir/holochain-mpc-core.happ",
            "network", "--bootstrap", url, "quic", url], cwd=run.root,
            # MPC_CONDUCTOR_LOG (e.g. "info") raises conductor tracing for diagnosis only.
            env=dict(run.env, RUST_LOG=os.environ["MPC_CONDUCTOR_LOG"]) if "MPC_CONDUCTOR_LOG" in os.environ else None)
        conductors.wait_for(r"Conductor ready", count=len(NODES), timeout=300)
        for node in NODES:  # provisioning refuses group/other access to a Lair root
            os.chmod(run.state / node / "ks", 0o700)
            os.chmod(run.state / node / "ks" / "lair-keystore-config.yaml", 0o600)
        log(f"admin ports {admin}, app ports {app_ports}")

        agents, dna = [], None
        for i, port in enumerate(admin):
            for attempt in range(30):  # read-only: retry until the app is installed and enabled
                p = Proc(f"list-apps-{i+1}-{attempt}", ["hc", "client", "call", "--port", str(port), "list-apps"], run)
                apps = p.text() if p.wait(60) == 0 else ""
                agent = re.findall(r"uhCAk[A-Za-z0-9_-]{48}", apps)
                dnas = set(re.findall(r"uhC0k[A-Za-z0-9_-]{48}", apps))
                if agent and len(dnas) == 1:
                    break
                time.sleep(3)
            else:
                fail(f"cannot read agent/DNA for {NODES[i]}")
            agents.append(agent[0])
            if dna not in (None, *dnas):
                fail("conductors run different DNA hashes")
            dna = next(iter(dnas))
        if len(set(agents)) != len(NODES):
            fail("agents are not distinct")
        log(f"DNA {dna} (fresh network seed); agents {agents}")

        ops = []
        for i, node in enumerate(NODES):
            d = run.ops / node
            for sub in ("", "offers", "caps", "signer"):
                (d / sub).mkdir(mode=0o700, exist_ok=True)
            ops.append(d)
            run.step(f"token-{i+1}", [boot, "issue-app-token", "--admin-port", admin[i], "--installed-app-id",
                     APP_ID, "--out", d / "app-token", "--expiry-seconds", "7200", "--confirm-admin-token-issue"])
        (run.ops / "participants.txt").write_text("\n".join(agents) + "\n")
        os.chmod(run.ops / "participants.txt", 0o600)

        def app(i: int) -> list:
            return ["--app-port", app_ports[i], "--origin", f"http://localhost:{app_ports[i]}",
                    "--app-token-file", ops[i] / "app-token", "--agent-b64", agents[i],
                    "--lair-root", run.state / NODES[i] / "ks"]

        run.step("propose", [prov, "propose", *app(0), "--installed-app-id", APP_ID, "--dna-b64", dna,
                 "--participants-file", run.ops / "participants.txt", "--threshold", "2",
                 "--record-out", ops[0] / "ceremony.json", "--confirm-source-chain-write"])
        for d in ops[1:]:
            shutil.copyfile(ops[0] / "ceremony.json", d / "ceremony.json")
            os.chmod(d / "ceremony.json", 0o600)

        # Read-only status may be repeated; writes are never retried.
        for i in range(1, len(NODES)):
            for attempt in range(30):
                p = Proc(f"status-{i+1}-{attempt}", [str(a) for a in [prov, "status", *app(i), "--record", ops[i] / "ceremony.json"]], run)
                if p.wait(60) == 0 and "matches the pinned ceremony exactly" in p.text():
                    break
                time.sleep(5)
            else:
                fail(f"{NODES[i]} never saw the proposal (discovery/gossip)")
        for i in range(len(NODES)):
            accept_until_committed(run, i, [prov, "accept", *app(i), "--record", ops[i] / "ceremony.json",
                                   "--confirm-acceptance-write"],
                                   [prov, "status", *app(i), "--record", ops[i] / "ceremony.json"], agents[i])
        for i in range(len(NODES)):
            for attempt in range(30):
                p = Proc(f"ready-{i+1}-{attempt}", [str(a) for a in [prov, "status", *app(i), "--record", ops[i] / "ceremony.json"]], run)
                if p.wait(60) == 0 and "ready_observed=true" in p.text():
                    break
                time.sleep(5)
            else:
                fail(f"{NODES[i]} never observed all acceptances")
        for i in range(len(NODES)):
            run.step(f"grant-{i+1}", [prov, "prepare-grant", *app(i), "--record", ops[i] / "ceremony.json",
                     "--admin-port", admin[i], "--offers-dir", ops[i] / "offers", "--confirm-grant-write"])
        for i in range(len(NODES)):
            for j in range(len(NODES)):
                if i == j:
                    continue
                for offer in sorted((ops[j] / "offers").glob("offer-*.json")):
                    p = Proc(f"import-{i+1}-from-{j+1}-{offer.stem[-8:]}", [str(a) for a in [
                        prov, "import-offer", "--record", ops[i] / "ceremony.json", "--agent-b64", agents[i],
                        "--lair-root", run.state / NODES[i] / "ks", "--offer", offer, "--caps-dir", ops[i] / "caps"]], run)
                    p.wait(60)  # offers for other agents fail closed; the policy step checks completeness
        for i in range(len(NODES)):
            ids = dict(line.split("=", 1) for line in run.step(f"ids-{i+1}", [prov, "ids", "--record", ops[i] / "ceremony.json",
                       "--agent-b64", agents[i]]).split() if "=" in line)
            run.step(f"node-provision-{i+1}", [run.bin / "mpc-node", "provision", ops[i] / "node",
                     ids["AGENT_HEX"], ids["PROPOSAL_HEX"], ids["SESSION_HEX"]])
            run.step(f"write-policy-{i+1}", [prov, "write-policy", "--record", ops[i] / "ceremony.json",
                     "--state-dir", ops[i] / "node", "--caps-dir", ops[i] / "caps", "--out", ops[i] / "signer-policy.json"])
            record = json.loads((ops[i] / "ceremony.json").read_text())
            binding = ops[i] / "binding.json"
            binding.write_text(json.dumps({"proposal_action": record["proposal_action"], "spec": record["spec"]}))
            os.chmod(binding, 0o600)
            ops[i].joinpath("dna-hex").write_text(ids["DNA_HEX"])

        relays = []
        for i in range(len(NODES)):
            run.start(f"mpc-node-{i+1}", [run.bin / "mpc-node", "serve", ops[i] / "node"])
            signer = run.start(f"signer-{i+1}", [run.bin / "mpc-lair-signer", "--policy-file", ops[i] / "signer-policy.json",
                               "--signer-socket", ops[i] / "signer" / "signer.sock", "--lair-root", run.state / NODES[i] / "ks"])
            signer.wait_for(r"Lair signer ready", timeout=60)
        for i in range(len(NODES)):
            relays.append(run.start(f"relay-{i+1}", [run.bin / "mpc-relay-service", "--state-dir", ops[i] / "node",
                          "--binding-file", ops[i] / "binding.json", "--app-socket", f"127.0.0.1:{app_ports[i]}",
                          "--origin", f"http://localhost:{app_ports[i]}", "--app-token-file", ops[i] / "app-token",
                          "--installed-app-id", APP_ID, "--dna-hex", (ops[i] / "dna-hex").read_text().strip(),
                          "--signer-socket", ops[i] / "signer" / "signer.sock", "--poll-ms", "1000", "--max-polls", "900"]))
        transcripts = []
        deadline = time.time() + 1200
        while any(r.proc.poll() is None for r in relays):
            failed = [r for r in relays if r.proc.poll() not in (None, 0)]
            if failed:  # fail closed at once: the other relays cannot finish without it
                fail(f"{failed[0].name} aborted the DKG (exit {failed[0].proc.poll()}); see {failed[0].logfile}")
            if time.time() > deadline:
                fail("DKG did not finish within 20 minutes")
            time.sleep(1)
        for r in relays:
            code = r.wait(10)
            found = re.findall(r"PASS: DKG completed with public descriptor, transcript=(\[[0-9, ]+\])", r.text())
            if code != 0 or not found:
                fail(f"{r.name} did not complete DKG (exit {code}); see {r.logfile}")
            transcripts.append(found[-1])
        if len(set(transcripts)) != 1:
            fail(f"nodes disagree on the DKG transcript: {transcripts}")
        log(f"PASS: three independent conductors completed one 2-of-3 DKG; transcript {transcripts[0]}")
        summary = {"run": str(run.root), "dna": dna, "agents": agents, "transcript": transcripts[0],
                   "network_seed": run.seed}
        if not skip_signing:
            summary["signing"] = phase8(run, prov, app, ops, agents, app_ports)
        summary["completed_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (run.root / "RESULT.json").write_text(json.dumps(summary, indent=2) + "\n")
        log(f"result written to {run.root / 'RESULT.json'}")
        if keep_running:
            log("--keep-running: services stay up; press Ctrl-C to stop")
            signal.pause()
    finally:
        run.stop_all()


if __name__ == "__main__":
    main("--keep-running" in sys.argv[1:], "--dkg-only" in sys.argv[1:])
