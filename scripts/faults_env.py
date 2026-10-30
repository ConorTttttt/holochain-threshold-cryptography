#!/usr/bin/env python3
"""Environment for the Phase 6/8 fault-injection scenarios (scripts/phase6_faults.py).

DISPOSABLE ONLY. Reuses `Run`/`Proc` from scripts/phase6_rehearsal.py (imported, not
modified) and repeats its provisioning sequence with three differences:

* each conductor is its own `hc sandbox generate -n 1` process, so one node can be
  frozen, killed or moved into a private network namespace on its own;
* every relay and signing service reaches its Lair signer through a SignerProxy, a
  transparent unix-socket forwarder that can hold, drop or react to named requests
  (it never logs payloads);
* journal.sqlite is read through its plaintext columns only (state, revision, row
  counts), and `gate()` can freeze a node's journal between two commits to make a
  kill point deterministic.

Nothing here touches ~/mpc-phase5b-sandbox, ~/mpc-phase5c-sandbox or
~/.local/state/mpc-phase5c; the run directory is refused if it would.
"""
from __future__ import annotations
import datetime, importlib.util, json, os, re, secrets, shutil, signal, socket, sqlite3
import struct, subprocess, sys, threading, time
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _load_rehearsal():
    spec = importlib.util.spec_from_file_location("phase6_rehearsal", HERE / "phase6_rehearsal.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["phase6_rehearsal"] = module
    spec.loader.exec_module(module)
    return module


rh = _load_rehearsal()
REPO, HOME, NODES, APP_ID = rh.REPO, rh.HOME, rh.NODES, rh.APP_ID
FORBIDDEN = rh.FORBIDDEN
# ~/mpc-phase6-rehearsal may be a symlink (it is on the development host: offloaded to
# /mnt/holochain). Lair records its real socket path, and provisioning refuses a
# --lair-root spelled through a symlink, so every run path is fully resolved.
BASE = (HOME / "mpc-phase6-rehearsal").resolve()
_log_sink = {"file": None}
_log_lock = threading.Lock()


def log(msg: str) -> None:
    line = f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {msg}"
    with _log_lock:
        print(line, flush=True)
        if _log_sink["file"]:
            _log_sink["file"].write(line + "\n")
            _log_sink["file"].flush()


rh.log = log  # Proc/step messages go to the scenario log too


class HarnessError(Exception):
    """The environment could not be built; says nothing about the product."""


def hfail(msg: str):
    raise HarnessError(msg)


def guarded(fn, *a, **kw):
    """rh.fail() raises SystemExit; turn it into a HarnessError."""
    try:
        return fn(*a, **kw)
    except SystemExit as e:
        raise HarnessError(f"harness step failed (exit {e.code}); see the run logs") from None


class FaultRun(rh.Run):
    def __init__(self, label: str):
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        # Short on purpose: Lair and signer unix sockets live below this path and
        # SUN_LEN limits them to ~107 bytes.
        short = re.sub(r"[^a-z0-9]", "", label.lower())[:6]
        self.root = BASE / f"f{stamp[9:15]}-{short}-{os.getpid()}"
        for path in FORBIDDEN:
            for forbidden in (path, path.resolve()):
                if forbidden == self.root or forbidden in self.root.parents:
                    raise HarnessError(f"refusing to touch {forbidden}")
        os.umask(0o077)
        self.root.mkdir(mode=0o700, parents=True)
        self.state, self.ops, self.logs = (self.root / d for d in ("state", "ops", "logs"))
        for d in (self.state, self.ops, self.logs):
            d.mkdir(mode=0o700)
        self.passphrase = secrets.token_urlsafe(24)
        (self.root / "THROWAWAY-passphrase").write_text(self.passphrase + "\n")
        os.chmod(self.root / "THROWAWAY-passphrase", 0o600)
        self.env = dict(os.environ, PATH=rh.tool_path())
        self.background = []
        self.seed = f"mpc-phase6-faults-{label}-{stamp}"
        self.bin = REPO / "target" / "debug"
        _log_sink["file"] = open(self.logs / "harness.log", "a")


def free_port() -> int:
    return rh.free_port()


# ---------------------------------------------------------------- journal ----

def _connect(db: Path, timeout: float = 5.0) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db), timeout=timeout, isolation_level=None)
    conn.execute("PRAGMA query_only=1")
    return conn


def _read(conn: sqlite3.Connection) -> dict:
    def rows(sql):
        try:
            return conn.execute(sql).fetchall()
        except sqlite3.OperationalError:
            return []
    return {
        "dkg": [{"state": s, "revision": r} for s, r in rows("SELECT state,revision FROM dkg_checkpoints")],
        "secrets": len(rows("SELECT 1 FROM secrets")),
        "nonces": [{"operation": o[:8], "state": s} for o, s in rows("SELECT hex(operation),state FROM nonces")],
        "lifecycles": [{"operation": o[:8], "state": s, "reason": r}
                       for o, s, r in rows("SELECT hex(operation),state,reason FROM lifecycles")],
    }


def snapshot(state_dir: Path) -> dict:
    db = state_dir / "journal.sqlite"
    if not db.exists():
        return {"journal": None}
    conn = _connect(db)
    try:
        return _read(conn)
    finally:
        conn.close()


def dkg_state(snap: dict) -> str | None:
    return snap["dkg"][0]["state"] if snap.get("dkg") else None


def dkg_revision(snap: dict) -> int:
    return snap["dkg"][0]["revision"] if snap.get("dkg") else -1


def gate(db: Path, predicate, on_hit, timeout: float, idle: float = 0.0003):
    """Hold SQLite's write lock while `predicate(snapshot)` is evaluated, so the
    process that owns `db` cannot commit another write between the check and
    `on_hit()`. The lock is released between attempts so the process can make
    progress. Returns the snapshot that matched, or None on timeout."""
    deadline = time.time() + timeout
    while not db.exists():
        if time.time() > deadline:
            return None
        time.sleep(0.05)
    conn = sqlite3.connect(str(db), timeout=0, isolation_level=None)
    try:
        while time.time() < deadline:
            try:
                conn.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError:
                time.sleep(idle)
                continue
            try:
                snap = _read(conn)
                if predicate(snap):
                    on_hit(snap)
                    return snap
            finally:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.OperationalError:
                    pass
            time.sleep(idle)
        return None
    finally:
        conn.close()


def wait_snapshot(state_dir: Path, predicate, timeout: float, every: float = 0.5):
    deadline = time.time() + timeout
    snap = {"journal": None}
    while time.time() < deadline:
        snap = snapshot(state_dir)
        if predicate(snap):
            return snap
        time.sleep(every)
    return None


# ----------------------------------------------------------- signer proxy ----

class Event:
    def __init__(self, node: int, index: int, operation: str, round_: int | None):
        self.node, self.index, self.operation, self.round = node, index, operation, round_
        self.at = time.time()

    def label(self) -> str:
        return f"{self.operation}" + (f"/r{self.round}" if self.round is not None else "")


class Trigger:
    """Fires once, when `match(event, history)` is true for the nth time.
    `action(event)` runs BEFORE the request is forwarded and returns "forward" or
    "drop" (close the connection: the caller sees an uncertain signer failure)."""

    def __init__(self, name: str, match, action, nth: int = 1):
        self.name, self.match, self.action, self.nth = name, match, action, nth
        self.seen, self.fired, self.fired_at = 0, False, None


class SignerProxy:
    """Transparent forwarder in front of one node's Lair signer socket."""

    def __init__(self, node: int, listen: Path, upstream: Path):
        self.node, self.listen, self.upstream = node, listen, upstream
        self.history: list[Event] = []
        self.triggers: list[Trigger] = []
        self.lock = threading.Lock()
        self.stopped = False
        listen.parent.mkdir(mode=0o700, exist_ok=True)
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(listen))
        os.chmod(listen, 0o600)
        self.server.listen(16)
        threading.Thread(target=self._accept, daemon=True).start()

    def add(self, trigger: Trigger) -> Trigger:
        with self.lock:
            self.triggers.append(trigger)
        return trigger

    def stop(self):
        self.stopped = True
        try:
            self.server.close()
        except OSError:
            pass

    def _accept(self):
        while not self.stopped:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    @staticmethod
    def _read_exact(conn, n):
        data = b""
        while len(data) < n:
            chunk = conn.recv(n - len(data))
            if not chunk:
                raise EOFError
            data += chunk
        return data

    def _serve(self, conn):
        try:
            size = struct.unpack(">I", self._read_exact(conn, 4))[0]
            raw = self._read_exact(conn, size)
            try:
                req = json.loads(raw)
                envelope = req.get("envelope") or {}
                op, round_ = req.get("operation", "?"), envelope.get("round")
            except ValueError:
                op, round_ = "?", None
            with self.lock:
                event = Event(self.node, len(self.history), op, round_)
                due = []
                for t in self.triggers:
                    if not t.fired and t.match(event, list(self.history)):
                        t.seen += 1
                        if t.seen >= t.nth:
                            t.fired, t.fired_at = True, time.time()
                            due.append(t)
            action = "forward"
            for t in due:
                log(f"trigger '{t.name}' fired on node-{self.node + 1} at {event.label()} (#{event.index})")
                if t.action(event) == "drop":
                    action = "drop"
            with self.lock:
                self.history.append(event)
            if action == "drop":
                conn.close()
                return
            up = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            up.settimeout(20)
            up.connect(str(self.upstream))
            up.sendall(struct.pack(">I", size) + raw)
            head = self._read_exact(up, 4)
            body = self._read_exact(up, struct.unpack(">I", head)[0])
            up.close()
            conn.sendall(head + body)
        except (EOFError, OSError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def trace(self) -> list[str]:
        with self.lock:
            return [e.label() for e in self.history]


# ---------------------------------------------------------------- network ----

class Net:
    """Rootless private network for the partition scenarios, with custody outside it.

    Custody refuses euid 0 and any ancestor directory not owned by root or by this user
    (mpc-runtime `check_location`). Inside any unprivileged user namespace euid 0 is
    the only identity with capabilities, and real root's directories (/, /mnt) show as
    the overflow uid, so no process in such a namespace can pass that check. Therefore:

    * the custody stack (mpc-node, relays, signers, mpc-sign, provisioning) runs in the
      host namespaces as this user, exactly as in every other scenario;
    * a hub user + network namespace maps only this user to itself
      (`unshare --map-current-user -n`); every node gets a network namespace owned by
      it, joined to the hub by a veth pair, and the bootstrap/relay server sits in the
      hub;
    * conductors (and their Lair) run in their node's namespace as this user with no
      capabilities (`nsenter --preserve-credentials`); only the plumbing commands (ip,
      nft, sysctl, the namespace holders) get capabilities, and only inside that user
      namespace (`nsenter --keep-caps`);
    * each conductor's admin and app ports are bridged to the same ports on the host
      loopback through 0700 unix sockets (scripts/faults_portfwd.py).

    A partition is an nft drop rule in the hub (between two nodes) or a downed hub-side
    veth (a node from everyone, including the bootstrap server). No root is needed and
    no host interface, route or ruleset is touched. Every namespace process is started
    and killed by PID."""

    PLAIN = ["nsenter", "-U", "-n", "--preserve-credentials"]
    CAPS = [*PLAIN, "--keep-caps"]

    def __init__(self, count: int):
        self.count = count
        self.hub: subprocess.Popen | None = None
        self.holders: list[subprocess.Popen] = []
        self.host_ns = {k: os.readlink(f"/proc/self/ns/{k}") for k in ("user", "net")}
        self.ns: dict[str, str] = {}
        self.ready = False

    @staticmethod
    def _holder(argv: list[str]) -> subprocess.Popen:
        """A `sleep infinity` that keeps a namespace alive; SIGKILLed if the harness dies."""
        def die_with_parent():
            import ctypes
            ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGKILL)  # PR_SET_PDEATHSIG
        return subprocess.Popen(argv, stdin=subprocess.DEVNULL, preexec_fn=die_with_parent)

    @staticmethod
    def _await_ns(pid: int, kind: str, *others: str):
        """Wait until `pid` is in a namespace of `kind` that is none of `others`. A node
        holder is nsenter: it starts in the host namespace, joins the hub's, then
        unshare(1) gives it its own, so both earlier ones must be excluded."""
        for _ in range(100):
            try:
                if os.readlink(f"/proc/{pid}/ns/{kind}") not in others:
                    return
            except OSError:
                pass
            time.sleep(0.05)
        hfail(f"{kind} namespace of pid {pid} did not appear")

    @staticmethod
    def available() -> tuple[bool, str]:
        if any(shutil.which(t) is None for t in ("unshare", "nsenter", "ip", "nft")):
            return False, "needs unshare, nsenter (util-linux >= 2.39), ip (iproute2) and nft"
        hub = Net._holder(["unshare", "--map-current-user", "-n", "sleep", "infinity"])
        try:
            Net._await_ns(hub.pid, "user", os.readlink("/proc/self/ns/user"))
            t = ["-t", str(hub.pid), "--"]
            caps = subprocess.run([*Net.CAPS, *t, "sh", "-c",
                                   "ip link add t0 type veth peer name t1 && nft list ruleset >/dev/null"],
                                  capture_output=True, text=True)
            plain = subprocess.run([*Net.PLAIN, *t, "sh", "-c", "id -u; grep CapEff /proc/self/status"],
                                   capture_output=True, text=True)
        except HarnessError as e:
            return False, str(e)
        finally:
            hub.kill()
            hub.wait(5)
        if caps.returncode != 0:
            return False, ("unprivileged user+network namespaces or nftables are unavailable here: "
                           + (caps.stderr.strip().splitlines() or ["?"])[-1])
        out = plain.stdout.split()
        if plain.returncode != 0 or out[:1] != [str(os.getuid())] or out[-1:] != ["0000000000000000"]:
            return False, f"a namespace workload would not run as uid {os.getuid()} without capabilities: {plain.stdout!r}"
        return True, (f"rootless user namespace mapping only uid {os.getuid()} (unshare --map-current-user -n) + "
                      "veth + nft; conductors run there without capabilities, custody stays in the host namespaces")

    def _run(self, pid: int, argv: list, caps: bool = True, **kw) -> subprocess.CompletedProcess:
        return subprocess.run([*(self.CAPS if caps else self.PLAIN), "-t", str(pid), "--", *map(str, argv)],
                              capture_output=True, text=True, **kw)

    def _ip(self, *args, ns: int | None = None):
        pid = self.hub.pid if ns is None else self.holders[ns].pid
        r = self._run(pid, ["ip", *args])
        if r.returncode != 0:
            hfail(f"ip {' '.join(args)} failed: {r.stderr.strip()}")

    def setup(self):
        self.hub = self._holder(["unshare", "--map-current-user", "-n", "sleep", "infinity"])
        self._await_ns(self.hub.pid, "net", self.host_ns["net"])
        self._ip("link", "set", "lo", "up")
        self._ip("addr", "add", "10.77.0.1/32", "dev", "lo")
        if self._run(self.hub.pid, ["sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"]).returncode != 0:
            hfail("cannot enable forwarding in the hub namespace")
        for i in range(self.count):
            holder = self._holder([*self.CAPS, "-t", str(self.hub.pid), "--", "unshare", "-n", "sleep", "infinity"])
            self.holders.append(holder)
            self._await_ns(holder.pid, "net", self.host_ns["net"], os.readlink(f"/proc/{self.hub.pid}/ns/net"))
            n = i + 1
            self._ip("link", "add", f"vh{n}", "type", "veth", "peer", f"vn{n}", "netns", str(holder.pid))
            self._ip("addr", "add", f"10.77.{n}.1/24", "dev", f"vh{n}")
            self._ip("link", "set", f"vh{n}", "up")
            self._ip("link", "set", "lo", "up", ns=i)
            self._ip("addr", "add", f"10.77.{n}.2/24", "dev", f"vn{n}", ns=i)
            self._ip("link", "set", f"vn{n}", "up", ns=i)
            self._ip("route", "add", "default", "via", f"10.77.{n}.1", ns=i)
        nft = ("add table inet faults\n"
               "add chain inet faults forward { type filter hook forward priority 0; policy accept; }\n"
               "add chain inet faults input { type filter hook input priority 0; policy accept; }\n")
        r = self._run(self.hub.pid, ["nft", "-f", "-"], input=nft)
        if r.returncode != 0:
            hfail(f"nft setup failed: {r.stderr.strip()}")
        self.ns = {"hub_user": os.readlink(f"/proc/{self.hub.pid}/ns/user"),
                   "hub_net": os.readlink(f"/proc/{self.hub.pid}/ns/net"),
                   "uid_map": " ".join(Path(f"/proc/{self.hub.pid}/uid_map").read_text().split()),
                   **{f"node{i + 1}_net": os.readlink(f"/proc/{h.pid}/ns/net") for i, h in enumerate(self.holders)}}
        self.ready = True
        log(f"netns topology up: hub 10.77.0.1, nodes 10.77.1.2 .. 10.77.{self.count}.2 "
            f"(rootless user namespace, uid_map '{self.ns['uid_map']}'; custody stays in the host namespaces)")

    def prefix(self, i: int) -> list[str]:
        """Run as this user, without capabilities, in node i's network namespace."""
        return [*self.PLAIN, "-t", str(self.holders[i].pid), "--"]

    def hub_prefix(self) -> list[str]:
        return [*self.PLAIN, "-t", str(self.hub.pid), "--"]

    def ip_of(self, i: int) -> str:
        return f"10.77.{i + 1}.2"

    def _nft(self, *rule):
        r = self._run(self.hub.pid, ["nft", "add", "rule", "inet", "faults", *rule])
        if r.returncode != 0:
            hfail(f"nft rule failed: {r.stderr.strip()}")

    def cut(self, a: int, b: int | None = None, relay_port: int | None = None):
        """Partition node a from node b (both directions), or from everyone (b=None).

        The conductors reach each other directly AND through the relay that runs inside
        the bootstrap server in the hub, so a pairwise partition drops (1) the direct
        a<->b traffic in the hub's forward chain and (2) a's and b's traffic to the
        relay port in its input chain. Node a and b can still reach every OTHER node
        directly; the only path between a and b is gone. Drop rules count what they drop."""
        if b is None:
            self._ip("link", "set", f"vh{a + 1}", "down")
            log(f"PARTITION: node-{a + 1} isolated from every peer and the bootstrap server")
            return
        for s, d in ((a, b), (b, a)):
            self._nft("forward", "ip", "saddr", self.ip_of(s), "ip", "daddr", self.ip_of(d), "counter", "drop")
        if relay_port:
            for n in (a, b):
                for proto in ("tcp", "udp"):
                    self._nft("input", "ip", "saddr", self.ip_of(n), proto, "dport", str(relay_port), "counter", "drop")
        log(f"PARTITION: node-{a + 1} <-> node-{b + 1}: direct traffic dropped in the hub"
            + (f" and both nodes cut from the relay on port {relay_port}" if relay_port else ""))

    def heal(self):
        for chain in ("forward", "input"):
            self._run(self.hub.pid, ["nft", "flush", "chain", "inet", "faults", chain])
        for i in range(self.count):
            self._run(self.hub.pid, ["ip", "link", "set", f"vh{i + 1}", "up"])
        log("partition healed")

    # -- evidence: who runs where, and whether the cut is real
    def identity(self, pid: int) -> dict | None:
        try:
            status = dict(l.split(":", 1) for l in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in l)
            return {"euid": int(status["Uid"].split()[1]), "egid": int(status["Gid"].split()[1]),
                    "cap_eff": status["CapEff"].strip(),
                    "user_ns": os.readlink(f"/proc/{pid}/ns/user"), "net_ns": os.readlink(f"/proc/{pid}/ns/net")}
        except (OSError, KeyError, ValueError):
            return None

    def reach(self, i: int | None, host: str, port: int, timeout: float = 3.0) -> str:
        """TCP connect from node i's namespace (None: the hub), as this user without
        capabilities: 'connected', 'refused' (path open, nothing listening), or
        'timeout'/'unreachable' (path cut)."""
        code = ("import socket,sys\n"
                f"try:\n socket.create_connection(({host!r},{port}),timeout={timeout}); print('connected')\n"
                "except ConnectionRefusedError: print('refused')\n"
                "except TimeoutError: print('timeout')\n"
                "except OSError as e: print('unreachable' if e.errno in (101, 113) else f'error {e.errno}')\n")
        pid = self.hub.pid if i is None else self.holders[i].pid
        r = self._run(pid, [sys.executable, "-I", "-c", code], caps=False, timeout=timeout + 10)
        return r.stdout.strip() or f"error: {r.stderr.strip()[-120:]}"

    def link_state(self, i: int) -> str:
        r = self._run(self.hub.pid, ["ip", "-o", "link", "show", f"vh{i + 1}"])
        m = re.search(r"state (\S+)", r.stdout)
        return m.group(1) if m else "?"

    def drop_counters(self) -> list[str]:
        r = self._run(self.hub.pid, ["nft", "list", "table", "inet", "faults"])
        return [" ".join(l.split()) for l in r.stdout.splitlines() if "drop" in l]

    def teardown(self) -> dict:
        """Kill the holders and the hub by PID, then confirm that no process is left in
        any of the namespaces, so the kernel has released them."""
        for p in [*self.holders, *([self.hub] if self.hub else [])]:
            try:
                p.kill()
                p.wait(5)
            except Exception:
                pass
        mine = {v for k, v in self.ns.items() if k != "uid_map"}
        left = []
        for proc in Path("/proc").iterdir():
            if proc.name.isdigit():
                try:
                    if {os.readlink(proc / "ns/net"), os.readlink(proc / "ns/user")} & mine:
                        left.append(int(proc.name))
                except OSError:
                    pass
        alive = [p.pid for p in [*self.holders, *([self.hub] if self.hub else [])] if p.poll() is None]
        result = {"namespaces": self.ns, "holder_pids": [h.pid for h in self.holders],
                  "hub_pid": self.hub.pid if self.hub else None, "holders_alive": alive,
                  "processes_left_in_namespaces": left, "released": not alive and not left}
        log(f"netns teardown: holders and hub killed by PID; processes left in the namespaces: {left or 'none'}")
        return result


# ------------------------------------------------------------- environment ----

class Node:
    def __init__(self, i: int):
        self.i, self.name = i, NODES[i]
        self.procs: dict[str, rh.Proc] = {}
        self.agent = None
        self.ops: Path = None
        self.admin = self.app_port = 0
        self.proxies: dict[str, SignerProxy] = {}
        self.ids: dict[str, str] = {}

    @property
    def state_dir(self) -> Path:
        return self.ops / "node"


class Env:
    def __init__(self, label: str, netns: bool = False, polls: int = 60, poll_ms: int = 1000):
        self.label, self.netns = label, netns
        self.run = FaultRun(label)
        self.polls, self.poll_ms = polls, poll_ms
        self.nodes = [Node(i) for i in range(len(NODES))]
        self.net: Net | None = None
        self.dna = None
        self.agents: list[str] = []
        self.prov = self.run.bin / "mpc-phase5c-provision"
        self.boot = self.run.bin / "mpc-phase5b-bootstrap"
        self.bootstrap_host = "127.0.0.1"
        self.extra: list = []
        self.flags: dict = {}
        log(f"scenario '{label}': run directory {self.run.root}")

    # -- process helpers
    # Every command runs in the host namespaces as this user, including the custody
    # stack in the partition scenarios. Only conductors and the bootstrap server are
    # placed in the private network (see Net).
    def argv(self, i: int, argv: list) -> list[str]:
        return [str(a) for a in argv]

    def step(self, i: int, name: str, argv: list, timeout: float = 120) -> str:
        return guarded(self.run.step, name, self.argv(i, argv), timeout)

    def proc(self, i: int, name: str, argv: list) -> "rh.Proc":
        return rh.Proc(name, self.argv(i, argv), self.run)

    def start(self, i: int, name: str, argv: list, cwd: Path | None = None) -> "rh.Proc":
        p = guarded(self.run.start, name, self.argv(i, argv), cwd)
        self.nodes[i].procs[name] = p
        return p

    def app(self, i: int) -> list:
        n = self.nodes[i]
        return ["--app-port", n.app_port, "--origin", f"http://localhost:{n.app_port}",
                "--app-token-file", n.ops / "app-token", "--agent-b64", self.agents[i],
                "--lair-root", self.run.state / n.name / "ks"]

    def pgids(self, i: int) -> list[int]:
        return [p.proc.pid for p in self.nodes[i].procs.values() if p.proc.poll() is None]

    def signal_node(self, i: int, sig: int, keep: tuple = ()):
        for name, p in self.nodes[i].procs.items():
            if name in keep or p.proc.poll() is not None:
                continue
            try:
                os.killpg(p.proc.pid, sig)
            except ProcessLookupError:
                pass

    def kill(self, i: int, name: str):
        p = self.nodes[i].procs[name]
        if p.proc.poll() is None:
            os.killpg(p.proc.pid, signal.SIGKILL)
        p.proc.wait(10)
        log(f"SIGKILL {self.nodes[i].name}/{name}")

    def alive(self, i: int, name: str) -> bool:
        p = self.nodes[i].procs.get(name)
        return p is not None and p.proc.poll() is None

    # -- bring-up
    def bring_up(self):
        run = self.run
        if self.netns:
            ok, why = Net.available()
            if not ok:
                raise SkipScenario(why)
            self.net = Net(len(NODES))
            self.net.setup()
            self.bootstrap_host = "10.77.0.1"
        bootstrap = free_port()
        self.bootstrap_port = bootstrap
        for n in self.nodes:
            n.app_port, n.admin = free_port(), free_port()
            n.ops = run.ops / n.name
        if self.net:
            self.bridge_ports()
        hub = self.net.hub_prefix() if self.net else []
        guarded(run.start, "bootstrap-srv", [*hub, "kitsune2-bootstrap-srv", "--listen", f"{self.bootstrap_host}:{bootstrap}"])
        time.sleep(2)
        url = f"http://{self.bootstrap_host}:{bootstrap}"
        happ = REPO / "workdir/holochain-mpc-core.happ"
        for i, n in enumerate(self.nodes):
            cwd = run.root / f"hc-{i + 1}"
            cwd.mkdir(mode=0o700)
            self.start(i, f"conductor-{i + 1}", [
                *(self.net.prefix(i) if self.net else []), "hc", "sandbox", f"--force-admin-ports={n.admin}", "generate", "--app-id", APP_ID,
                "--root", run.state, f"-d={n.name}", "-n", "1", "--network-seed", run.seed,
                f"--run={n.app_port}", happ, "network", "--bootstrap", url, "quic", url], cwd)
        for i, n in enumerate(self.nodes):
            guarded(n.procs[f"conductor-{i + 1}"].wait_for, r"Conductor ready", 1, 300)
            os.chmod(run.state / n.name / "ks", 0o700)
            os.chmod(run.state / n.name / "ks" / "lair-keystore-config.yaml", 0o600)
        log("admin ports " + str([n.admin for n in self.nodes]) + ", app ports " + str([n.app_port for n in self.nodes]))
        dna = None
        for i, n in enumerate(self.nodes):
            for attempt in range(30):
                p = self.proc(i, f"list-apps-{i + 1}-{attempt}", ["hc", "client", "call", "--port", n.admin, "list-apps"])
                apps = p.text() if guarded(p.wait, 60) == 0 else ""
                agent = re.findall(r"uhCAk[A-Za-z0-9_-]{48}", apps)
                dnas = set(re.findall(r"uhC0k[A-Za-z0-9_-]{48}", apps))
                if agent and len(dnas) == 1:
                    break
                time.sleep(3)
            else:
                hfail(f"cannot read agent/DNA for {n.name}")
            self.agents.append(agent[0])
            n.agent = agent[0]
            if dna not in (None, *dnas):
                hfail("conductors run different DNA hashes")
            dna = next(iter(dnas))
        if len(set(self.agents)) != len(NODES):
            hfail("agents are not distinct")
        self.dna = dna
        log(f"DNA {dna} (fresh network seed); agents {self.agents}")

    def bridge_ports(self):
        """Bridge each node's admin and app port from its network namespace to the same
        port on the host loopback (scripts/faults_portfwd.py), so the custody stack can
        stay in the host namespaces. The partition never cuts this local link, just as
        it never cut the loopback inside a node's namespace before."""
        fwd = [sys.executable, "-I", HERE / "faults_portfwd.py"]
        socks = self.run.root / "fw"
        socks.mkdir(mode=0o700)
        for i, n in enumerate(self.nodes):
            ports = ["--dir", socks, "--ports", f"{n.admin},{n.app_port}"]
            inner = self.start(i, f"bridge-ns-{i + 1}", [*self.net.prefix(i), *fwd, "--side", "ns", *ports])
            guarded(inner.wait_for, r"bridge ready", 1, 30)
            outer = self.start(i, f"bridge-host-{i + 1}", [*fwd, "--side", "host", *ports])
            guarded(outer.wait_for, r"bridge ready", 1, 30)

    def identities(self) -> dict:
        """euid, capabilities and namespaces of every live process, by node and name."""
        return {f"{n.name}/{name}": self.net.identity(p.proc.pid)
                for n in self.nodes for name, p in n.procs.items() if p.proc.poll() is None}

    # -- provisioning (mirrors scripts/phase6_rehearsal.py main())
    def provision(self):
        run, prov = self.run, self.prov
        for i, n in enumerate(self.nodes):
            for sub in ("", "offers", "caps", "signer"):
                (n.ops / sub).mkdir(mode=0o700, exist_ok=True, parents=True)
            self.step(i, f"token-{i + 1}", [self.boot, "issue-app-token", "--admin-port", n.admin, "--installed-app-id",
                      APP_ID, "--out", n.ops / "app-token", "--expiry-seconds", "7200", "--confirm-admin-token-issue"])
        (run.ops / "participants.txt").write_text("\n".join(self.agents) + "\n")
        os.chmod(run.ops / "participants.txt", 0o600)
        self.step(0, "propose", [prov, "propose", *self.app(0), "--installed-app-id", APP_ID, "--dna-b64", self.dna,
                  "--participants-file", run.ops / "participants.txt", "--threshold", "2",
                  "--record-out", self.nodes[0].ops / "ceremony.json", "--confirm-source-chain-write"])
        for n in self.nodes[1:]:
            shutil.copyfile(self.nodes[0].ops / "ceremony.json", n.ops / "ceremony.json")
            os.chmod(n.ops / "ceremony.json", 0o600)
        rec = lambda i: self.nodes[i].ops / "ceremony.json"
        for i in range(1, len(NODES)):
            self.poll_status(i, "matches the pinned ceremony exactly", "status", f"{NODES[i]} never saw the proposal")
        for i in range(len(NODES)):
            self.accept(i)
        for i in range(len(NODES)):
            self.poll_status(i, "ready_observed=true", "ready", f"{NODES[i]} never observed all acceptances")
        for i, n in enumerate(self.nodes):
            self.step(i, f"grant-{i + 1}", [prov, "prepare-grant", *self.app(i), "--record", rec(i), "--admin-port", n.admin,
                      "--offers-dir", n.ops / "offers", "--confirm-grant-write"])
        for i in range(len(NODES)):
            for j in range(len(NODES)):
                if i == j:
                    continue
                for offer in sorted((self.nodes[j].ops / "offers").glob("offer-*.json")):
                    p = self.proc(i, f"import-{i + 1}-from-{j + 1}-{offer.stem[-8:]}", [
                        prov, "import-offer", "--record", rec(i), "--agent-b64", self.agents[i],
                        "--lair-root", run.state / NODES[i] / "ks", "--offer", offer, "--caps-dir", self.nodes[i].ops / "caps"])
                    guarded(p.wait, 60)
        for i, n in enumerate(self.nodes):
            ids = dict(line.split("=", 1) for line in self.step(i, f"ids-{i + 1}", [
                prov, "ids", "--record", rec(i), "--agent-b64", self.agents[i]]).split() if "=" in line)
            self.step(i, f"node-provision-{i + 1}", [run.bin / "mpc-node", "provision", n.state_dir,
                      ids["AGENT_HEX"], ids["PROPOSAL_HEX"], ids["SESSION_HEX"]])
            self.step(i, f"write-policy-{i + 1}", [prov, "write-policy", "--record", rec(i), "--state-dir", n.state_dir,
                      "--caps-dir", n.ops / "caps", "--out", n.ops / "signer-policy.json"])
            record = json.loads(rec(i).read_text())
            binding = n.ops / "binding.json"
            binding.write_text(json.dumps({"proposal_action": record["proposal_action"], "spec": record["spec"]}))
            os.chmod(binding, 0o600)
            (n.ops / "dna-hex").write_text(ids["DNA_HEX"])
            n.ids = ids
        log("provisioned: proposal accepted by all three, capabilities exchanged, node state pinned")

    def poll_status(self, i, needle, tag, failure):
        for attempt in range(30):
            p = self.proc(i, f"{tag}-{i + 1}-{attempt}", [self.prov, "status", *self.app(i),
                          "--record", self.nodes[i].ops / "ceremony.json"])
            if guarded(p.wait, 60) == 0 and needle in p.text():
                return
            time.sleep(5)
        hfail(failure)

    def accept(self, i):
        accept = self.argv(i, [self.prov, "accept", *self.app(i), "--record", self.nodes[i].ops / "ceremony.json",
                               "--confirm-acceptance-write"])
        status = self.argv(i, [self.prov, "status", *self.app(i), "--record", self.nodes[i].ops / "ceremony.json"])
        for attempt in range(12):  # same single allowed repeat as the rehearsal
            p = rh.Proc(f"accept-{i + 1}-{attempt}", accept, self.run)
            if guarded(p.wait, 120) == 0:
                return
            out = p.text()
            if "DepMissingFromDht" not in out or "could not be completed" not in out:
                hfail(f"accept on {NODES[i]} failed; see {p.logfile}")
            time.sleep(10)
            s = rh.Proc(f"accept-{i + 1}-{attempt}-recheck", status, self.run)
            if guarded(s.wait, 60) != 0 or not re.search(rf"pending\s+{re.escape(self.agents[i])}", s.text()):
                hfail(f"cannot confirm {NODES[i]} acceptance is uncommitted; see {s.logfile}")
        hfail(f"{NODES[i]} still lacks the proposal as a validation dependency")

    # -- DKG
    def start_dkg(self):
        """Start every node's worker, DKG-profile signer and relay. Relays reach their
        signer through a SignerProxy; budget = polls * poll_ms."""
        run = self.run
        for i, n in enumerate(self.nodes):
            self.start(i, f"mpc-node-{i + 1}", [run.bin / "mpc-node", "serve", n.state_dir])
            self.start(i, f"signer-{i + 1}", [run.bin / "mpc-lair-signer", "--policy-file", n.ops / "signer-policy.json",
                       "--signer-socket", n.ops / "signer" / "signer.sock", "--lair-root", run.state / n.name / "ks"])
            guarded(n.procs[f"signer-{i + 1}"].wait_for, r"Lair signer ready", 1, 60)
            n.proxies["dkg"] = SignerProxy(i, n.ops / "px-dkg" / "s.sock", n.ops / "signer" / "signer.sock")
        # A relay that connects before its worker has bound controller.sock exits at once
        # (ENOENT). Under load that race is real (seen once in ~60 starts), so wait for it.
        for i, n in enumerate(self.nodes):
            sock = n.state_dir / "controller.sock"
            for _ in range(300):
                if sock.exists() and self.alive(i, f"mpc-node-{i + 1}"):
                    break
                time.sleep(0.1)
            else:
                hfail(f"{n.name}: mpc-node did not bind {sock.name} within 30s")

    def start_relays(self, only: list[int] | None = None):
        run = self.run
        for i, n in enumerate(self.nodes):
            if only is not None and i not in only:
                continue
            self.start(i, f"relay-{i + 1}", [run.bin / "mpc-relay-service", "--state-dir", n.state_dir,
                       "--binding-file", n.ops / "binding.json", "--app-socket", f"127.0.0.1:{n.app_port}",
                       "--origin", f"http://localhost:{n.app_port}", "--app-token-file", n.ops / "app-token",
                       "--installed-app-id", APP_ID, "--dna-hex", (n.ops / "dna-hex").read_text().strip(),
                       "--signer-socket", n.ops / "px-dkg" / "s.sock",
                       "--poll-ms", str(self.poll_ms), "--max-polls", str(self.polls)])

    def relay_exit(self, i: int) -> int | None:
        return self.nodes[i].procs[f"relay-{i + 1}"].proc.poll()

    def wait_relays(self, indexes: list[int], timeout: float) -> dict:
        """Wait until the given relays have exited; returns {i: exit code or None}."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if all(self.relay_exit(i) is not None for i in indexes):
                break
            time.sleep(0.5)
        return {i: self.relay_exit(i) for i in indexes}

    def relay_text(self, i: int) -> str:
        return self.nodes[i].procs[f"relay-{i + 1}"].text()

    # -- teardown
    def stop(self):
        for p in reversed(self.run.background):
            if p.proc.poll() is None:
                try:
                    os.killpg(p.proc.pid, signal.SIGCONT)
                except ProcessLookupError:
                    pass
        for n in self.nodes:
            for px in n.proxies.values():
                px.stop()
        guarded_stop = [self.run.stop_all]
        for fn in guarded_stop:
            try:
                fn()
            except BaseException as e:  # keep tearing down
                log(f"teardown note: {e!r}")
        for n in self.nodes:  # stragglers that a SIGTERM did not remove
            for p in n.procs.values():
                if p.proc.poll() is None:
                    try:
                        os.killpg(p.proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
        if self.net:
            record = self.net.teardown()
            (self.run.root / "NETNS-TEARDOWN.json").write_text(json.dumps(record, indent=2) + "\n")

    def compact(self):
        """Drop the conductor databases (hundreds of MB); keep logs and evidence."""
        shutil.rmtree(self.run.state, ignore_errors=True)
        for sub in self.run.root.glob("hc-*"):
            shutil.rmtree(sub, ignore_errors=True)


class SkipScenario(Exception):
    pass
