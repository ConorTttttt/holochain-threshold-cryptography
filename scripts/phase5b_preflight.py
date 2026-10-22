#!/usr/bin/env python3
"""Phase 5B read-only preflight for a Lair-signed live conductor read.

Strictly NON-DESTRUCTIVE. It only reads file metadata, the conductor and Lair
configuration (printing safe fields only), and calls read-only admin APIs via
`hc client call` (list-apps, dump-state). It never reads the app token's
contents, never prints Lair URL query strings, passphrases, capability
secrets, signatures or private keys, and never writes anywhere.

Each check prints PASS / FAIL / BLOCKED / SKIP. Exit status is 0 only when
every requested check is PASS or SKIP. Run with --self-test to check the
Holochain hash decoder against known vectors.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys

PREFIX = {"dna": bytes([0x84, 0x2D, 0x24]), "agent": bytes([0x84, 0x20, 0x24]),
          "action": bytes([0x84, 0x29, 0x24])}
RESULTS = []


def report(name, status, detail=""):
    RESULTS.append(status)
    print(f"{status:<8} {name}" + (f": {detail}" if detail else ""))


def holo_location(core):
    h = hashlib.blake2b(core, digest_size=16).digest()
    out = bytearray(h[0:4])
    for i in range(4, 16, 4):
        for j in range(4):
            out[j] ^= h[i + j]
    return bytes(out)


def decode_holo_b64(kind, value):
    """Validated decode mirroring holo_hash 0.7.1 `holo_hash_decode`."""
    if not value.startswith("u"):
        raise ValueError("missing multibase 'u' prefix")
    raw = base64.urlsafe_b64decode(value[1:] + "=" * (-len(value[1:]) % 4))
    if len(raw) != 39:
        raise ValueError("hash is not 39 bytes")
    if raw[:3] != PREFIX[kind]:
        raise ValueError(f"not a {kind} hash")
    if holo_location(raw[3:35]) != raw[35:]:
        raise ValueError("bad DHT location checksum")
    return raw


def private(path, want_mode, want_dir=False, want_sock=False):
    """Return None if path is owned by this uid with exact mode, else a reason."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return "missing"
    if stat.S_ISLNK(st.st_mode):
        return "is a symlink"
    kind_ok = (stat.S_ISDIR(st.st_mode) if want_dir else
               stat.S_ISSOCK(st.st_mode) if want_sock else stat.S_ISREG(st.st_mode))
    if not kind_ok:
        return "wrong file type"
    if st.st_uid != os.geteuid():
        return "not owned by this user"
    mode = stat.S_IMODE(st.st_mode)
    # Sockets: only "no group/other access" matters; files/dirs: exact mode.
    if (mode & 0o077) if want_sock else (mode != want_mode):
        return f"mode {oct(mode)}, expected {oct(want_mode)}"
    if not want_dir and not want_sock and st.st_nlink != 1:
        return "has hard links"
    return None


def load_yaml(path):
    try:
        import yaml  # PyYAML; optional
        with open(path) as f:
            return yaml.safe_load(f)
    except ImportError:
        # Minimal fallback for the flat keys this script needs.
        data, block = {}, None
        for line in open(path):
            m = re.match(r"^([A-Za-z_]+):\s*(.*)$", line)
            if m:
                block = m.group(1)
                data[block] = m.group(2).strip().strip("'\"") or {}
            m = re.match(r"^\s+([A-Za-z_]+):\s*(.*)$", line)
            if m and block and isinstance(data.get(block), dict):
                data[block][m.group(1)] = m.group(2).strip().strip("'\"")
        return data


def url_path(url):
    """unix:// path with any query (Lair server public key) removed."""
    return str(url).split("?", 1)[0]


def hc_call(port, *args):
    out = subprocess.run(["hc", "client", "call", "--port", str(port), *args],
                         capture_output=True, text=True, timeout=30, cwd="/")
    if out.returncode != 0:
        raise RuntimeError(f"hc client call {args[0]} failed")
    data = json.loads(out.stdout)
    return json.loads(data) if isinstance(data, str) else data


def check_keystore(sandbox):
    cfg_path = os.path.join(sandbox, "conductor-config.yaml")
    if private(cfg_path, 0o600):
        report("config discovery", "FAIL", f"{cfg_path}: {private(cfg_path, 0o600)}")
        return None
    ks = (load_yaml(cfg_path) or {}).get("keystore") or {}
    ktype = ks.get("type")
    report("config discovery", "PASS", f"{cfg_path}; keystore.type={ktype}")
    if ktype == "danger_test_keystore":
        report("same-agent Lair access", "BLOCKED", "test keystore is not secure Lair custody")
        return None
    if ktype == "lair_server_in_proc":
        report("same-agent Lair access", "BLOCKED",
               "in-process Lair has no standalone IPC endpoint for mpc-lair-signer")
        return None
    if ktype != "lair_server":
        report("same-agent Lair access", "FAIL", "unrecognised keystore type")
        return None
    url = ks.get("connection_url", "")
    sock = url_path(url)[len("unix://"):]
    print(f"         keystore.connection_url path={sock} (query not shown)")
    reason = private(sock, 0o700, want_sock=True)
    if reason:
        report("Lair IPC socket", "FAIL", reason)
        return None
    lair_cfg = os.path.join(os.path.dirname(sock), "lair-keystore-config.yaml")
    try:
        same = (load_yaml(lair_cfg) or {}).get("connectionUrl") == url
    except OSError:
        same = False
    listener = subprocess.run(["ss", "-xlp"], capture_output=True, text=True).stdout
    owner = next((re.search(r'users:\(\("([^"]+)",pid=(\d+)', l) for l in listener.splitlines()
                  if f" {sock} " in l), None)
    if not owner:
        report("Lair IPC socket", "FAIL", "no process is listening on the configured socket")
        return None
    report("Lair IPC socket", "PASS" if same else "FAIL",
           f"listening process={owner.group(1)} pid={owner.group(2)}; "
           f"lair root={os.path.dirname(sock)}; config URL matches conductor={same}")
    return os.path.dirname(sock) if same else None


def check_app(port, app_id, dna, agent):
    try:
        apps = hc_call(port, "list-apps")
    except Exception as e:  # noqa: BLE001 - surface only a generic reason
        report("conductor app", "FAIL", str(e))
        return False
    app = next((a for a in apps if a.get("installed_app_id") == app_id), None)
    if not app:
        report("conductor app", "FAIL", f"{app_id} not installed")
        return False
    cells = [c["value"]["cell_id"] for c in app["cell_info"].get("mpc", []) if c.get("type") == "provisioned"]
    ok = (app.get("status", {}).get("type") == "enabled" and app.get("agent_pub_key") == agent and
          len(cells) == 1 and cells[0]["dna_hash"] == dna and cells[0]["agent_pub_key"] == agent)
    report("conductor app", "PASS" if ok else "FAIL",
           f"{app_id} enabled with exactly one provisioned mpc cell matching DNA+agent" if ok else
           "app status, agent or mpc cell does not match the pin")
    return ok


def check_proposal(port, dna, agent, proposal_raw):
    try:
        dump = hc_call(port, "dump-state", dna, agent)
    except Exception as e:  # noqa: BLE001
        report("session proposal", "FAIL", str(e))
        return
    dump = dump[0] if isinstance(dump, list) else dump
    records = dump["source_chain_dump"]["records"]
    found = []
    for rec in records:
        data = rec["action"].get("data", {})
        et = data.get("entry_type")
        if data.get("type") == "Create" and isinstance(et, dict) and "App" in et:
            app = et["App"]
            if app.get("zome_index") == 0 and app.get("entry_index") == 0:
                found.append(bytes(rec["action_address"]))
    if proposal_raw is None:
        report("session proposal", "PASS" if found else "BLOCKED",
               f"{len(found)} local SessionProposal record(s) on {len(records)}-record chain" if found else
               f"no SessionProposal on the {len(records)}-record source chain; operator-approved "
               "`mpc-phase5b-bootstrap propose-session` is required")
    else:
        report("session proposal", "PASS" if proposal_raw in found else "FAIL",
               "pinned proposal is a local SessionProposal" if proposal_raw in found else
               "pinned proposal not found as a local SessionProposal")


def check_files(args, dna_raw, agent_raw, proposal_raw):
    if args.app_token_file:
        reason = private(args.app_token_file, 0o600)
        report("app token file", "FAIL" if reason else "PASS",
               reason or "owned 0600 regular single-link file (contents not read)")
    else:
        report("app token file", "SKIP", "not supplied")
    node = None
    if args.state_dir:
        reason = private(args.state_dir, 0o700, want_dir=True) or \
            private(os.path.join(args.state_dir, "node.json"), 0o600)
        if not reason:
            ctx = json.load(open(os.path.join(args.state_dir, "node.json")))["context"]
            node = ctx
            ok = bytes(ctx["worker_agent"]) == agent_raw and \
                (proposal_raw is None or bytes(ctx["proposal_action"]) == proposal_raw)
            report("pinned node", "PASS" if ok else "FAIL",
                   "node agent/proposal match the pin" if ok else "node agent or proposal mismatch")
        else:
            report("pinned node", "FAIL", reason)
    else:
        report("pinned node", "SKIP", "not supplied")
    if args.policy_file:
        reason = private(args.policy_file, 0o600)
        if reason:
            report("signer policy", "FAIL", reason)
        else:
            pol = json.load(open(args.policy_file))
            b = pol.get("binding", {})
            problems = []
            if pol.get("recipients") != []:
                problems.append("recipients must be [] for Phase 5B")
            if b.get("installed_app_id") != args.installed_app_id or b.get("role") != "mpc":
                problems.append("app id/role")
            if bytes(b.get("dna_hash", [])) != dna_raw:
                problems.append("DNA")
            if bytes(b.get("agent", [])) != agent_raw:
                problems.append("agent")
            if node is None:
                problems.append("cannot compare with node state (--state-dir missing/invalid)")
            else:
                for k_pol, k_node in (("agent", "worker_agent"), ("proposal_action", "proposal_action"),
                                      ("session_id", "session_id"), ("channel_id", "channel_id")):
                    if b.get(k_pol) != node.get(k_node):
                        problems.append(f"{k_pol} differs from node.json")
            report("signer policy", "FAIL" if problems else "PASS",
                   "; ".join(problems) or "exact match with node, DNA and app; recipients []")
    else:
        report("signer policy", "SKIP", "not supplied")
    if args.signer_socket:
        parent = os.path.dirname(args.signer_socket)
        reason = private(parent, 0o700, want_dir=True)
        if not reason and os.path.lexists(args.signer_socket):
            reason = private(args.signer_socket, 0o600, want_sock=True)
        report("signer socket", "FAIL" if reason else "PASS",
               reason or ("socket present and private" if os.path.lexists(args.signer_socket)
                          else "private 0700 parent ready; signer not running"))
    else:
        report("signer socket", "SKIP", "not supplied")


def self_test():
    dna = "uhC0kV173j4T9Qc2pCxriXG5im1O5Zw7aFxchFZJuPG68qxwgzGm5"
    agent = "uhCAkVOE_IPgBUc6zuSoVhkgslTdHyepHxIyIFVURdOVhej3KlKwd"
    # Expected values produced by the Rust holo_hash 0.7.1 decoder.
    assert decode_holo_b64("dna", dna).hex() == \
        "842d24575ef78f84fd41cda90b1ae25c6e629b53b9670eda17172115926e3c6ebcab1c20cc69b9"
    assert decode_holo_b64("agent", agent).hex() == \
        "84202454e13f20f80151ceb3b92a1586482c953747c9ea47c48c8815551174e5617a3dca94ac1d"
    for kind, bad in (("agent", dna), ("dna", dna[:-2]), ("agent", agent[:-1] + "A"), ("dna", dna[1:])):
        try:
            decode_holo_b64(kind, bad)
        except ValueError:
            continue
        raise AssertionError(f"accepted invalid {kind} hash")
    assert url_path("unix:///a/socket?k=SERVERKEY") == "unix:///a/socket"
    print("PASS: phase5b_preflight self-test")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--sandbox-dir", help="conductor data root, e.g. .../state/node-a")
    p.add_argument("--admin-port", type=int)
    p.add_argument("--installed-app-id", default="mpc-phase5b")
    p.add_argument("--dna-b64")
    p.add_argument("--agent-b64")
    p.add_argument("--proposal-b64")
    p.add_argument("--app-token-file")
    p.add_argument("--state-dir")
    p.add_argument("--policy-file")
    p.add_argument("--signer-socket")
    args = p.parse_args()
    if args.self_test:
        return self_test()
    if not (args.sandbox_dir and args.admin_port and args.dna_b64 and args.agent_b64):
        p.error("--sandbox-dir, --admin-port, --dna-b64 and --agent-b64 are required")
    dna_raw = decode_holo_b64("dna", args.dna_b64)
    agent_raw = decode_holo_b64("agent", args.agent_b64)
    proposal_raw = decode_holo_b64("action", args.proposal_b64) if args.proposal_b64 else None
    print(f"         DNA hex={dna_raw.hex()}\n         agent hex={agent_raw.hex()}")
    if proposal_raw:
        print(f"         proposal hex={proposal_raw.hex()}")
    check_keystore(args.sandbox_dir)
    print("NOTE     Lair key authority for the agent is proven only by a signer-produced "
          "signature that the conductor accepts (live probe).")
    if check_app(args.admin_port, args.installed_app_id, args.dna_b64, args.agent_b64):
        check_proposal(args.admin_port, args.dna_b64, args.agent_b64, proposal_raw)
    check_files(args, dna_raw, agent_raw, proposal_raw)
    sys.exit(0 if all(r in ("PASS", "SKIP") for r in RESULTS) else 1)


if __name__ == "__main__":
    main()
