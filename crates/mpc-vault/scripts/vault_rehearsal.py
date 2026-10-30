#!/usr/bin/env python3
"""Vault end-to-end on the DISPOSABLE Phase 6 rehearsal, against Solana DEVNET.

It reuses scripts/phase6_rehearsal.py unmodified (loaded from --repo, read-only):
fresh three-conductor DKG with a throwaway Lair passphrase. Two harness hooks are
patched in memory only: the rehearsal root is resolved (HOME/mpc-phase6-rehearsal is
a symlink on this host and Lair refuses it) and `signal.pause` runs this vault test
once the DKG is done. Nothing in --repo is written except the rehearsal run dir the
harness itself creates.

Then: activate the group, fund the vault and create a durable nonce account with a
THROWAWAY devnet funder key (NETWORK ACCESS: devnet RPC), start one vault service per
node, and drive a devnet transfer through the HTTP API: propose on node 1, import on
nodes 2 and 3, node 2 refused as non-selected, approve on nodes 1 and 3, signed by
mpc-sign, broadcast once, confirmed on devnet. OpenSSL independently verifies the
signature.

The devnet RPC faucet is closed, so the funder address must be funded by a person
from https://faucet.solana.com (devnet). The script prints the address first and waits.

  python3 -I vault_rehearsal.py --repo <repo with built binaries> --vault-bin <mpc-vault> \
      --funder-key-file <abs path, created 0600 if missing>
"""
from __future__ import annotations
import argparse, base64, importlib.util, json, os, re, secrets, subprocess, sys, tempfile, time, types
import urllib.error, urllib.request
from pathlib import Path

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
DEVNET = "https://api.devnet.solana.com"


def b58(raw: bytes) -> str:
    n, out = int.from_bytes(raw, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out


def rpc(method: str, params: list):
    req = urllib.request.Request(DEVNET, json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
                                 {"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r).get("result")


class Api:
    def __init__(self, port: int, token: str):
        self.port, self.token = port, token

    def __call__(self, method: str, path: str, body=None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data, method=method,
                                     headers={"authorization": f"Bearer {self.token}", "content-type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True, type=Path)
    ap.add_argument("--vault-bin", required=True, type=Path)
    ap.add_argument("--funder-key-file", required=True, type=Path)
    ap.add_argument("--fund-lamports", type=int, default=50_000_000)
    ap.add_argument("--amount", type=int, default=1_000_000)
    ap.add_argument("--funding-wait-secs", type=int, default=3000)
    args = ap.parse_args()
    repo = args.repo.resolve()

    spec = importlib.util.spec_from_file_location("phase6", repo / "scripts" / "phase6_rehearsal.py")
    h = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(h)
    log = h.log

    # 1. A funder address to show the operator right away.
    out = subprocess.run([args.vault_bin, "solana-funder", "--funder-key-file", args.funder_key_file], capture_output=True, text=True)
    if out.returncode != 0:
        h.fail(f"cannot prepare the funder key: {out.stderr.strip()}")
    funder = out.stdout.strip().split("=", 1)[1]
    log(f"THROWAWAY devnet funder {funder}: fund it from https://faucet.solana.com (devnet, 0.1 SOL is enough) while the DKG runs")

    # 2. Harness patches (in memory only).
    h.HOME = (Path.home() / "mpc-phase6-rehearsal").resolve().parent
    if not (repo / "workdir/holochain-mpc-core.happ").is_file():
        h.fail("workdir/holochain-mpc-core.happ missing in --repo")
    h.build = lambda: None  # the binaries in --repo/target/debug are used as they are
    ports, runs = [], []
    real_free = h.free_port
    h.free_port = lambda: ports.append(real_free()) or ports[-1]
    real_run = h.Run
    class CapturedRun(real_run):
        def __init__(self):
            super().__init__()
            runs.append(self)
    h.Run = CapturedRun
    result: dict = {}
    h.signal.pause = lambda: vault_test(h, runs[0], ports, args, funder, result)
    try:
        h.main(True, True)
    finally:
        if result:
            Path(runs[0].root / "RESULT-vault.json").write_text(json.dumps(result, indent=2) + "\n")
            log(f"result written to {runs[0].root / 'RESULT-vault.json'}")


def vault_test(h, run, ports, args, funder: str, result: dict) -> None:
    log, fail = h.log, h.fail
    bootstrap, app_ports, admin = ports[0], ports[1:4], ports[4:7]
    ops = [run.ops / n for n in h.NODES]
    agents = (run.ops / "participants.txt").read_text().split()
    prov = run.bin / "mpc-phase5c-provision"

    def app(i: int) -> list:
        return ["--app-port", app_ports[i], "--origin", f"http://localhost:{app_ports[i]}", "--app-token-file", ops[i] / "app-token",
                "--agent-b64", agents[i], "--lair-root", run.state / h.NODES[i] / "ks"]

    # 3. Group activation (what the operators do in Phase 8).
    for i in range(3):
        run.step(f"activate-{i+1}", [prov, "activate-group", *app(i), "--record", ops[i] / "ceremony.json",
                 "--state-dir", ops[i] / "node", "--confirm-activation-write"])

    # 4. Vault service configs. A SHORT base path: unix socket paths are limited to ~107 bytes.
    base = Path(tempfile.mkdtemp(prefix="mv-", dir="/tmp"))
    os.chmod(base, 0o700)
    services = []
    for i in range(3):
        token_file = base / f"n{i+1}.token"
        subprocess.run([args.vault_bin, "gen-token", token_file], check=True)
        cfg = {"listen": f"127.0.0.1:{h.free_port()}", "token_file": str(token_file), "data_dir": str(base / f"n{i+1}"),
               "auto_broadcast": True, "default_expiry_secs": 3600,
               "node": {"bin_dir": str(run.bin), "agent_b64": agents[i], "record": str(ops[i] / "ceremony.json"),
                        "state_dir": str(ops[i] / "node"), "caps_dir": str(ops[i] / "caps"), "app_port": app_ports[i],
                        "origin": f"http://localhost:{app_ports[i]}", "app_token_file": str(ops[i] / "app-token"),
                        "lair_root": str(run.state / h.NODES[i] / "ks"), "installed_app_id": h.APP_ID,
                        "dna_hex_file": str(ops[i] / "dna-hex"), "passphrase_file": str(run.root / "THROWAWAY-passphrase")}}
        services.append({"cfg": cfg, "cfg_path": base / f"n{i+1}.json", "token": token_file.read_text().strip()})

    # 5. NETWORK: fund the vault and create the durable nonce account from the funder.
    first = services[0]
    first["cfg_path"].write_text(json.dumps(first["cfg"]))
    log("devnet setup: waiting for the funder, then funding the vault and creating a durable nonce account")
    setup = subprocess.run([args.vault_bin, "solana-setup", "--config", first["cfg_path"], "--funder-key-file", args.funder_key_file,
                            "--fund-lamports", str(args.fund_lamports), "--nonce", "--wait-funding-secs", str(args.funding_wait_secs)],
                           capture_output=True, text=True)
    (run.logs / "solana-setup.log").write_text(setup.stdout + setup.stderr)
    if setup.returncode != 0:
        fail(f"devnet setup failed (see {run.logs / 'solana-setup.log'}): {(setup.stderr or setup.stdout).strip()[-300:]}")
    nonce = re.search(r"nonce_account=(\w+)", setup.stdout).group(1)
    vault_addr = re.search(r"vault address:\s+(\w+)", setup.stdout).group(1)
    log(f"vault address {vault_addr} funded; durable nonce account {nonce}")
    result.update({"vault_address": vault_addr, "nonce_account": nonce, "funder": funder, "network": "solana-devnet (throwaway funds)"})

    # 6. One service per node.
    apis = []
    for i, s in enumerate(services):
        s["cfg"]["solana"] = {"nonce_account": nonce}
        s["cfg_path"].write_text(json.dumps(s["cfg"]))
        p = run.start(f"vault-{i+1}", [args.vault_bin, "serve", "--config", s["cfg_path"]])
        p.wait_for(r"mpc-vault listening", timeout=60)
        apis.append(Api(int(s["cfg"]["listen"].rsplit(":", 1)[1]), s["token"]))
    vaults = []
    for i, api in enumerate(apis):
        code, v = api("POST", "/vaults", {"name": "rehearsal vault", "chain": "solana-devnet"})
        if code != 201 or v["address"] != vault_addr:
            fail(f"node {i+1} vault creation: {code} {v}")
        vaults.append(v["id"])
        if [m["local"] for m in v["members"]].count(True) != 1:
            fail("exactly one member must be local")
    code, v = apis[0]("GET", f"/vaults/{vaults[0]}")
    before = int(v["balance"]["raw"])
    log(f"all three services agree on vault {vault_addr}; balance {v['balance']['display']}")
    code, dup = apis[0]("POST", "/vaults", {"name": "again", "chain": "solana-devnet"})
    if code != 409:
        fail(f"a second vault for the same group was not refused: {code}")

    # 7. Propose on node 1: node 1 and node 3 sign.
    recipient = b58(secrets.token_bytes(32))
    req = {"vault_id": vaults[0], "recipient": recipient, "amount": str(args.amount), "memo": "mpc-vault rehearsal",
           "selected_signers": [agents[0], agents[2]]}
    code, pre = apis[0]("POST", "/proposals/preview", req)
    if code != 200:
        fail(f"preview failed: {code} {pre}")
    code, prop = apis[0]("POST", "/proposals", req)
    if code != 201:
        fail(f"proposal failed: {code} {prop}")
    s = prop["summary"]
    assert prop["integrity"]["status"] == "verified" and pre["summary"] == s and pre["message_sha256"] == prop["message_sha256"]
    assert (s["recipient"], s["amount"]["raw"], s["fee"]["raw"], s["memo"], s["from"]) == (recipient, str(args.amount), "5000", "mpc-vault rehearsal", vault_addr), s
    assert any("Durable nonce" in n for n in s["notes"]), s["notes"]
    log(f"proposal {prop['id']}: {s['amount']['display']} -> {recipient}, fee {s['fee']['display']}, {prop['message_len']} bytes, sha256 {prop['message_sha256'][:16]}...")
    code, plan = apis[0]("GET", f"/proposals/{prop['id']}/plan")

    # 8. Imports. A truncated plan is refused (the bytes no longer decode); the real one is accepted.
    cut = json.loads(json.dumps(plan))
    cut["message"] = cut["message"][:-1]
    code, e = apis[2]("POST", "/proposals/import", {"vault_id": vaults[2], "plan": cut})
    if code != 400:
        fail(f"a truncated plan was not refused: {code} {e}")
    imported = []
    for i in (1, 2):
        code, p = apis[i]("POST", "/proposals/import", {"vault_id": vaults[i], "plan": plan})
        if code != 201 or p["summary"] != s or p["message_sha256"] != prop["message_sha256"]:
            fail(f"import on node {i+1}: {code} {p}")
        imported.append(p)
    code, e = apis[2]("POST", "/proposals/import", {"vault_id": vaults[2], "plan": plan})
    if code != 409 or e["error"]["code"] != "replay":
        fail(f"a repeated import was not refused as replay: {code} {e}")
    log("node 3 and node 2 decoded the same bytes to the same summary; truncated and repeated plans refused")

    # 9. Node 2 is not a selected signer.
    code, e = apis[1]("POST", f"/proposals/{imported[0]['id']}/approve", {"confirm": True, "message_sha256": prop["message_sha256"]})
    if code != 403 or e["error"]["code"] != "not_selected":
        fail(f"approval by the non-selected node was not refused: {code} {e}")
    log("PASS: approval by node 2 (not selected) refused with 403 not_selected")

    # 10. Wait until every selected node sees the full group activation (read-only), then approve.
    plan_file = run.ops / "vault-plan.json"
    plan_file.write_text(json.dumps(plan))
    os.chmod(plan_file, 0o600)
    for i in (0, 2):
        for attempt in range(40):
            pr = h.Proc(f"signing-status-{i+1}-{attempt}", [str(a) for a in [prov, "signing-status", *app(i), "--record",
                        ops[i] / "ceremony.json", "--plan", plan_file]], run)
            if pr.wait(60) == 0 and "activated=true" in pr.text():
                break
            time.sleep(5)
        else:
            fail(f"node {i+1} never saw the full activation")
    ids = {0: prop["id"], 2: imported[1]["id"]}
    t0 = time.time()
    for i in (0, 2):
        code, p = apis[i]("POST", f"/proposals/{ids[i]}/approve", {"confirm": True, "message_sha256": prop["message_sha256"]})
        if code != 202 or p["local_task"] != "approving":
            fail(f"approve on node {i+1}: {code} {p}")
        dup_code, dup = apis[i]("POST", f"/proposals/{ids[i]}/approve", {"confirm": True, "message_sha256": prop["message_sha256"]})
        if dup_code != 409:
            fail(f"a duplicate approval on node {i+1} was not refused: {dup_code} {dup}")
    log("both operators approved through the API (duplicate approvals refused); waiting for signing, broadcast, confirmation")

    # 11. Watch to the end. Nothing is retried by anyone.
    states, final = [], None
    end = time.time() + 1200
    while time.time() < end:
        code, p = apis[0]("GET", f"/proposals/{prop['id']}")
        tag = (p["state"], p["local_task"])
        if not states or states[-1] != tag:
            states.append(tag)
            log(f"node 1 proposal: {p['state']} (task {p['local_task']}), confirmations {p['confirmations']['count']}/2")
        if p["state"] in ("confirmed", "failed", "expired", "rejected"):
            final = p
            break
        time.sleep(2)
    if final and final["state"] == "failed" and final["failure"]["step"] == "attach":
        # Known blocker: the signing profile signs a domain-separated wrapper, not the transaction bytes.
        signed = Path(services[0]["cfg"]["data_dir"]) / "w" / prop["id"] / "signed"
        work = run.ops / "vault-verify"
        work.mkdir(mode=0o700)
        key = (signed / "group-public-key.bin").read_bytes()
        (work / "key.pem").write_text("-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(bytes.fromhex("302a300506032b6570032100") + key).decode()
                                      + "\n-----END PUBLIC KEY-----\n")
        (work / "tx.bin").write_bytes(bytes(plan["message"]))
        def verify(msg: Path) -> bool:
            r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", work / "key.pem", "-rawin", "-in", msg,
                                "-sigfile", signed / "signature.bin"], capture_output=True, text=True)
            return "Signature Verified Successfully" in r.stdout
        over_wrapper, over_tx = verify(signed / "signed-message.bin"), verify(work / "tx.bin")
        result.update({"outcome": "BLOCKED: the 2-of-3 signature is valid over signed-message.bin but not over the transaction bytes",
                       "proposal": prop["id"], "failure": final["failure"], "tx_bytes": len(plan["message"]),
                       "signed_message_bytes": (signed / "signed-message.bin").stat().st_size,
                       "openssl_valid_over_signed_message": over_wrapper, "openssl_valid_over_transaction": over_tx,
                       "broadcast_attempted": final["broadcast"] is not None, "state_sequence": states})
        log(f"BLOCKED at attach: signature valid over signed-message.bin={over_wrapper}, over the transaction bytes={over_tx}; nothing broadcast")
        fail("devnet cannot accept this signature: the signing profile signs a domain-separated wrapper (see RESULT-vault.json)")
    if not final or final["state"] != "confirmed":
        fail(f"the proposal did not confirm: {json.dumps(final or p, indent=1)[:1500]}")
    time.sleep(8)
    code, third = apis[2]("GET", f"/proposals/{ids[2]}")
    sig_hex, txid = final["signature"], final["broadcast"]["txid"]

    # 12. Independent checks: OpenSSL (RFC 8032) and the chain itself.
    message = bytes(plan["message"])
    group_key = bytes(plan["descriptor"]["group_verifying_key"])
    work = run.ops / "vault-verify"
    work.mkdir(mode=0o700)
    (work / "msg.bin").write_bytes(message)
    (work / "sig.bin").write_bytes(bytes.fromhex(sig_hex))
    (work / "key.pem").write_text("-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(bytes.fromhex("302a300506032b6570032100") + group_key).decode()
                                  + "\n-----END PUBLIC KEY-----\n")
    ok = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", work / "key.pem", "-rawin", "-in", work / "msg.bin",
                         "-sigfile", work / "sig.bin"], capture_output=True, text=True)
    if "Signature Verified Successfully" not in ok.stdout:
        fail(f"OpenSSL rejected the group signature: {ok.stdout} {ok.stderr}")
    if b58(group_key) != vault_addr or b58(bytes.fromhex(sig_hex)) != txid:
        fail("vault address or transaction id do not follow from the group key and signature")
    status = rpc("getSignatureStatuses", [[txid], {"searchTransactionHistory": True}])["value"][0]
    got = int(rpc("getBalance", [recipient, {"commitment": "confirmed"}])["value"])
    after = int(rpc("getBalance", [vault_addr, {"commitment": "confirmed"}])["value"])
    if not status or status.get("err") or status.get("confirmationStatus") not in ("confirmed", "finalized"):
        fail(f"devnet does not report the transaction confirmed: {status}")
    if got != args.amount or before - after != args.amount + 5000:
        fail(f"balances do not match: recipient {got}, vault {before} -> {after}")
    log(f"PASS: devnet accepted the 2-of-3 signed transfer {txid} ({status['confirmationStatus']}); recipient holds {got} lamports, "
        f"vault paid {before - after} (amount + 5000 fee); OpenSSL verifies the signature")

    # 13. Replays and retries stay refused.
    code, e = apis[0]("POST", f"/proposals/{prop['id']}/broadcast")
    if code != 409 or e["error"]["code"] != "broadcast_attempted":
        fail(f"a second broadcast was not refused: {code} {e}")
    code2, e2 = apis[0]("POST", "/proposals/import", {"vault_id": vaults[0], "plan": plan})
    if code2 != 409:
        fail(f"re-importing a finished plan was not refused: {code2} {e2}")
    code, ev = apis[0]("GET", "/events")
    log("PASS: second broadcast and replayed plan refused; nothing was retried")
    result.update({"proposal": prop["id"], "operation_id": prop["operation_id"], "txid": txid,
                   "explorer": final["broadcast"]["url"], "state_sequence": states, "signature": sig_hex,
                   "node3_state": third.get("state"), "recipient": recipient, "amount_lamports": args.amount,
                   "vault_balance_before": before, "vault_balance_after": after, "openssl": "verified",
                   "events": [e["kind"] for e in ev["events"]], "seconds_from_approval_to_confirmed": round(time.time() - t0)})


if __name__ == "__main__":
    main()
