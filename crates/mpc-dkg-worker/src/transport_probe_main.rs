//! Opt-in probe operator CLI. NO automatic provisioning, credential issuance,
//! DKG, retries or FROST policy fallback. Do not run against live state without
//! separate operator approval; local recovery performs SQLite housekeeping.
use holochain_mpc_dkg_worker::{
    capability_exchange::CeremonyRecord,
    connection_policy::{parse_local_app_socket, ConductorPin},
    node_service,
    probe_signer::{read_private_json, validate_record},
    relay::MpcTransport,
    signed_relay::SignedAppTransport,
    socket_signer::UnixMpcSigner,
    transport_probe::{ProbeEndpoint, ProbePlan},
};
use std::{collections::BTreeMap, path::PathBuf};

struct Args {
    op: String,
    flags: BTreeMap<String, String>,
}
fn parse(items: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut items = items;
    let op = items
        .next()
        .ok_or("expected keys|register-key|inspect|send|receive")?;
    let confirm = match op.as_str() {
        "keys" => None,
        "register-key" => Some("--confirm-probe-registration-write"),
        "send" => Some("--confirm-probe-send"),
        "receive" => Some("--confirm-local-receipt-write"),
        "inspect" => Some("--confirm-local-state-access"),
        _ => return Err("unlisted probe operation".into()),
    };
    let mut flags = BTreeMap::new();
    let mut confirmed = false;
    while let Some(flag) = items.next() {
        if flag.starts_with("--confirm-") {
            if Some(flag.as_str()) != confirm || confirmed {
                return Err("unexpected or repeated confirmation".into());
            }
            confirmed = true;
            continue;
        }
        let allowed = [
            "--node-dir",
            "--app-socket",
            "--origin",
            "--app-token-file",
            "--signer-socket",
        ];
        if !allowed.contains(&flag.as_str())
            && !(matches!(op.as_str(), "keys" | "register-key") && flag == "--record")
            && !(matches!(op.as_str(), "inspect" | "send" | "receive") && flag == "--plan")
            && !(op == "send" && flag == "--payload-file")
        {
            return Err("unknown probe option".into());
        }
        let value = items.next().ok_or("missing option value")?;
        if flags.insert(flag, value).is_some() {
            return Err("repeated probe option".into());
        }
    }
    if confirm.is_some() && !confirmed {
        return Err("operation requires its explicit confirmation flag".into());
    }
    for key in [
        "--node-dir",
        "--app-socket",
        "--origin",
        "--app-token-file",
        "--signer-socket",
    ] {
        if !flags.contains_key(key) {
            return Err("missing probe connection option".into());
        }
    }
    if !flags.contains_key(if matches!(op.as_str(), "keys" | "register-key") {
        "--record"
    } else {
        "--plan"
    }) || op == "send" && !flags.contains_key("--payload-file")
    {
        return Err("missing probe input file".into());
    }
    Ok(Args { op, flags })
}
impl Args {
    fn value(&self, k: &str) -> Result<&str, String> {
        self.flags
            .get(k)
            .map(String::as_str)
            .ok_or_else(|| "missing option".into())
    }
    fn path(&self, k: &str) -> Result<PathBuf, String> {
        Ok(PathBuf::from(self.value(k)?))
    }
}
fn exclusive_marker(node: &std::path::Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    use std::{
        fs::{File, OpenOptions},
        io::Write,
        os::unix::fs::OpenOptionsExt,
    };
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(node.join(name))
        .map_err(|_| "registration marker exists/unavailable: inspect; never retry")?;
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .map_err(|_| "registration marker uncertain; never retry")?;
    File::open(node)
        .and_then(|f| f.sync_all())
        .map_err(|_| "registration marker durability uncertain; never retry".into())
}
async fn run() -> Result<(), String> {
    let args = parse(std::env::args().skip(1))?;
    let plan: Option<ProbePlan> = if args.flags.contains_key("--plan") {
        Some(read_private_json(&args.path("--plan")?)?)
    } else {
        None
    };
    if let Some(p) = &plan {
        p.validate()?;
    }
    let record: CeremonyRecord = match &plan {
        Some(p) => p.record.clone(),
        None => read_private_json(&args.path("--record")?)?,
    };
    validate_record(&record)?;
    let node = args.path("--node-dir")?;
    let ctx = node_service::pinned_context(&node).map_err(|_| "private node context refused")?;
    if ctx.proposal_action != record.proposal_action
        || ctx.session_id != record.spec.session_id
        || !record.spec.contains(&ctx.worker_agent)
    {
        return Err("node/record mismatch".into());
    }
    let pin = ConductorPin {
        app_id: record.installed_app_id.clone(),
        role: "mpc".into(),
        dna_hash: record.dna_hash.clone(),
        node: ctx,
    };
    let signer = UnixMpcSigner::new(args.path("--signer-socket")?, pin.clone())?;
    let mut transport = SignedAppTransport {
        addr: parse_local_app_socket(args.value("--app-socket")?).map_err(str::to_owned)?,
        origin: args.value("--origin")?.to_owned(),
        token_file: args.path("--app-token-file")?,
        pin,
        signer,
    };
    // Check proposal protocol, full spec and acceptance BEFORE any key access.
    transport.verify_probe_session(&record).await?;
    let observed = transport.get_encryption_keys().await?;
    if args.op == "keys" {
        println!("UNAPPROVED conductor observations; independently review before creating pins:");
        println!(
            "{}",
            serde_json::to_string(&observed).map_err(|_| "public evidence encoding")?
        );
        return Ok(());
    }
    if args.op == "register-key" {
        let me = transport.pin.node.worker_agent.clone();
        if observed.iter().any(|k| k.author == me) {
            return Err("existing own registration: reconcile; never register again".into());
        }
        let dna = record
            .dna_hash
            .as_slice()
            .try_into()
            .map_err(|_| "invalid DNA")?;
        let public = node_service::transport_public_key(&node, dna, false)
            .map_err(|_| "retained key recovery refused")?;
        let marker =
            serde_json::to_vec(&(record.clone(), &me, public)).map_err(|_| "marker encoding")?;
        exclusive_marker(&node, "probe-registration-attempt.json", &marker)?;
        let action = transport
            .register_key(public)
            .await
            .map_err(|_| "registration UNCERTAIN: inspect; never retry")?;
        let after = transport
            .get_encryption_keys()
            .await
            .map_err(|_| "registration readback UNCERTAIN: inspect; never retry")?;
        let own: Vec<_> = after.iter().filter(|k| k.author == me).collect();
        if action.len() != 39
            || own.len() != 1
            || own[0].action != action
            || own[0].public_key != public
        {
            return Err("registration readback mismatch: inspect; never retry".into());
        }
        exclusive_marker(
            &node,
            "probe-registration-receipt.json",
            &serde_json::to_vec(&own[0]).map_err(|_| "receipt encoding")?,
        )?;
        println!("PASS: retained public key registered/read back; independent pin approval still required");
        return Ok(());
    }
    let p = plan.ok_or("missing plan")?;
    let mut endpoint = ProbeEndpoint::open_node(p.clone(), &node, &observed)?;
    let hex = |bytes: [u8; 32]| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() };
    println!("message_id_hex={}", hex(p.message_id()?));
    println!("plan_digest_hex={}", hex(p.digest()?));
    match args.op.as_str() {
        "inspect" => match endpoint.attempt()? {
            Some(a) => println!(
                "attempt={} (pending/uncertain are terminal; no retry)",
                a.state
            ),
            None => println!("no outbound attempt recorded"),
        },
        "send" => {
            let bytes: Vec<u8> = read_private_json(&args.path("--payload-file")?)?;
            let bytes = zeroize::Zeroizing::new(bytes);
            let receipt = endpoint.send_once(&mut transport, &bytes).await?;
            println!("PASS: remote storage acknowledged; already_stored={}; native decryption must be checked separately",receipt.already_stored);
        }
        "receive" => {
            let inbox = transport.get_inbox().await?;
            let mut found = false;
            for env in &inbox {
                let result = endpoint.receive(env)?;
                found = true;
                println!("authenticated probe receipt={result:?}");
            }
            if !found {
                return Err("no probe in recipient inbox".into());
            }
            println!(
                "PASS: retained native key verified approved probe digest (no plaintext printed)"
            );
        }
        _ => return Err("unlisted probe operation".into()),
    }
    Ok(())
}
#[tokio::main]
async fn main() {
    holochain_mpc_dkg_worker::notice::exit_on_help("mpc-transport-probe", "Transport probe. See docs/V040_PHASE5C_C_TRANSPORT_PROBE.md.");
    if run().await.is_err() {
        eprintln!("FAIL: probe refused or outcome uncertain; inspect state; do not retry a write");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(op: &str) -> Vec<String> {
        [
            op,
            "--node-dir",
            "/tmp/node",
            "--app-socket",
            "127.0.0.1:1",
            "--origin",
            "http://localhost:1",
            "--app-token-file",
            "/tmp/token",
            "--signer-socket",
            "/tmp/signer",
            "--plan",
            "/tmp/plan",
        ]
        .map(str::to_owned)
        .to_vec()
    }
    #[test]
    fn writes_require_exact_confirmation_and_no_arbitrary_operations() {
        for op in ["send", "receive", "inspect"] {
            assert!(parse(args(op).into_iter()).is_err());
        }
        let mut a = args("send");
        a.extend(["--payload-file", "/tmp/payload", "--confirm-probe-send"].map(str::to_owned));
        assert!(parse(a.clone().into_iter()).is_ok());
        a.push("--confirm-probe-send".into());
        assert!(parse(a.into_iter()).is_err());
        assert!(parse(args("dkg").into_iter()).is_err());
        let mut a = args("receive");
        a.push("--confirm-probe-send".into());
        assert!(parse(a.into_iter()).is_err());
    }
}
