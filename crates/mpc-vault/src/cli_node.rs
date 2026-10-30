//! The real node: runs the existing operator binaries as processes and reads
//! their results. No protocol or signing logic lives here.
//!   make-intent / approve-intent / signing-status / write-signing-policy
//!       -> `mpc-phase5c-provision`
//!   signer service -> `mpc-lair-signer --signing-profile`
//!   signing        -> `mpc-sign`
use crate::node::*;
use crate::proc::Child;
use crate::util::holochain_b64;
use base64::Engine as _;
use serde::Deserialize;
use serde_json::Value;
use std::ffi::OsString;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// Directory holding mpc-phase5c-provision, mpc-lair-signer and mpc-sign.
    pub bin_dir: PathBuf,
    pub agent_b64: String,
    pub record: PathBuf,
    pub state_dir: PathBuf,
    pub caps_dir: PathBuf,
    pub app_port: u16,
    pub origin: String,
    pub app_token_file: PathBuf,
    pub lair_root: PathBuf,
    pub installed_app_id: String,
    pub dna_hex_file: PathBuf,
    /// Disposable rehearsals only: a 0600 file with a throwaway Lair passphrase.
    /// Absent: the operator types the passphrase on the service's terminal.
    pub passphrase_file: Option<PathBuf>,
}

pub struct CliNode {
    cfg: NodeConfig,
    local: Vec<u8>,
}

fn agent_raw(b64: &str) -> Result<Vec<u8>, String> {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b64.strip_prefix('u').ok_or("agent must start with u")?)
        .map_err(|_| "agent is not base64url")?;
    if raw.len() != 39 { return Err("agent key must be 39 bytes".into()); }
    Ok(raw)
}

fn bytes(v: &Value) -> Option<Vec<u8>> {
    v.as_array()?.iter().map(|x| x.as_u64().and_then(|n| u8::try_from(n).ok())).collect()
}

/// Write a private file; replace atomically if it exists.
fn write_private(path: &Path, data: &[u8]) -> Result<(), NodeError> {
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    f.write_all(data).and_then(|_| f.sync_all()).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
    Ok(())
}

impl CliNode {
    pub fn new(cfg: NodeConfig) -> Result<Self, String> {
        let local = agent_raw(&cfg.agent_b64)?;
        for p in [&cfg.bin_dir, &cfg.record, &cfg.state_dir, &cfg.caps_dir, &cfg.app_token_file, &cfg.lair_root, &cfg.dna_hex_file] {
            if !p.is_absolute() { return Err(format!("{} must be an absolute path", p.display())); }
        }
        for tool in ["mpc-phase5c-provision", "mpc-lair-signer", "mpc-sign"] {
            if !cfg.bin_dir.join(tool).is_file() { return Err(format!("{tool} not found in {}", cfg.bin_dir.display())); }
        }
        if let Some(p) = &cfg.passphrase_file {
            let info = std::fs::symlink_metadata(p).map_err(|e| format!("passphrase file: {e}"))?;
            if !info.is_file() || info.permissions().mode() & 0o077 != 0 || info.uid() != unsafe { libc::geteuid() } {
                return Err("the passphrase file must be a regular 0600 file owned by this user".into());
            }
        }
        Ok(Self { cfg, local })
    }

    fn passphrase(&self) -> Result<Option<Vec<u8>>, NodeError> {
        let Some(p) = &self.cfg.passphrase_file else { return Ok(None) };
        let mut s = std::fs::read(p).map_err(|e| format!("cannot read the passphrase file: {e}"))?;
        while s.last().map_or(false, |b| *b == b'\n' || *b == b'\r') { s.pop(); }
        Ok(Some(s))
    }

    fn bin(&self, name: &str) -> OsString { self.cfg.bin_dir.join(name).into_os_string() }

    /// `--agent-b64 ... --lair-root` as every conductor-facing subcommand takes them.
    fn conductor_args(&self) -> Vec<OsString> {
        let c = &self.cfg;
        vec!["--agent-b64".into(), c.agent_b64.clone().into(), "--app-port".into(), c.app_port.to_string().into(),
            "--origin".into(), c.origin.clone().into(), "--app-token-file".into(), c.app_token_file.clone().into(),
            "--lair-root".into(), c.lair_root.clone().into()]
    }

    /// Run a provision subcommand that needs no Lair (local files only).
    fn run_local(&self, args: &[OsString]) -> Result<String, NodeError> {
        let mut argv = vec![self.bin("mpc-phase5c-provision")];
        argv.extend_from_slice(args);
        let mut child = Child::spawn(&argv, None).map_err(|e| format!("cannot start the tool: {e}"))?;
        let status = child.wait(Duration::from_secs(60)).ok_or("the tool did not finish in 60 s")?;
        let text = child.text();
        if status.success() { Ok(text) } else { Err(NodeError(format!("tool failed ({status}): {}", text.trim()))) }
    }

    /// Run a provision subcommand that unlocks Lair (passphrase prompt).
    fn run_lair(&self, args: &[OsString], timeout: Duration) -> Result<String, NodeError> {
        let mut argv = vec![self.bin("mpc-phase5c-provision")];
        argv.extend_from_slice(args);
        let mut child = Child::spawn(&argv, self.passphrase()?).map_err(|e| format!("cannot start the tool: {e}"))?;
        let status = child.wait(timeout).ok_or("the tool did not finish in time (is a passphrase waiting on the service terminal?)")?;
        let text = child.text();
        if status.success() { Ok(text) } else { Err(NodeError(format!("tool failed ({status}): {}", last_lines(&text)))) }
    }

    fn plan_file(&self, plan: &Value, work: &Path) -> Result<PathBuf, NodeError> {
        let path = work.join("plan.json");
        write_private(&path, &serde_json::to_vec(plan).map_err(|e| e.to_string())?)?;
        Ok(path)
    }
}

fn last_lines(text: &str) -> String {
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    lines[lines.len().saturating_sub(4)..].join(" | ")
}

fn os(parts: &[&dyn AsRef<std::ffi::OsStr>]) -> Vec<OsString> { parts.iter().map(|p| p.as_ref().to_owned()).collect() }

impl Node for CliNode {
    fn group(&self) -> Result<GroupInfo, NodeError> {
        let path = self.cfg.state_dir.join("group-descriptor.json");
        let raw = std::fs::read(&path).map_err(|e| format!("no completed group in {}: {e}", self.cfg.state_dir.display()))?;
        if raw.len() > 64 * 1024 { return Err("oversized group descriptor".into()); }
        let d: Value = serde_json::from_slice(&raw).map_err(|e| format!("invalid group descriptor: {e}"))?;
        let bad = || NodeError("invalid group descriptor".into());
        let key: [u8; 32] = bytes(&d["group_verifying_key"]).and_then(|b| b.try_into().ok()).ok_or_else(bad)?;
        let members = d["spec"]["participants"].as_array().ok_or_else(bad)?.iter().map(|p| bytes(p).ok_or_else(bad)).collect::<Result<Vec<_>, _>>()?;
        let threshold = d["spec"]["threshold"].as_u64().and_then(|t| u16::try_from(t).ok()).ok_or_else(bad)?;
        if !members.contains(&self.local) { return Err("this agent is not a member of the node's group".into()); }
        Ok(GroupInfo { group_key: key, members, threshold, local: self.local.clone() })
    }

    fn make_plan(&self, message: &[u8], selected: &[Vec<u8>], work: &Path) -> Result<Value, NodeError> {
        let (msg, sel, out) = (work.join("message.bin"), work.join("selected.txt"), work.join("plan.json"));
        write_private(&msg, message)?;
        write_private(&sel, selected.iter().map(|s| holochain_b64(s)).collect::<Vec<_>>().join("\n").as_bytes())?;
        let _ = std::fs::remove_file(&out); // make-intent creates it new
        self.run_local(&os(&[&"make-intent", &"--state-dir", &self.cfg.state_dir, &"--message-file", &msg,
            &"--selected-file", &sel, &"--out", &out]))?;
        serde_json::from_slice(&std::fs::read(&out).map_err(|e| e.to_string())?).map_err(|e| NodeError(format!("unreadable plan: {e}")))
    }

    fn approve(&self, plan: &Value, message: &[u8], work: &Path) -> Result<(), NodeError> {
        let plan_path = self.plan_file(plan, work)?;
        let msg = work.join("message.bin"); // this node's own copy, taken from the verified stored bytes
        write_private(&msg, message)?;
        let mut args = os(&[&"approve-intent"]);
        args.extend(self.conductor_args());
        args.extend(os(&[&"--record", &self.cfg.record, &"--plan", &plan_path, &"--message-file", &msg, &"--confirm-approval-write"]));
        let out = self.run_lair(&args, Duration::from_secs(600))?;
        if !out.contains("PASS: signing approval recorded") { return Err(NodeError(format!("approval was not confirmed: {}", last_lines(&out)))); }
        Ok(())
    }

    fn signing_status(&self, plan: &Value, work: &Path) -> Result<ApprovalStatus, NodeError> {
        let plan_path = self.plan_file(plan, work)?;
        let mut args = os(&[&"signing-status"]);
        args.extend(self.conductor_args());
        args.extend(os(&[&"--record", &self.cfg.record, &"--plan", &plan_path]));
        let out = self.run_lair(&args, Duration::from_secs(300))?;
        let view = PlanView::parse(plan)?;
        let activated = out.contains("activated=true");
        let mut approvals = Vec::new();
        for s in &view.selected {
            let b64 = holochain_b64(s);
            let line = out.lines().find(|l| l.contains(&b64)).ok_or("signing-status did not list every selected signer")?;
            approvals.push((s.clone(), line.trim_start().starts_with("approved")));
        }
        Ok(ApprovalStatus { activated, approvals })
    }

    fn sign(&self, plan: &Value, work: &Path, budget_secs: u64) -> Result<SignedOutput, NodeError> {
        let plan_path = self.plan_file(plan, work)?;
        let policy = work.join("signing-policy.json");
        // A second run in the same work dir would be a retry; write-signing-policy refuses to overwrite.
        self.run_local(&os(&[&"write-signing-policy", &"--record", &self.cfg.record, &"--plan", &plan_path,
            &"--state-dir", &self.cfg.state_dir, &"--caps-dir", &self.cfg.caps_dir, &"--out", &policy]))?;
        let (sock_dir, out_dir) = (work.join("s"), work.join("signed"));
        for d in [&sock_dir, &out_dir] {
            std::fs::create_dir(d).map_err(|e| format!("cannot create {} (a signing run already happened here?): {e}", d.display()))?;
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
        }
        let sock = sock_dir.join("sign.sock");
        if sock.as_os_str().len() > 100 { return Err(NodeError(format!("socket path too long ({}); use a shorter data_dir", sock.display()))); }
        let dna = std::fs::read_to_string(&self.cfg.dna_hex_file).map_err(|e| format!("cannot read the DNA hex file: {e}"))?;

        let signer_argv = os(&[&self.bin("mpc-lair-signer"), &"--signing-profile", &"--policy-file", &policy,
            &"--signer-socket", &sock, &"--lair-root", &self.cfg.lair_root]);
        let mut signer = Child::spawn(&signer_argv, self.passphrase()?).map_err(|e| format!("cannot start the signer: {e}"))?;
        if !signer.wait_for("Lair signer ready", Duration::from_secs(300)) {
            signer.kill();
            return Err(NodeError(format!("the signing signer did not become ready: {}", last_lines(&signer.text()))));
        }
        // Poll the other signer's approval for as long as the proposal lives.
        let interval_ms = (budget_secs * 1000 / 10_000).clamp(1_000, 60_000);
        let polls = (budget_secs * 1000 / interval_ms).clamp(1, 10_000);
        let sign_argv = os(&[&self.bin("mpc-sign"), &"--state-dir", &self.cfg.state_dir, &"--plan-file", &plan_path,
            &"--app-socket", &format!("127.0.0.1:{}", self.cfg.app_port), &"--origin", &self.cfg.origin,
            &"--app-token-file", &self.cfg.app_token_file, &"--installed-app-id", &self.cfg.installed_app_id,
            &"--dna-hex", &dna.trim(), &"--signer-socket", &sock, &"--poll-ms", &interval_ms.to_string(),
            &"--max-polls", &polls.to_string(), &"--out-dir", &out_dir]);
        let result = (|| {
            let mut sign = Child::spawn(&sign_argv, None).map_err(|e| format!("cannot start mpc-sign: {e}"))?;
            let Some(status) = sign.wait(Duration::from_secs(budget_secs + 180)) else {
                sign.kill();
                return Err(NodeError("mpc-sign did not finish in time and was stopped".into()));
            };
            if !status.success() { return Err(NodeError(format!("mpc-sign failed ({status}): {}", last_lines(&sign.text())))); }
            let sig = std::fs::read(out_dir.join("signature.bin")).map_err(|e| format!("no signature written: {e}"))?;
            let signed_message = std::fs::read(out_dir.join("signed-message.bin")).map_err(|e| format!("no signed-message.bin written: {e}"))?;
            if signed_message.len() > 64 * 1024 { return Err(NodeError("signed-message.bin is oversized".into())); }
            let signature = sig.try_into().map_err(|_| NodeError("signature.bin is not 64 bytes".into()))?;
            Ok(SignedOutput { signature, signed_message })
        })();
        signer.kill();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn agent_text_roundtrip() {
        let raw = [7_u8; 39];
        assert_eq!(agent_raw(&holochain_b64(&raw)).unwrap(), raw);
        assert!(agent_raw("nou").is_err() && agent_raw("uAAAA").is_err());
    }
    #[test]
    fn config_rejects_unknown_fields_and_relative_paths() {
        let bad = serde_json::json!({"bin_dir": "x", "agent_b64": "u", "record": "/r", "state_dir": "/s", "caps_dir": "/c", "app_port": 1,
            "origin": "o", "app_token_file": "/t", "lair_root": "/l", "installed_app_id": "a", "dna_hex_file": "/d", "extra": 1});
        assert!(serde_json::from_value::<NodeConfig>(bad).is_err());
    }
}
