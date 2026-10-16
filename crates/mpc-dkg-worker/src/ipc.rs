//! v0.3.6: authenticated, ceremony-bound local IPC **for test-only provisioning**.
//!
//! The host provisions a fresh 256-bit symmetric secret over a private pipe.
//! This protocol authenticates both commands and replies and enforces strict
//! sequence numbers and context binding. It does NOT attest Holochain source
//! chain provenance, protect against a compromised host, or safely bootstrap
//! secrets on arbitrary OS endpoints. Not production-ready transport.
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};
use std::path::PathBuf;

type HmacSha256 = Hmac<Sha256>;
const VERSION: u8 = 1;
const DOMAIN: &str = "holochain-mpc-local-ipc-v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelContext {
    pub worker_agent: Vec<u8>,
    pub proposal_action: Vec<u8>,
    pub session_id: [u8; 32],
    pub channel_id: [u8; 32],
}
impl ChannelContext {
    pub fn validate(&self) -> Result<(), String> {
        if self.worker_agent.len() != 39 || self.proposal_action.len() != 39 ||
           self.session_id == [0; 32] || self.channel_id == [0; 32] {
            return Err("invalid authenticated IPC context".into());
        }
        Ok(())
    }
}

/// TEST-ONLY bootstrap. Private anonymous pipes and secure OS process
/// management are mandatory. Anyone observing this frame learns the key.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestBootstrap {
    pub context: ChannelContext,
    pub secret: [u8; 32],
    /// Opt-in test-only durability. Older v0.3.6 fixtures remain supported,
    /// but production operation must NOT run without a durable ceremony guard.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistence: Option<TestPersistence>,
}

/// TEST ONLY: supplies an independent database encryption key via the same
/// trusted private bootstrap pipe. Production needs OS/Lair-backed key access.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestPersistence {
    pub database_path: PathBuf,
    pub master_key: [u8; 32],
}
impl Drop for TestPersistence {
    fn drop(&mut self) { self.master_key.zeroize(); }
}
impl Drop for TestBootstrap {
    fn drop(&mut self) { self.secret.zeroize(); }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthFrame<T> {
    pub version: u8,
    pub context: ChannelContext,
    pub sequence: u64,
    pub body: T,
    pub tag: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
pub enum Role { Host, Worker }
impl Role {
    fn send_direction(self) -> &'static str { match self { Role::Host => "host-to-worker", Role::Worker => "worker-to-host" } }
    fn recv_direction(self) -> &'static str { match self { Role::Host => "worker-to-host", Role::Worker => "host-to-worker" } }
}

pub struct AuthChannel {
    secret: Zeroizing<[u8; 32]>,
    context: ChannelContext,
    role: Role,
    tx: u64,
    rx: u64,
}
impl AuthChannel {
    pub fn new(secret: [u8; 32], context: ChannelContext, role: Role) -> Result<Self, String> {
        context.validate()?;
        if secret == [0; 32] { return Err("unprovisioned IPC secret".into()); }
        Ok(Self { secret: Zeroizing::new(secret), context, role, tx: 0, rx: 0 })
    }
    fn tag<T: Serialize>(&self, direction: &str, sequence: u64, body: &T) -> Result<[u8; 32], String> {
        // Domain-separated encoded tuple. Both peers reserialize after parsing,
        // avoiding dependence on raw JSON key ordering or whitespace.
        let bytes = serde_json::to_vec(&(DOMAIN, direction, VERSION, &self.context, sequence, body))
            .map_err(|_| "unable to encode authenticated IPC frame")?;
        let mut mac = HmacSha256::new_from_slice(&self.secret[..])
            .map_err(|_| "invalid authentication key")?;
        mac.update(&bytes);
        let digest = mac.finalize().into_bytes();
        let mut tag = [0_u8; 32];
        tag.copy_from_slice(&digest);
        Ok(tag)
    }
    pub fn seal<T: Serialize>(&mut self, body: T) -> Result<AuthFrame<T>, String> {
        let next = self.tx.checked_add(1).ok_or("IPC sequence exhausted")?;
        let tag = self.tag(self.role.send_direction(), next, &body)?;
        self.tx = next;
        Ok(AuthFrame { version: VERSION, context: self.context.clone(), sequence: next, body, tag })
    }
    pub fn open<T: Serialize>(&mut self, frame: AuthFrame<T>) -> Result<T, String> {
        if frame.version != VERSION || frame.context != self.context ||
            self.rx.checked_add(1) != Some(frame.sequence) {
            return Err("IPC version, ceremony context or sequence mismatch".into());
        }
        let bytes = serde_json::to_vec(&(DOMAIN, self.role.recv_direction(), VERSION,
            &self.context, frame.sequence, &frame.body))
            .map_err(|_| "invalid IPC body")?;
        let mut mac = HmacSha256::new_from_slice(&self.secret[..])
            .map_err(|_| "invalid authentication key")?;
        mac.update(&bytes);
        mac.verify_slice(&frame.tag).map_err(|_| "IPC authentication failed".to_string())?;
        self.rx = frame.sequence;
        Ok(frame.body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn context() -> ChannelContext { ChannelContext {
        worker_agent: vec![1; 39], proposal_action: vec![9; 39],
        session_id: [3; 32], channel_id: [4; 32] } }
    fn peers() -> (AuthChannel, AuthChannel) {
        (AuthChannel::new([7;32], context(), Role::Host).unwrap(),
         AuthChannel::new([7;32], context(), Role::Worker).unwrap())
    }
    #[test]
    fn duplex_mac_and_monotonic_sequences() {
        let (mut host, mut worker) = peers();
        assert_eq!(worker.open(host.seal("begin").unwrap()).unwrap(), "begin");
        assert_eq!(host.open(worker.seal("accepted").unwrap()).unwrap(), "accepted");
        assert_eq!(worker.open(host.seal("round2").unwrap()).unwrap(), "round2");
    }
    #[test]
    fn replay_and_out_of_order_fail_closed() {
        let (mut host, mut worker) = peers();
        let first = host.seal("one").unwrap();
        let second = host.seal("two").unwrap();
        assert!(worker.open(second).is_err());
        let first_bytes = serde_json::to_vec(&first).unwrap();
        let duplicate: AuthFrame<String> = serde_json::from_slice(&first_bytes).unwrap();
        assert_eq!(worker.open(first).unwrap(), "one");
        assert!(worker.open(duplicate).is_err());
    }
    #[test]
    fn tamper_wrong_key_wrong_direction_and_ceremony_rejected() {
        let (mut host, mut worker) = peers();
        let valid = host.seal("stage1").unwrap();
        let mut tampered: AuthFrame<String> = serde_json::from_slice(&serde_json::to_vec(&valid).unwrap()).unwrap();
        tampered.body = "stage3".into();
        assert!(worker.open(tampered).is_err());
        let mut other_worker = AuthChannel::new([8;32], context(), Role::Worker).unwrap();
        let copy: AuthFrame<String> = serde_json::from_slice(&serde_json::to_vec(&valid).unwrap()).unwrap();
        assert!(other_worker.open(copy).is_err());
        let mut swapped = context(); swapped.proposal_action = vec![2;39];
        let mut other_ceremony = AuthChannel::new([7;32], swapped, Role::Worker).unwrap();
        let copy: AuthFrame<String> = serde_json::from_slice(&serde_json::to_vec(&valid).unwrap()).unwrap();
        assert!(other_ceremony.open(copy).is_err());
        assert!(host.open(valid).is_err()); // A host may not authenticate its own outbound command as a reply.
    }
    #[test]
    fn invalid_bootstrap_fails() {
        assert!(AuthChannel::new([0;32], context(), Role::Host).is_err());
        let mut c = context(); c.worker_agent.clear();
        assert!(AuthChannel::new([1;32], c, Role::Host).is_err());
    }
}
