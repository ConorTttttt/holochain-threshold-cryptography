//! v0.3.9 experimental conductor-facing adapter for independent MPC nodes.
//!
//! This library is NOT a Holochain websocket client. A TRUSTED, authenticated
//! app interface must call the local MPC zome's `get_inbox`,
//! `get_encryption_key_bindings`, and `send_protocol_message` externs, passing
//! ONLY their decoded results here. A caller that can fabricate those results
//! or read the per-node HMAC key can impersonate the conductor. Do not use for
//! valuable keys or treat it as proof of source-chain author identity.
//!
//! The bridge is one connection for one ceremony: HMAC-authenticated Unix IPC,
//! local agent/proposal/session binding, strict inbound/outbound validation,
//! in-memory duplicate filtering and rejection of invalid messages.
use crate::ipc::{AuthChannel, AuthFrame, ChannelContext, Role};
use crate::node_service::{bridge_credentials, socket_path, MAX_IPC_LINE};
use crate::{Command, PeerKeyBinding, Reply};
use holochain_mpc_core::{Envelope, SealedPacket};
use holochain_mpc_frost_ed25519::Binding;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// Author and action MUST originate from an authenticated conductor zome
/// response, not from the remotely supplied DKG packet.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyEvidence {
    pub author: Vec<u8>,
    pub action: Vec<u8>,
    pub public_key: [u8; 32],
}

pub struct ConductorBridge {
    binding: Binding,
    context: ChannelContext,
    auth: AuthChannel,
    socket: UnixStream,
    reader: BufReader<UnixStream>,
    /// In-memory dedup only. The worker's encrypted journal prevents unsafe
    /// replay after process termination by permanently rejecting restart.
    delivered: BTreeMap<(Vec<u8>, u32, u64), Envelope>,
}

fn invalid(msg: &'static str) -> String { msg.to_owned() }

impl ConductorBridge {
    /// Construct only after checking the conductor app authentication and
    /// pinning the local cell's AgentPubKey and the exact proposal ActionHash.
    pub fn connect(dir: &Path, expected: ChannelContext, binding: Binding) -> Result<Self, String> {
        // Do not accept a deserialized Binding without revalidating its spec.
        Binding::new(binding.proposal_action.clone(), binding.spec.clone())
            .map_err(|e| e.to_string())?;
        expected.validate()?;
        if binding.proposal_action != expected.proposal_action ||
           binding.spec.session_id != expected.session_id ||
           !binding.spec.contains(&expected.worker_agent) {
            return Err(invalid("conductor cell, proposal and worker ceremony do not match"));
        }
        let (pinned, key) = bridge_credentials(dir).map_err(|e| e.to_string())?;
        if pinned != expected { return Err(invalid("node state is pinned to another conductor cell")); }
        let auth = AuthChannel::new(*key, pinned.clone(), Role::Host)?;
        let socket = UnixStream::connect(socket_path(dir)).map_err(|e| e.to_string())?;
        socket.set_read_timeout(Some(Duration::from_secs(10))).map_err(|e| e.to_string())?;
        socket.set_write_timeout(Some(Duration::from_secs(10))).map_err(|e| e.to_string())?;
        let reader = BufReader::new(socket.try_clone().map_err(|e| e.to_string())?);
        Ok(Self { binding, context: pinned, auth, socket, reader,
            delivered: BTreeMap::new() })
    }

    /// Tear down both halves of the authenticated IPC connection when the
    /// relay cannot continue. The native service then durably aborts a running
    /// ceremony on EOF. If the service was killed instead, the existing
    /// `running` tombstone still forbids resumption.
    pub fn abort_connection(&mut self) -> Result<(), String> {
        self.socket.shutdown(std::net::Shutdown::Both).map_err(|e| e.to_string())
    }

    fn command(&mut self, cmd: Command) -> Result<Reply, String> {
        let frame = self.auth.seal(cmd)?;
        let data = serde_json::to_vec(&frame).map_err(|e| e.to_string())?;
        if data.len() + 1 > MAX_IPC_LINE { return Err(invalid("oversized IPC command")); }
        self.socket.write_all(&data).map_err(|e| e.to_string())?;
        self.socket.write_all(b"\n").map_err(|e| e.to_string())?;
        self.socket.flush().map_err(|e| e.to_string())?;
        // Bound the reply BEFORE allocating an untrusted line.
        let mut line = Vec::new();
        let count = (&mut self.reader).take((MAX_IPC_LINE + 1) as u64)
            .read_until(b'\n', &mut line).map_err(|e| e.to_string())?;
        if count == 0 || count > MAX_IPC_LINE || line.last() != Some(&b'\n') {
            return Err(invalid("worker closed connection or invalid IPC reply"));
        }
        let reply: AuthFrame<Reply> = serde_json::from_slice(&line).map_err(|e| e.to_string())?;
        let body = self.auth.open(reply)?;
        if matches!(body, Reply::Error { .. }) { return Err(invalid("worker rejected authenticated command")); }
        Ok(body)
    }

    pub fn initialize(&mut self) -> Result<([u8; 32], Vec<Envelope>), String> {
        let reply = self.command(Command::Init {
            binding: self.binding.clone(), local: self.context.worker_agent.clone(),
        })?;
        let Reply::Initialized { local_public_key, outbound } = reply
            else { return Err(invalid("wrong worker initialize reply")); };
        self.validate_outbound(&outbound)?;
        Ok((local_public_key, outbound))
    }

    /// Check the complete set of author-signed binding records obtained from
    /// `get_encryption_key_bindings`, rejecting missing or forked records.
    /// This does NOT validate source-chain signatures independently; the app
    /// interface and Holochain zome response must already be authenticated.
    pub fn pins_from_conductor(&self, records: &[KeyEvidence], my_key: [u8; 32])
        -> Result<Vec<PeerKeyBinding>, String>
    {
        if records.len() != self.binding.spec.participants.len() {
            return Err(invalid("missing, duplicate or forked DKG encryption key registrations"));
        }
        let mut seen = BTreeSet::new();
        let mut pins = Vec::new();
        for r in records {
            if !self.binding.spec.contains(&r.author) || r.action.len() != 39 ||
               r.public_key == [0_u8; 32] || !seen.insert(r.author.clone()) {
                return Err(invalid("invalid, forged or duplicate key binding"));
            }
            pins.push(PeerKeyBinding { member: r.author.clone(),
                public_key: r.public_key, action: r.action.clone() });
        }
        if !seen.iter().eq(self.binding.spec.participants.iter()) ||
           records.iter().find(|r| r.author == self.context.worker_agent)
               .map(|r| r.public_key) != Some(my_key) {
            return Err(invalid("conductor encryption-key roster disagrees with local worker"));
        }
        pins.sort_by(|a, b| a.member.cmp(&b.member));
        Ok(pins)
    }

    /// Validate outbound worker-created envelopes *before* using the local
    /// cell's `send_protocol_message`. This endpoint constructs the actual
    /// transport envelope under Holochain's agent identity.
    pub fn validate_outbound(&self, outbound: &[Envelope]) -> Result<(), String> {
        for env in outbound {
            env.validate_against(&self.binding.spec).map_err(|e| e.to_string())?;
            if env.sender != self.context.worker_agent ||
               env.recipient.as_ref().map_or(true, |p| p == &self.context.worker_agent) {
                return Err(invalid("worker outbound identity or destination invalid"));
            }
            if env.round == 3 {
                let sealed: SealedPacket = serde_json::from_slice(&env.payload)
                    .map_err(|_| invalid("plaintext FROST Round-2 outbound is forbidden"))?;
                if !sealed.structurally_valid() { return Err(invalid("malformed sealed DKG packet")); }
            }
        }
        Ok(())
    }

    /// Forward ONE envelope from the recipient cell's trusted `get_inbox`
    /// response. Caller must not substitute untrusted caller-supplied JSON.
    /// The sender used by IPC comes only from the zome-validated inbox entry.
    pub fn deliver_from_local_inbox(&mut self, env: Envelope) -> Result<Vec<Envelope>, String> {
        env.validate_received(&self.binding.spec, &self.context.worker_agent, &env.sender)
            .map_err(|e| e.to_string())?;
        if env.recipient.as_deref() != Some(self.context.worker_agent.as_slice()) {
            return Err(invalid("inbox delivery is not addressed to this local conductor cell"));
        }
        if env.round == 3 {
            let sealed: SealedPacket = serde_json::from_slice(&env.payload)
                .map_err(|_| invalid("unencrypted Round-2 inbox payload"))?;
            if !sealed.structurally_valid() { return Err(invalid("invalid Round-2 ciphertext container")); }
        }
        let id = (env.sender.clone(), env.round, env.sequence);
        if let Some(previous) = self.delivered.get(&id) {
            if previous != &env { return Err(invalid("equivocating inbox record")); }
            return Ok(Vec::new()); // cumulative get_inbox calls are idempotent
        }
        let reply = self.command(Command::Deliver {
            authenticated_sender: env.sender.clone(), envelope: env.clone(),
        })?;
        let Reply::Delivered { outbound } = reply
            else { return Err(invalid("wrong delivery response")); };
        self.validate_outbound(&outbound)?;
        self.delivered.insert(id, env);
        Ok(outbound)
    }

    pub fn attest(&mut self) -> Result<Vec<Envelope>, String> {
        let Reply::Attesting { outbound } = self.command(Command::Attest)?
            else { return Err(invalid("wrong attestation reply")); };
        self.validate_outbound(&outbound)?;
        Ok(outbound)
    }

    // INV-13: An authenticated DHT observation is NOT independent operator
    // approval of a recipient encryption key. No authenticated, out-of-band
    // approval channel is specified for the current signed relay.
    // Keep the live secret-bearing boundary CLOSED until that contract and its
    // ceremony-scoped key roster are approved and implemented.
    fn require_round_two_key_approval() -> Result<(), &'static str> {
        Err("INV-13: independently authorised Round-2 encryption-key roster unavailable; live delivery blocked")
    }

    /// Never accept arbitrary caller-constructed pins at the Round-2 gate.
    /// Use the exact complete roster observed in the trusted Holochain zome
    /// response and pin the worker's own secret-derived key to that record.
    pub fn round_two(&mut self, records: &[KeyEvidence], my_key: [u8;32])
        -> Result<([u8;32], Vec<Envelope>), String>
    {
        Self::require_round_two_key_approval().map_err(str::to_owned)?;
        let pins = self.pins_from_conductor(records, my_key)?;
        let Reply::RoundTwo { transcript_hash, outbound } =
            self.command(Command::BeginRoundTwo { pinned_keys: pins })?
            else { return Err(invalid("wrong Round-2 reply")); };
        self.validate_outbound(&outbound)?;
        Ok((transcript_hash, outbound))
    }

    pub fn finalize(&mut self) -> Result<holochain_mpc_security::activation::GroupDescriptor, String> {
        let Reply::Completed { descriptor } = self.command(Command::Finalize)?
            else { return Err(invalid("wrong completion reply")); };
        Ok(descriptor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use holochain_mpc_core::{commitment, SessionSpec};
    fn context() -> ChannelContext {
        ChannelContext { worker_agent: vec![1;39], proposal_action: vec![9;39],
            session_id: commitment("bridge-test-session", b"session"), channel_id: [4;32] }
    }
    fn binding() -> Binding {
        let ctx = context();
        Binding::new(ctx.proposal_action, SessionSpec {
            session_id: ctx.session_id, application_id:"org.example.conductor.test".into(),
            protocol_id:"frost-ed25519".into(), protocol_version:1,
            context_hash:commitment("bridge-test-context", b"session"),
            participants:vec![vec![1;39],vec![2;39],vec![3;39]], threshold:2, max_round:6,
        }).unwrap()
    }
    fn offline_bridge() -> ConductorBridge {
        // We can exercise local validation without a live worker via an
        // unconnected socket pair; no protocol commands are sent in this test.
        let (socket, _peer) = UnixStream::pair().unwrap();
        ConductorBridge { binding: binding(), context: context(),
            auth: AuthChannel::new([7;32], context(), Role::Host).unwrap(),
            reader: BufReader::new(socket.try_clone().unwrap()), socket,
            delivered: BTreeMap::new() }
    }
    #[test]
    fn rejects_forged_outbound_and_plaintext_round_two() {
        let bridge = offline_bridge();
        let spec = &bridge.binding.spec;
        let good = Envelope::new(spec, vec![1;39], Some(vec![2;39]), 1, 1, b"announce".to_vec()).unwrap();
        bridge.validate_outbound(&[good]).unwrap();
        let forged = Envelope::new(spec, vec![2;39], Some(vec![1;39]), 1, 1, b"x".to_vec()).unwrap();
        assert!(bridge.validate_outbound(&[forged]).is_err());
        let plaintext = Envelope::new(spec, vec![1;39], Some(vec![2;39]), 3, 1, b"secret".to_vec()).unwrap();
        assert!(bridge.validate_outbound(&[plaintext]).is_err());
    }
    #[test]
    fn exact_key_evidence_set_pinned_to_local_worker() {
        let bridge = offline_bridge();
        let evidence: Vec<_> = (1..=3).map(|i| KeyEvidence {
            author:vec![i;39], action:vec![i+10;39], public_key:[i;32],
        }).collect();
        assert_eq!(bridge.pins_from_conductor(&evidence, [1;32]).unwrap().len(), 3);
        let mut duplicate = evidence.clone(); duplicate[1] = duplicate[0].clone();
        assert!(bridge.pins_from_conductor(&duplicate, [1;32]).is_err());
        assert!(bridge.pins_from_conductor(&evidence, [9;32]).is_err());
        assert!(bridge.pins_from_conductor(&evidence[..2], [1;32]).is_err());
        let mut fork = evidence.clone(); fork.push(evidence[0].clone());
        assert!(bridge.pins_from_conductor(&fork, [1;32]).is_err());
    }
    #[test]
    fn rejects_wrong_recipient_cross_session_and_unsealed_inbox() {
        let mut bridge = offline_bridge();
        let spec = bridge.binding.spec.clone();
        let to_peer = Envelope::new(&spec, vec![2;39], Some(vec![3;39]), 1, 1,
            b"announcement".to_vec()).unwrap();
        assert!(bridge.deliver_from_local_inbox(to_peer).is_err());
        let wrong_sender = Envelope::new(&spec, vec![1;39], Some(vec![2;39]), 1, 1,
            b"announcement".to_vec()).unwrap();
        assert!(bridge.deliver_from_local_inbox(wrong_sender).is_err());
        let bad_ciphertext = Envelope::new(&spec, vec![2;39], Some(vec![1;39]), 3, 1,
            b"not an encrypted share".to_vec()).unwrap();
        assert!(bridge.deliver_from_local_inbox(bad_ciphertext).is_err());
        let mut cross_session = Envelope::new(&spec, vec![2;39], Some(vec![1;39]), 1, 1,
            b"announcement".to_vec()).unwrap();
        cross_session.session_id = [5;32];
        assert!(bridge.deliver_from_local_inbox(cross_session).is_err());
        let mut corrupted_hash = Envelope::new(&spec, vec![2;39], Some(vec![1;39]), 1, 1,
            b"announcement".to_vec()).unwrap();
        corrupted_hash.payload_hash = [0;32];
        assert!(bridge.deliver_from_local_inbox(corrupted_hash).is_err());
    }
    #[test]
    fn cumulative_local_inbox_is_idempotent_and_equivocation_is_rejected() {
        let mut bridge = offline_bridge();
        let spec = bridge.binding.spec.clone();
        let original = Envelope::new(&spec, vec![2;39], Some(vec![1;39]), 1, 1,
            b"original announcement".to_vec()).unwrap();
        bridge.delivered.insert((vec![2;39], 1, 1), original.clone());
        assert!(bridge.deliver_from_local_inbox(original).unwrap().is_empty());
        let conflicting = Envelope::new(&spec, vec![2;39], Some(vec![1;39]), 1, 1,
            b"equivocating announcement".to_vec()).unwrap();
        assert!(bridge.deliver_from_local_inbox(conflicting).is_err());
    }
    #[test]
    fn wrong_conductor_context_is_rejected_before_connecting() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("node");
        crate::node_service::provision(&dir, context()).unwrap();
        let mut wrong = context(); wrong.worker_agent = vec![2;39];
        assert!(ConductorBridge::connect(&dir, wrong, binding()).is_err());
        let mut wrong = context(); wrong.channel_id = [5;32];
        assert!(ConductorBridge::connect(&dir, wrong, binding()).is_err());
    }
}
