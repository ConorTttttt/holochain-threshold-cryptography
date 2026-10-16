//! Security protocol *building blocks*, not a consensus service or full MPC runtime.
//! The caller authenticates *every* inbound sender from the Holochain transport,
//! pins encryption keys to signed membership records, persists the inbound event
//! log before acknowledgment, and feeds messages to this deterministic engine.
//! Do not use DHT gossip as proof of round-one agreement.
use holochain_mpc_core::{commitment, Envelope, ParticipantId, SessionSpec};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

pub mod sealed;
pub mod activation;

// Bound announcement bytes for serde_json's Vec<u8> array encoding and the
// mpc-core 64 KiB envelope cap. A future binary wire codec can raise this.
pub const MAX_ANNOUNCEMENT: usize = 8 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecurityError {
    Invalid(&'static str),
    Unauthorized,
    Equivocation,
    Aborted,
    NotReady,
    AttestationMismatch,
    Crypto,
}
impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self {
            Self::Invalid(m) => m,
            Self::Unauthorized => "authenticated sender or origin is not authorized",
            Self::Equivocation => "inconsistent authenticated broadcast; ceremony aborted",
            Self::Aborted => "ceremony aborted",
            Self::NotReady => "broadcast or attestations incomplete",
            Self::AttestationMismatch => "transcript attestations disagree; ceremony aborted",
            Self::Crypto => "authenticated encryption or decryption failed",
        })
    }
}
impl std::error::Error for SecurityError {}

/// Immutable wire messages. The sender field is NOT carried: adapters MUST
/// supply transport-authenticated provenance, not sender-controlled metadata.
/// `Announce` is sent only by `origin`; other members echo a commitment
/// to the exact bytes. Any disagreement causes an abort.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BroadcastMessage {
    Announce { package: Vec<u8> },
    Echo { origin: ParticipantId, package: Vec<u8> }, // legacy; expensive, retained for input compatibility
    /// Compact, origin- and ceremony-bound SHA-256 echo. Preferred for DKG.
    EchoDigest { origin: ParticipantId, package_digest: [u8; 32] },
    Attest { transcript_hash: [u8; 32] },
    Abort,
}

/// Session binding also includes the *exact* Holochain proposal ActionHash,
/// avoiding accidental transcript reuse if a session id is recycled.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ceremony {
    pub spec: SessionSpec,
    pub proposal_action: Vec<u8>,
}
impl Ceremony {
    pub fn validate(&self) -> Result<(), SecurityError> {
        self.spec.validate().map_err(|_| SecurityError::Invalid("invalid session"))?;
        if self.proposal_action.len() != 39 {
            return Err(SecurityError::Invalid("proposal action must be 39 raw bytes"));
        }
        Ok(())
    }
    pub fn fingerprint(&self) -> Result<[u8; 32], SecurityError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| SecurityError::Invalid("ceremony encoding failed"))?;
        Ok(commitment("mpc-security-ceremony-v1", &bytes))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct OriginState {
    direct: Option<Vec<u8>>,
    echoes: BTreeMap<ParticipantId, [u8; 32]>,
}

/// Replayable, deterministic echo-and-attest protocol with *unanimous* progress.
/// Every required participant must be reachable: this sacrifices liveness
/// under partitions or Byzantine withholding, deliberately fails closed, and
/// does NOT implement a general asynchronous Byzantine consensus primitive.
/// Intentionally NOT deserializable: a fabricated checkpoint could forge a
/// `VerifiedTranscript`. Restore only by reapplying a separately authenticated,
/// durable event log through `begin`, `receive_envelope`, and `attest`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EchoBroadcast {
    ceremony: Ceremony,
    local: ParticipantId,
    origins: BTreeMap<ParticipantId, OriginState>,
    attestations: BTreeMap<ParticipantId, [u8; 32]>,
    proposed_hash: Option<[u8; 32]>,
    aborted: bool,
}

/// The only public constructor is `EchoBroadcast::finalize`. No serde
/// deserialization, public fields, or arbitrary digest-based constructor.
/// This is a local proof-of-protocol-completion object, NOT a signed proof
/// accepted by other machines in isolation.
#[derive(Clone, Debug)]
pub struct VerifiedTranscript {
    ceremony: Ceremony,
    hash: [u8; 32],
    packages: BTreeMap<ParticipantId, Vec<u8>>,
}
impl VerifiedTranscript {
    pub fn hash(&self) -> [u8; 32] { self.hash }
    pub fn ceremony(&self) -> &Ceremony { &self.ceremony }
    pub fn package(&self, origin: &[u8]) -> Option<&[u8]> {
        self.packages.get(origin).map(Vec::as_slice)
    }
    pub fn packages(&self) -> &BTreeMap<ParticipantId, Vec<u8>> { &self.packages }
}

/// Name the actual safety/liveness guarantee; a fault-tolerant Byzantine
/// broadcast or asynchronous agreement protocol is NOT implemented here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BroadcastGuarantee {
    /// Every enrolled participant must echo and attest. Missing or conflicting
    /// contributions abort or block indefinitely; no Byzantine liveness claim.
    UnanimousAbort,
    /// Placeholder ONLY; asking for this returns an error rather than silently
    /// weakening the caller's security requirement.
    AsynchronousByzantineReliable,
}

/// Use length-prefix framing for each variable-length portion. This hash is
/// a wire commitment, NOT a digital signature: the receiver must authenticate
/// the forwarding agent independently.
pub fn dkg_package_digest(ceremony: &Ceremony, origin: &[u8], package: &[u8])
    -> Result<[u8; 32], SecurityError> {
    ceremony.validate()?;
    if !ceremony.spec.contains(origin) { return Err(SecurityError::Unauthorized); }
    if package.is_empty() || package.len() > MAX_ANNOUNCEMENT {
        return Err(SecurityError::Invalid("announcement size invalid"));
    }
    let mut bytes = ceremony.fingerprint()?.to_vec();
    bytes.extend_from_slice(&(origin.len() as u64).to_be_bytes());
    bytes.extend_from_slice(origin);
    bytes.extend_from_slice(&(package.len() as u64).to_be_bytes());
    bytes.extend_from_slice(package);
    Ok(commitment("mpc-dkg-echo-package-v2", &bytes))
}

/// Expected aggregate echo payload sizes, excluding framing and transport
/// overhead. There are n*(n-1)^2 directed echo deliveries for n participants.
/// Compact echoes change byte complexity, not message-count complexity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EchoTrafficEstimate {
    pub echo_deliveries: u64,
    pub full_package_payload_bytes: u64,
    pub digest_payload_bytes: u64,
}
pub fn estimate_echo_traffic(n: usize, package_bytes: usize) -> Option<EchoTrafficEstimate> {
    if n < 2 || n > holochain_mpc_core::MAX_PARTICIPANTS ||
       package_bytes == 0 || package_bytes > MAX_ANNOUNCEMENT { return None; }
    let n = u64::try_from(n).ok()?;
    let deliveries = n.checked_mul(n.checked_sub(1)?)?.checked_mul(n.checked_sub(1)?)?;
    Some(EchoTrafficEstimate {
        echo_deliveries: deliveries,
        full_package_payload_bytes: deliveries.checked_mul(u64::try_from(package_bytes).ok()?)?,
        digest_payload_bytes: deliveries.checked_mul(32)?,
    })
}

/// A versioned wire wrapper carries the full ceremony binding: the base
/// Envelope only binds SessionSpec and does NOT carry proposal_action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundBroadcastV2 {
    pub version: u16,
    pub proposal_action: Vec<u8>,
    pub ceremony_hash: [u8; 32],
    pub message: BroadcastMessage,
}

/// Persist these operations in an append-only native journal. This is an
/// *untrusted wire shape*: it does not attest to agent identity or receipt
/// authenticity by itself, and must not be accepted without `authenticate`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DkgReplayEvent {
    LocalBegin { package: Vec<u8> },
    Inbound { envelope: Envelope, authenticated_sender: ParticipantId },
    LocalAttest,
}

impl EchoBroadcast {
    /// Restore by replaying durable events, NEVER by decoding an internal
    /// checkpoint. The `authenticate` hook MUST verify the journal record's
    /// origin, session binding and anti-tamper evidence (e.g. signed receipts),
    /// including locally authored events. Passing an unconditional Ok closure
    /// is appropriate ONLY for tests with a pre-verified immutable journal.
    /// Holochain RPC caller identity by itself is not a portable signature.
    pub fn replay_authenticated_events<F>(ceremony: Ceremony, local: ParticipantId,
        events: &[DkgReplayEvent], mut authenticate: F) -> Result<Self, SecurityError>
    where F: FnMut(&DkgReplayEvent) -> Result<(), SecurityError> {
        let mut restored = Self::new(ceremony, local)?;
        for event in events {
            authenticate(event)?;
            match event {
                DkgReplayEvent::LocalBegin { package } => { restored.begin(package.clone())?; }
                DkgReplayEvent::Inbound { envelope, authenticated_sender } => {
                    let recipient = restored.local.clone();
                    restored.receive_envelope(&recipient, authenticated_sender, envelope)?;
                }
                DkgReplayEvent::LocalAttest => { restored.attest()?; }
            }
        }
        Ok(restored)
    }
    pub fn new_with_guarantee(ceremony: Ceremony, local: ParticipantId,
        guarantee: BroadcastGuarantee) -> Result<Self, SecurityError> {
        if guarantee != BroadcastGuarantee::UnanimousAbort {
            return Err(SecurityError::Invalid("Byzantine reliable broadcast not implemented"));
        }
        Self::new(ceremony, local)
    }
    pub fn new(ceremony: Ceremony, local: ParticipantId) -> Result<Self, SecurityError> {
        ceremony.validate()?;
        if !ceremony.spec.contains(&local) { return Err(SecurityError::Unauthorized); }
        let origins = ceremony.spec.participants.iter()
            .cloned().map(|p| (p, OriginState::default())).collect();
        Ok(Self { ceremony, local, origins, attestations: BTreeMap::new(),
                  proposed_hash: None, aborted: false })
    }
    /// Produce one authenticated-protocol envelope. The Holochain coordinator
    /// will *reconstruct* and send it using the actual local agent identity.
    /// Broadcast messages are per-peer addressed; retransmissions use the
    /// exact same (sender, round, sequence, payload).
    pub fn outgoing(&self, to: &[u8], sequence: u64, message: &BroadcastMessage)
        -> Result<Envelope, SecurityError> {
        self.member(to)?;
        let round = match message {
            BroadcastMessage::Announce { .. } | BroadcastMessage::Echo { .. } | BroadcastMessage::EchoDigest { .. } => 1,
            BroadcastMessage::Attest { .. } => 2,
            BroadcastMessage::Abort => 1,
        };
        let payload = serde_json::to_vec(&BoundBroadcastV2 {
            version: 2,
            proposal_action: self.ceremony.proposal_action.clone(),
            ceremony_hash: self.ceremony.fingerprint()?,
            message: message.clone(),
        }).map_err(|_| SecurityError::Invalid("broadcast wire encoding"))?;
        Envelope::new(&self.ceremony.spec, self.local.clone(), Some(to.to_vec()),
                      round, sequence, payload)
            .map_err(|_| SecurityError::Invalid("broadcast envelope invalid"))
    }
    /// Always derive authenticated_sender from the local Holochain RPC
    /// provenance or a trusted, already authenticated private inbox record.
    pub fn receive_envelope(&mut self, local_recipient: &[u8], authenticated_sender: &[u8],
                            env: &Envelope) -> Result<Option<BroadcastMessage>, SecurityError> {
        env.validate_received(&self.ceremony.spec, local_recipient, authenticated_sender)
            .map_err(|_| SecurityError::Unauthorized)?;
        if local_recipient != self.local { return Err(SecurityError::Unauthorized); }
        // Reject legacy unbound messages even when SessionSpec matches.
        // Two proposals can share SessionSpec yet have different action hashes.
        let bound: BoundBroadcastV2 = serde_json::from_slice(&env.payload)
            .map_err(|_| SecurityError::Invalid("missing or malformed DKG ceremony binding"))?;
        if bound.version != 2 || bound.proposal_action != self.ceremony.proposal_action ||
           bound.ceremony_hash != self.ceremony.fingerprint()? {
            return Err(SecurityError::Invalid("DKG ceremony binding mismatch"));
        }
        let message = bound.message;
        let round = if matches!(&message, BroadcastMessage::Attest { .. }) { 2 } else { 1 };
        if env.round != round { return Err(SecurityError::Invalid("broadcast round mismatch")); }
        self.receive(authenticated_sender, message)
    }
    pub fn is_aborted(&self) -> bool { self.aborted }
    pub fn ceremony(&self) -> &Ceremony { &self.ceremony }
    fn active(&self) -> Result<(), SecurityError> {
        if self.aborted { Err(SecurityError::Aborted) }
        else if self.proposed_hash.is_some() { Err(SecurityError::Invalid("broadcast already frozen")) }
        else { Ok(()) }
    }
    fn member(&self, p: &[u8]) -> Result<(), SecurityError> {
        if self.ceremony.spec.contains(p) { Ok(()) } else { Err(SecurityError::Unauthorized) }
    }
    fn valid_package(package: &[u8]) -> Result<(), SecurityError> {
        if package.is_empty() || package.len() > MAX_ANNOUNCEMENT {
            Err(SecurityError::Invalid("announcement size invalid"))
        } else { Ok(()) }
    }
    fn record_digest(&mut self, origin: &ParticipantId, echoer: &ParticipantId,
                     digest: [u8; 32]) -> Result<(), SecurityError> {
        self.member(origin)?;
        self.member(echoer)?;
        let expected = self.origins.get(origin).and_then(|s| s.direct.as_deref())
            .map(|p| dkg_package_digest(&self.ceremony, origin, p)).transpose()?;
        let origin_state = self.origins.get_mut(origin).ok_or(SecurityError::Unauthorized)?;
        if expected.is_some_and(|value| value != digest) ||
           origin_state.echoes.get(echoer).is_some_and(|old| *old != digest) ||
           origin_state.echoes.values().any(|old| *old != digest) {
            self.aborted = true;
            return Err(SecurityError::Equivocation);
        }
        origin_state.echoes.entry(echoer.clone()).or_insert(digest);
        Ok(())
    }
    fn record(&mut self, origin: &ParticipantId, echoer: &ParticipantId,
              bytes: &[u8]) -> Result<(), SecurityError> {
        let digest = dkg_package_digest(&self.ceremony, origin, bytes)?;
        self.record_digest(origin, echoer, digest)
    }
    /// Begin the local party's package broadcast. Caller sends the returned
    /// announcement to ALL peers over authenticated, acknowledged RPCs.
    pub fn begin(&mut self, package: Vec<u8>) -> Result<BroadcastMessage, SecurityError> {
        self.active()?;
        if self.origins[&self.local].direct.is_some() {
            return Err(SecurityError::Invalid("own announcement already set"));
        }
        Self::valid_package(&package)?;
        self.receive_announcement(self.local.clone(), package.clone())?;
        Ok(BroadcastMessage::Announce { package })
    }
    /// Trusted adapter supplies `authenticated_sender`. If a fresh
    /// announcement arrives, send the returned Echo to ALL participants.
    /// Repeated identical announces/echoes are idempotent for network retry.
    pub fn receive(&mut self, authenticated_sender: &[u8], message: BroadcastMessage)
        -> Result<Option<BroadcastMessage>, SecurityError>
    {
        if self.aborted { return Err(SecurityError::Aborted); }
        self.member(authenticated_sender)?;
        match message {
            BroadcastMessage::Abort => { self.aborted = true; Ok(None) }
            BroadcastMessage::Announce { package } => {
                if self.proposed_hash.is_some() { return Err(SecurityError::Invalid("broadcast frozen")); }
                let origin = authenticated_sender.to_vec();
                if origin == self.local { return Err(SecurityError::Unauthorized); }
                let first = self.origins[&origin].direct.is_none();
                self.receive_announcement(origin.clone(), package.clone())?;
                if first { Ok(Some(BroadcastMessage::EchoDigest {
                    package_digest: dkg_package_digest(&self.ceremony, &origin, &package)?, origin,
                })) }
                else { Ok(None) }
            }
            BroadcastMessage::Echo { origin, package } => {
                if self.proposed_hash.is_some() { return Err(SecurityError::Invalid("broadcast frozen")); }
                self.member(&origin)?;
                Self::valid_package(&package)?;
                self.record(&origin, &authenticated_sender.to_vec(), &package)?;
                Ok(None)
            }
            BroadcastMessage::EchoDigest { origin, package_digest } => {
                if self.proposed_hash.is_some() { return Err(SecurityError::Invalid("broadcast frozen")); }
                self.record_digest(&origin, &authenticated_sender.to_vec(), package_digest)?;
                Ok(None)
            }
            BroadcastMessage::Attest { transcript_hash } => {
                if let Some(previous) = self.attestations.get(authenticated_sender) {
                    if previous != &transcript_hash { self.aborted = true; return Err(SecurityError::Equivocation); }
                }
                if self.proposed_hash.is_some_and(|hash| hash != transcript_hash) {
                    self.aborted = true;
                    return Err(SecurityError::AttestationMismatch);
                }
                self.attestations.insert(authenticated_sender.to_vec(), transcript_hash);
                Ok(None)
            }
        }
    }
    fn receive_announcement(&mut self, origin: ParticipantId, package: Vec<u8>) -> Result<(), SecurityError> {
        Self::valid_package(&package)?;
        if let Some(old) = &self.origins[&origin].direct {
            if old != &package { self.aborted = true; return Err(SecurityError::Equivocation); }
            return Ok(());
        }
        // Check both early echoes and conflicting direct announcements before
        // recording the origin package. Out-of-order compact echoes are allowed.
        let expected = dkg_package_digest(&self.ceremony, &origin, &package)?;
        if self.origins.get(&origin).ok_or(SecurityError::Unauthorized)?.echoes
            .values().any(|got| *got != expected) {
            self.aborted = true;
            return Err(SecurityError::Equivocation);
        }
        self.record(&origin, &origin, &package)?;
        self.record(&origin, &self.local.clone(), &package)?;
        self.origins.get_mut(&origin).ok_or(SecurityError::Unauthorized)?.direct = Some(package);
        Ok(())
    }
    pub fn echoes_complete(&self) -> bool {
        !self.aborted && self.origins.iter().all(|(identity, origin)| {
            origin.direct.as_deref().is_some_and(|bytes| {
                let Ok(expected) = dkg_package_digest(&self.ceremony, identity, bytes) else { return false; };
                origin.echoes.len() == self.ceremony.spec.participants.len() &&
                origin.echoes.values().all(|digest| *digest == expected)
            })
        })
    }
    fn transcript_hash(&self) -> Result<[u8; 32], SecurityError> {
        if !self.echoes_complete() { return Err(SecurityError::NotReady); }
        // Canonical sorted participant identity + exact serialized package bytes.
        let ordered: Vec<(&ParticipantId, &Vec<u8>)> = self.origins.iter().map(|(p,s)| {
            (p, s.direct.as_ref().expect("echoes_complete ensured direct"))
        }).collect();
        let value = serde_json::to_vec(&(self.ceremony.fingerprint()?, ordered))
            .map_err(|_| SecurityError::Invalid("transcript serialization failed"))?;
        Ok(commitment("mpc-security-echo-transcript-v1", &value))
    }
    /// Call after all N(N-1) echo deliveries. Broadcast returned attestation
    /// by remote RPC. Attestations received early are checked against this hash.
    pub fn attest(&mut self) -> Result<BroadcastMessage, SecurityError> {
        if self.aborted { return Err(SecurityError::Aborted); }
        let hash = self.transcript_hash()?;
        for attestation in self.attestations.values() {
            if attestation != &hash { self.aborted = true; return Err(SecurityError::AttestationMismatch); }
        }
        self.proposed_hash = Some(hash);
        self.attestations.insert(self.local.clone(), hash);
        Ok(BroadcastMessage::Attest { transcript_hash: hash })
    }
    pub fn finalize(&self) -> Result<VerifiedTranscript, SecurityError> {
        if self.aborted { return Err(SecurityError::Aborted); }
        let expected = self.proposed_hash.ok_or(SecurityError::NotReady)?;
        if !self.echoes_complete() || self.attestations.len() != self.ceremony.spec.participants.len() ||
           self.attestations.values().any(|hash| *hash != expected) {
            return Err(SecurityError::NotReady);
        }
        Ok(VerifiedTranscript { ceremony: self.ceremony.clone(), hash: expected,
            packages: self.origins.iter().map(|(p,s)| (p.clone(), s.direct.clone().unwrap())).collect() })
    }
}
