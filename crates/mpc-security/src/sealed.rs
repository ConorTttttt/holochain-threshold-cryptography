//! Native X25519 + XSalsa20Poly1305 sealed envelopes compatible in primitive
//! with libsodium's crypto_box. `SalsaBox` does not support external AAD;
//! the complete session, round, sender, recipient and sequence are authenticated
//! *inside* the ciphertext. Reject a mismatch before processing the payload.
//!
//! The key shown here is generated in native memory: it is for tests and local
//! prototypes only. Production keys require an OS-/Lair-backed keystore with
//! secure provisioning, anti-rollback, key rotation and restart recovery.
use crypto_box::{aead::{Aead, AeadCore, OsRng}, PublicKey, SalsaBox, SecretKey};
use holochain_mpc_core::ParticipantId;
pub use holochain_mpc_core::SealedPacket;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use crate::{Ceremony, SecurityError};

pub const MAX_SEALED_PAYLOAD: usize = 3 * 1024;// Bound nested JSON byte-array expansion under the 64 KiB Envelope cap.

/// DO NOT derive Clone, Debug or Serialize: contains sensitive key material.
pub struct NativeChannelKey { key: SecretKey }
impl NativeChannelKey {
    pub fn generate() -> Self { Self { key: SecretKey::generate(&mut OsRng) } }
    /// Reconstitute an existing native X25519 identity from an already
    /// authenticated, zeroising storage buffer. This does NOT provision a key
    /// and must not be called on untrusted or logged material.
    ///
    /// `crypto_box::SecretKey` zeroises its internal secret on drop.
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Result<Self, SecurityError> {
        if secret.iter().all(|b| *b == 0) {
            return Err(SecurityError::Invalid("zero native transport secret"));
        }
        let key = SecretKey::from_slice(secret)
            .map_err(|_| SecurityError::Invalid("invalid native transport secret"))?;
        Ok(Self { key })
    }
    pub fn public_key(&self) -> [u8; 32] { *self.key.public_key().as_bytes() }
    pub fn seal(&self, ceremony: &Ceremony, header: ChannelHeader,
                recipient_public_key: [u8; 32], payload: &[u8]) -> Result<SealedPacket, SecurityError> {
        ceremony.validate()?;
        header.validate(ceremony)?;
        if payload.is_empty() || payload.len() > MAX_SEALED_PAYLOAD {
            return Err(SecurityError::Invalid("sealed payload size invalid"));
        }
        if header.sender == header.recipient { return Err(SecurityError::Unauthorized); }
        if recipient_public_key == [0;32] || self.public_key() == [0;32] {
            return Err(SecurityError::Invalid("missing pinned encryption key"));
        }
        let binding = ceremony.fingerprint()?;
        let inner = PlainMessage { binding, header, payload: payload.to_vec() };
        let bytes = serde_json::to_vec(&inner).map_err(|_| SecurityError::Crypto)?;
        let cipher = SalsaBox::new(&PublicKey::from(recipient_public_key), &self.key);
        let nonce = SalsaBox::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, bytes.as_slice()).map_err(|_| SecurityError::Crypto)?;
        let mut nonce_bytes = [0u8; 24];
        nonce_bytes.copy_from_slice(&nonce);
        Ok(SealedPacket { version: 1, sender_key: self.public_key(), recipient_key: recipient_public_key,
                          nonce: nonce_bytes, ciphertext })
    }
    /// `trusted_sender_key` must be selected from a pinned *author-signed*
    /// key-binding record, not from the untrusted packet's `sender_key` field.
    pub fn open(&self, ceremony: &Ceremony, expected_header: &ChannelHeader,
                trusted_sender_key: [u8; 32], packet: &SealedPacket)
        -> Result<Vec<u8>, SecurityError>
    {
        ceremony.validate()?;
        expected_header.validate(ceremony)?;
        if packet.version != 1 || packet.sender_key != trusted_sender_key ||
           packet.recipient_key != self.public_key() || trusted_sender_key == [0; 32] ||
           packet.ciphertext.len() < 16 || packet.ciphertext.len() > 48 * 1024 {
            return Err(SecurityError::Unauthorized);
        }
        let cipher = SalsaBox::new(&PublicKey::from(trusted_sender_key), &self.key);
        let nonce = crypto_box::aead::generic_array::GenericArray::clone_from_slice(&packet.nonce);
        let plaintext = cipher.decrypt(&nonce, packet.ciphertext.as_slice()).map_err(|_| SecurityError::Crypto)?;
        let inner: PlainMessage = serde_json::from_slice(&plaintext).map_err(|_| SecurityError::Crypto)?;
        if inner.binding != ceremony.fingerprint()? || inner.header != *expected_header ||
           inner.payload.is_empty() || inner.payload.len() > MAX_SEALED_PAYLOAD {
            return Err(SecurityError::Unauthorized);
        }
        Ok(inner.payload)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelHeader {
    pub sender: ParticipantId,
    pub recipient: ParticipantId,
    pub round: u32,
    pub sequence: u64,
}
impl ChannelHeader {
    pub fn validate(&self, ceremony: &Ceremony) -> Result<(), SecurityError> {
        if !ceremony.spec.contains(&self.sender) || !ceremony.spec.contains(&self.recipient) ||
           self.sender == self.recipient || self.round == 0 ||
           self.round > ceremony.spec.max_round || self.sequence == 0 {
            return Err(SecurityError::Unauthorized);
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct PlainMessage {
    binding: [u8; 32],
    header: ChannelHeader,
    payload: Vec<u8>,
}

/// Durable replay state for *logical* channel identifiers. Process atomically
/// alongside application side effects (e.g., in a native transactional DB).
/// The Holochain private inbox alone does NOT supply this atomicity.
#[derive(Default, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelReplay {
    seen: BTreeSet<(ParticipantId, u32, u64)>,
}
impl ChannelReplay {
    pub fn check_and_mark(&mut self, header: &ChannelHeader) -> Result<(), SecurityError> {
        if !self.seen.insert((header.sender.clone(), header.round, header.sequence)) {
            return Err(SecurityError::Invalid("duplicate encrypted message"));
        }
        Ok(())
    }
}
