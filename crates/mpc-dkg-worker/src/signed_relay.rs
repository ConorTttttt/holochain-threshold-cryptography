//! Phase 3: signed app-API transport for `RelayEngine`.
//!
//! An authorised external agent signer must return a fresh, correctly signed
//! request on EVERY invocation. No private agent key or signing authority is
//! embedded in this bridge. Source-chain provenance is trusted only through
//! the pinned local conductor's authenticated zome responses.
use crate::conductor_bridge::KeyEvidence;
use crate::conductor_client::{submit_signed_mpc_call, MpcZomeResult};
use crate::connection_policy::ConductorPin;
use crate::relay::{MpcTransport, SendReceipt};
use crate::signed_call_policy::{validate_signed_envelope, validate_signed_key_registration, MpcCall};
use holochain_conductor_api::ZomeCallParamsSigned;
use holochain_mpc_core::Envelope;
use std::net::SocketAddr;
use std::path::PathBuf;

/// The `Publish` intent is not a signed message. The signer must construct
/// `ZomeCallParams`, including a fresh nonce, short expiry, the recipient's
/// capability secret, and sign using the approved Holochain agent authority.
pub enum SignIntent<'a> {
    ReadInbox,
    ReadProbeSession,
    ReadEncryptionKeys,
    RegisterEncryptionKey([u8;32]),
    Publish(&'a Envelope),
}

#[allow(async_fn_in_trait)]
pub trait FreshMpcSigner {
    async fn sign(&mut self, intent: SignIntent<'_>) -> Result<ZomeCallParamsSigned, String>;
}

pub struct SignedAppTransport<S> {
    pub addr: SocketAddr,
    pub origin: String,
    pub token_file: PathBuf,
    pub pin: ConductorPin,
    pub signer: S,
}

impl<S: FreshMpcSigner> SignedAppTransport<S> {
    #[cfg(feature = "lair-signer")]
    pub async fn verify_probe_session(&mut self, record: &crate::capability_exchange::CeremonyRecord)
        -> Result<(),String> {
        match self.call(SignIntent::ReadProbeSession).await? {
            MpcZomeResult::ProbeSession {spec,accepted,ready} =>
                crate::transport_probe::verify_status(record,&spec,&accepted,ready),
            _=>Err("wrong probe status response".into()),
        }
    }

    pub(crate) async fn call(&mut self, intent: SignIntent<'_>) -> Result<MpcZomeResult, String> {
        // Avoid a self-borrow of `signer` together with `intent` if a caller
        // requested Publish: the envelope is borrowed from the relay engine.
        let op = match &intent {
            SignIntent::ReadProbeSession => MpcCall::GetProbeSessionStatus,
            SignIntent::ReadInbox => MpcCall::GetInbox,
            SignIntent::ReadEncryptionKeys => MpcCall::GetEncryptionKeyBindings,
            SignIntent::RegisterEncryptionKey(_) => MpcCall::RegisterEncryptionKey,
            SignIntent::Publish(_) => MpcCall::SendProtocolMessage,
        };
        let signed = self.signer.sign(intent).await?;
        submit_signed_mpc_call(self.addr, &self.origin, &self.token_file,
            &self.pin, op, signed).await
    }
}

impl<S: FreshMpcSigner> MpcTransport for SignedAppTransport<S> {
    async fn register_key(&mut self, public_key: [u8;32]) -> Result<Vec<u8>, String> {
        let signed=self.signer.sign(SignIntent::RegisterEncryptionKey(public_key)).await?;
        validate_signed_key_registration(&self.pin,public_key,&signed)?;
        match submit_signed_mpc_call(self.addr,&self.origin,&self.token_file,
            &self.pin,MpcCall::RegisterEncryptionKey,signed).await? {
            MpcZomeResult::KeyRegistration { action } => Ok(action),
            _ => Err("signed conductor returned wrong key registration response".into()),
        }
    }
    async fn get_inbox(&mut self) -> Result<Vec<Envelope>, String> {
        match self.call(SignIntent::ReadInbox).await? {
            MpcZomeResult::Inbox(msgs) => Ok(msgs),
            _ => Err("signed conductor returned wrong inbox response".into()),
        }
    }
    async fn get_encryption_keys(&mut self) -> Result<Vec<KeyEvidence>, String> {
        match self.call(SignIntent::ReadEncryptionKeys).await? {
            MpcZomeResult::EncryptionKeys(keys) => Ok(keys),
            _ => Err("signed conductor returned wrong key binding response".into()),
        }
    }
    async fn publish(&mut self, envelope: &Envelope) -> Result<SendReceipt, String> {
        let signed = self.signer.sign(SignIntent::Publish(envelope)).await?;
        validate_signed_envelope(&self.pin, envelope, &signed)?;
        match submit_signed_mpc_call(self.addr, &self.origin, &self.token_file,
            &self.pin, MpcCall::SendProtocolMessage, signed).await? {
            MpcZomeResult::DeliveryReceipt { action, already_stored } => {
                Ok(SendReceipt { action, already_stored })
            }
            _ => Err("signed conductor returned wrong delivery receipt".into()),
        }
    }
}
