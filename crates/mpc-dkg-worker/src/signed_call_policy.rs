//! v0.4.0 Phase 2: fail-closed admission policy for externally signed
//! Holochain app zome calls. The bridge NEVER creates an agent signing key.
//!
//! A local trusted signer (e.g. a properly authorised Lair client) must
//! produce `ZomeCallParamsSigned`. The conductor checks that signature and
//! its nonce/expiry; this module checks the intent encoded in the *signed*
//! bytes before the call is submitted. WebSocket app authentication alone
//! is NOT permission to impersonate the agent.
use crate::connection_policy::ConductorPin;
use holochain_conductor_api::ZomeCallParamsSigned;
use holochain_zome_types::prelude::{ActionHash, AgentPubKey, ZomeCallParams};
use serde::Deserialize;

pub const MAX_SIGNED_CALL_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MpcCall {
    GetInbox,
    /// Read-only status, authorized only by the opt-in probe signer.
    GetProbeSessionStatus,
    GetEncryptionKeyBindings,
    RegisterEncryptionKey,
    SendProtocolMessage,
}

impl MpcCall {
    pub fn name(self) -> &'static str {
        match self {
            Self::GetProbeSessionStatus => "get_session_status",
            Self::GetInbox => "get_inbox",
            Self::GetEncryptionKeyBindings => "get_encryption_key_bindings",
            Self::RegisterEncryptionKey => "register_encryption_key",
            Self::SendProtocolMessage => "send_protocol_message",
        }
    }
}

#[derive(Debug, Deserialize)]
struct OutboundMessage {
    proposal: ActionHash,
    recipient: AgentPubKey,
    round: u32,
    sequence: u64,
    payload: Vec<u8>,
    recipient_cap_secret: serde::de::IgnoredAny,
}

#[derive(Debug, Deserialize)]
struct RegistrationPayload {
    proposal: ActionHash,
    public_key: [u8;32],
}

/// Validate the raw bytes that the agent actually signed. There must NOT be
/// any independently supplied, potentially divergent display/metadata fields.
///
/// This is *admission policy*, not Ed25519 signature verification. Signature,
/// expiry and nonce are enforced by the actual Holochain conductor.
pub fn validate_signed_call(
    pin: &ConductorPin,
    allowed: MpcCall,
    signed: &ZomeCallParamsSigned,
) -> Result<(), String> {
    pin.node.validate()?;
    if pin.role != "mpc" || pin.dna_hash.len() != 39 {
        return Err("expected pinned MPC coordinator cell".into());
    }
    let bytes = signed.bytes.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_SIGNED_CALL_BYTES {
        return Err("signed zome call exceeds size bounds".into());
    }
    let params: ZomeCallParams = holochain_serialized_bytes::decode(bytes)
        .map_err(|_| "malformed signed zome call parameters")?;
    if params.provenance.get_raw_39() != pin.node.worker_agent.as_slice() ||
        params.cell_id.agent_pubkey().get_raw_39() != pin.node.worker_agent.as_slice() ||
        params.cell_id.dna_hash().get_raw_39() != pin.dna_hash.as_slice() ||
        params.zome_name.to_string() != pin.role ||
        params.fn_name.to_string() != allowed.name()
    {
        return Err("signed call targets another agent, cell or function".into());
    }
    match allowed {
        MpcCall::GetInbox | MpcCall::GetEncryptionKeyBindings | MpcCall::GetProbeSessionStatus => {
            if params.cap_secret.is_some() {
                return Err("private-local read must not carry a capability secret".into());
            }
            let proposal: ActionHash = params.payload.decode()
                .map_err(|_| "read call has an invalid proposal payload")?;
            if proposal.get_raw_39() != pin.node.proposal_action.as_slice() {
                return Err("signed read belongs to a different DKG proposal".into());
            }
        }
        MpcCall::RegisterEncryptionKey => {
            if params.cap_secret.is_some() {
                return Err("local key registration must not carry capability secret".into());
            }
            let reg: RegistrationPayload = params.payload.decode()
                .map_err(|_| "key registration payload is malformed")?;
            if reg.proposal.get_raw_39() != pin.node.proposal_action.as_slice() ||
               reg.public_key == [0;32] {
                return Err("key registration belongs to another proposal or zero key".into());
            }
        }
        MpcCall::SendProtocolMessage => {
            // This is the public coordinator SendMessage shape. Its capability
            // secret is intentionally NEVER logged, copied into error strings
            // or exposed by the bridge. The coordinator still verifies it.
            let msg: OutboundMessage = params.payload.decode()
                .map_err(|_| "send call has an invalid envelope payload")?;
            if msg.proposal.get_raw_39() != pin.node.proposal_action.as_slice() ||
                msg.recipient.get_raw_39() == pin.node.worker_agent.as_slice() ||
                msg.round == 0 || msg.round > 6 || msg.sequence == u64::MAX ||
                msg.payload.is_empty() || msg.payload.len() > 128 * 1024 {
                return Err("send call violates local ceremony bounds".into());
            }
            // Round 3 carries JSON-encoded ciphertext; additional structural
            // and decryption checks happen in the existing coordinator/worker.
            if msg.round == 3 &&
                !serde_json::from_slice::<holochain_mpc_core::SealedPacket>(&msg.payload)
                    .map(|sealed| sealed.structurally_valid()).unwrap_or(false) {
                return Err("FROST Round-2 DKG message is not sealed".into());
            }
            let _ = &msg.recipient_cap_secret;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::ChannelContext;
    use holochain_conductor_api::ZomeCallParamsSigned;
    use holochain_zome_types::prelude::{CellId, ExternIO, Signature, ZomeCallParams, ZomeName, FunctionName, Timestamp};
    use serde::Serialize;

    fn pin() -> ConductorPin {
        use holochain_zome_types::prelude::DnaHash;
        let agent = AgentPubKey::from_raw_32(vec![0x84; 32]);
        let dna = DnaHash::from_raw_32(vec![0xdb; 32]);
        let proposal = ActionHash::from_raw_32(vec![0x86; 32]);
        ConductorPin {
            app_id: "org.test.mpc".into(), role: "mpc".into(),
            dna_hash: dna.get_raw_39().to_vec(),
            node: ChannelContext { worker_agent: agent.get_raw_39().to_vec(),
                proposal_action: proposal.get_raw_39().to_vec(),
                session_id: [7;32], channel_id: [8;32] },
        }
    }

    fn make_call(pin: &ConductorPin, name: &str, proposal: Vec<u8>) -> ZomeCallParamsSigned {
        use holochain_zome_types::prelude::DnaHash;
        use holochain_nonce::Nonce256Bits;
        let agent = AgentPubKey::try_from_raw_39(pin.node.worker_agent.clone()).unwrap();
        let dna = DnaHash::try_from_raw_39(pin.dna_hash.clone()).unwrap();
        let cell = CellId::new(dna, agent.clone());
        let hash = ActionHash::try_from_raw_39(proposal).unwrap();
        let params = ZomeCallParams {
            provenance: agent, cell_id: cell,
            zome_name: ZomeName::from("mpc"),
            fn_name: FunctionName::from(name),
            cap_secret: None,
            payload: ExternIO::encode(hash).unwrap(),
            nonce: Nonce256Bits::try_from(vec![42u8; 32]).expect("32-byte test nonce"),
            expires_at: Timestamp::now(),
        };
        let (bytes, _) = params.serialize_and_hash().unwrap();
        ZomeCallParamsSigned::new(bytes, Signature([0;64]))
    }

    #[derive(Debug, Serialize)]
    struct TestSend {
        proposal: ActionHash, recipient: AgentPubKey, round: u32,
        sequence: u64, payload: Vec<u8>, recipient_cap_secret: Vec<u8>,
    }

    fn signed_send(pin: &ConductorPin, env: &holochain_mpc_core::Envelope)
        -> ZomeCallParamsSigned {
        use holochain_zome_types::prelude::DnaHash;
        use holochain_nonce::Nonce256Bits;
        let agent = AgentPubKey::try_from_raw_39(pin.node.worker_agent.clone()).unwrap();
        let dna = DnaHash::try_from_raw_39(pin.dna_hash.clone()).unwrap();
        let recipient = AgentPubKey::try_from_raw_39(env.recipient.clone().unwrap()).unwrap();
        let payload = TestSend {
            proposal: ActionHash::try_from_raw_39(pin.node.proposal_action.clone()).unwrap(),
            recipient, round:env.round, sequence:env.sequence,
            payload:env.payload.clone(), recipient_cap_secret:vec![4;64],
        };
        let params = ZomeCallParams {
            provenance:agent.clone(), cell_id:CellId::new(dna,agent),
            zome_name:ZomeName::from("mpc"), fn_name:FunctionName::from("send_protocol_message"),
            cap_secret:None, payload:ExternIO::encode(payload).unwrap(),
            nonce:Nonce256Bits::try_from(vec![42u8; 32]).expect("32-byte test nonce"), expires_at:Timestamp::now(),
        };
        let (bytes,_) = params.serialize_and_hash().unwrap();
        ZomeCallParamsSigned::new(bytes,Signature([0;64])) // only an offline policy test
    }

    #[test]
    fn signed_outbound_must_match_worker_bytes_exactly() {
        let pin = pin();
        let env = holochain_mpc_core::Envelope {
            wire_version: 1, session_id: pin.node.session_id,
            protocol_id:"frost-ed25519".into(), protocol_version:1,
            sender: pin.node.worker_agent.clone(),
            recipient: Some(AgentPubKey::from_raw_32(vec![0x66;32]).get_raw_39().to_vec()),
            round:1, sequence:8,
            payload_hash:holochain_mpc_core::commitment("envelope-payload", b"example"),
            payload:b"example".to_vec(),
        };
        let signed = signed_send(&pin,&env);
        validate_signed_envelope(&pin,&env,&signed).unwrap();
        let mut changed = env.clone(); changed.sequence += 1;
        assert!(validate_signed_envelope(&pin,&changed,&signed).is_err());
        changed = env.clone(); changed.payload.push(b'!');
        assert!(validate_signed_envelope(&pin,&changed,&signed).is_err());
        changed = env.clone(); changed.session_id = [6;32];
        assert!(validate_signed_envelope(&pin,&changed,&signed).is_err());
        changed = env; changed.recipient = Some(pin.node.worker_agent.clone());
        assert!(validate_signed_envelope(&pin,&changed,&signed).is_err());
    }

    #[test]
    fn accepts_only_exact_pinned_read() {
        let pin = pin();
        let signed = make_call(&pin, "get_inbox", pin.node.proposal_action.clone());
        validate_signed_call(&pin, MpcCall::GetInbox, &signed).unwrap();
        assert!(validate_signed_call(&pin, MpcCall::GetEncryptionKeyBindings, &signed).is_err());
        let other_action = ActionHash::from_raw_32(vec![0x87;32]);
        let other = make_call(&pin, "get_inbox", other_action.get_raw_39().to_vec());
        assert!(validate_signed_call(&pin, MpcCall::GetInbox, &other).is_err());
    }

    #[test]
    fn rejects_wrong_agent_dna_role_and_unknown_function() {
        let pin = pin();
        let signed = make_call(&pin, "get_inbox", pin.node.proposal_action.clone());
        let mut bad = pin.clone(); bad.dna_hash = vec![0xaa;39];
        assert!(validate_signed_call(&bad, MpcCall::GetInbox, &signed).is_err());
        bad = pin.clone(); bad.node.worker_agent = vec![0x81;39];
        assert!(validate_signed_call(&bad, MpcCall::GetInbox, &signed).is_err());
        bad = pin.clone(); bad.role = "other".into();
        assert!(validate_signed_call(&bad, MpcCall::GetInbox, &signed).is_err());
        let wrong_fn = make_call(&pin, "prepare_inbox_grant", pin.node.proposal_action.clone());
        assert!(validate_signed_call(&pin, MpcCall::GetInbox, &wrong_fn).is_err());
    }

    fn signed_registration(pin: &ConductorPin, public_key: [u8;32]) -> ZomeCallParamsSigned {
        use holochain_zome_types::prelude::DnaHash;
        use holochain_nonce::Nonce256Bits;
        #[derive(Debug, Serialize)]
        struct Registration { proposal:ActionHash, public_key:[u8;32] }
        let agent=AgentPubKey::try_from_raw_39(pin.node.worker_agent.clone()).unwrap();
        let dna=DnaHash::try_from_raw_39(pin.dna_hash.clone()).unwrap();
        let params=ZomeCallParams {
            provenance:agent.clone(),cell_id:CellId::new(dna,agent),
            zome_name:ZomeName::from("mpc"),fn_name:FunctionName::from("register_encryption_key"),
            cap_secret:None,
            payload:ExternIO::encode(Registration {
                proposal:ActionHash::try_from_raw_39(pin.node.proposal_action.clone()).unwrap(),
                public_key,
            }).unwrap(), nonce:Nonce256Bits::try_from(vec![37u8;32]).expect("32-byte test nonce"),expires_at:Timestamp::now(),
        };
        let (bytes,_) = params.serialize_and_hash().unwrap();
        ZomeCallParamsSigned::new(bytes,Signature([0;64]))
    }
    #[test]
    fn own_encryption_key_registration_is_bound_to_signed_bytes() {
        let p=pin();
        let call=signed_registration(&p,[7;32]);
        validate_signed_key_registration(&p,[7;32],&call).unwrap();
        assert!(validate_signed_key_registration(&p,[8;32],&call).is_err());
        assert!(validate_signed_call(&p,MpcCall::GetInbox,&call).is_err());
        let other=signed_registration(&p,[0;32]);
        assert!(validate_signed_call(&p,MpcCall::RegisterEncryptionKey,&other).is_err());
        let mut another=p.clone(); another.node.proposal_action=vec![0x11;39];
        assert!(validate_signed_key_registration(&another,[7;32],&call).is_err());
    }

    #[test]
    fn rejects_malformed_or_oversized_signed_bytes() {
        let pin = pin();
        let malformed = ZomeCallParamsSigned::new(vec![0xc1], Signature([0;64]));
        assert!(validate_signed_call(&pin, MpcCall::GetInbox, &malformed).is_err());
        let big = ZomeCallParamsSigned::new(vec![0;MAX_SIGNED_CALL_BYTES + 1], Signature([0;64]));
        assert!(validate_signed_call(&pin, MpcCall::GetInbox, &big).is_err());
    }
}

/// Phase 3: do not merely approve a signed *send* function. The bytes
/// authorised by the signer must describe precisely the worker-produced
/// envelope that the relay has already validated (including round, sequence,
/// recipient and byte-for-byte ciphertext). This prevents a confused-deputy
/// signer from silently substituting a different outgoing MPC message.
pub fn validate_signed_envelope(
    pin: &ConductorPin,
    env: &holochain_mpc_core::Envelope,
    signed: &ZomeCallParamsSigned,
) -> Result<(), String> {
    validate_signed_call(pin, MpcCall::SendProtocolMessage, signed)?;
    let bytes = signed.bytes.as_bytes();
    let params: ZomeCallParams = holochain_serialized_bytes::decode(bytes)
        .map_err(|_| "malformed signed send parameters")?;
    let msg: OutboundMessage = params.payload.decode()
        .map_err(|_| "signed send payload is not an MPC envelope")?;
    if env.sender != pin.node.worker_agent ||
       env.session_id != pin.node.session_id ||
       env.recipient.as_deref() != Some(msg.recipient.get_raw_39()) ||
       msg.round != env.round || msg.sequence != env.sequence || msg.payload != env.payload ||
       msg.proposal.get_raw_39() != pin.node.proposal_action.as_slice() {
        return Err("signed send differs from authenticated worker output".into());
    }
    Ok(())
}

/// The signer must register precisely the worker-generated X25519 key. The
/// Holochain conductor verifies the Ed25519 agent signature separately.
pub fn validate_signed_key_registration(
    pin: &ConductorPin, public_key: [u8;32], signed: &ZomeCallParamsSigned,
) -> Result<(),String> {
    validate_signed_call(pin,MpcCall::RegisterEncryptionKey,signed)?;
    let params: ZomeCallParams = holochain_serialized_bytes::decode(signed.bytes.as_bytes())
        .map_err(|_| "malformed signed key registration")?;
    let reg: RegistrationPayload=params.payload.decode()
        .map_err(|_| "malformed key registration payload")?;
    if reg.public_key != public_key {
        return Err("signer substituted another worker's encryption key".into());
    }
    Ok(())
}
