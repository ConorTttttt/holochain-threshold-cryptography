//! Release-hardening audit (27 October 2026): unknown-field, version and
//! roster behaviour of the worker's external input types (IPC frames and
//! commands, signing plans, group descriptors). Offline, synthetic data only.
//!
//! Tests named `known_gap_*` pin TODAY's behaviour of a documented gap
//! (`docs/V040_RELEASE_HARDENING.md`); flip them when the gap is closed.
use holochain_mpc_core::{commitment, SessionSpec};
use holochain_mpc_dkg_worker::ipc::{AuthChannel, AuthFrame, ChannelContext, Role};
use holochain_mpc_dkg_worker::signing::{SigningPlan, PLAN_SCHEMA};
use holochain_mpc_dkg_worker::Command;
use holochain_mpc_security::activation::GroupDescriptor;

fn context() -> ChannelContext {
    ChannelContext { worker_agent: vec![1; 39], proposal_action: vec![9; 39],
        session_id: [3; 32], channel_id: [4; 32] }
}

fn peers() -> (AuthChannel, AuthChannel) {
    (AuthChannel::new([7; 32], context(), Role::Host).unwrap(),
     AuthChannel::new([7; 32], context(), Role::Worker).unwrap())
}

#[test]
fn ipc_frame_unknown_fields_and_wrong_version_are_refused() {
    let (mut host, mut worker) = peers();
    let frame = host.seal(Command::Attest).unwrap();
    let clean = serde_json::to_value(&frame).unwrap();

    // Extra top-level field.
    let mut with_extra = clean.clone();
    with_extra["extra"] = serde_json::json!(true);
    assert!(serde_json::from_value::<AuthFrame<Command>>(with_extra).is_err());
    // Extra field inside the authenticated context.
    let mut with_context_extra = clean.clone();
    with_context_extra["context"]["extra"] = serde_json::json!(1);
    assert!(serde_json::from_value::<AuthFrame<Command>>(with_context_extra).is_err());
    // Missing tag, short tag.
    for tag_len in [0_usize, 31] {
        let mut short = clean.clone();
        short["tag"] = serde_json::json!(vec![0_u8; tag_len]);
        assert!(serde_json::from_value::<AuthFrame<Command>>(short).is_err(), "tag of {tag_len} bytes");
    }
    // A well-formed frame with another version is refused by `open`.
    let mut wrong_version: AuthFrame<Command> = serde_json::from_value(clean.clone()).unwrap();
    wrong_version.version = 2;
    assert!(worker.open(wrong_version).is_err());
    // The untouched frame still opens: refusals above did not move the sequence.
    let intact: AuthFrame<Command> = serde_json::from_value(clean).unwrap();
    assert!(matches!(worker.open(intact).unwrap(), Command::Attest));
}

#[test]
fn ipc_command_unknown_op_or_field_is_refused() {
    assert!(matches!(serde_json::from_str::<Command>(r#"{"op":"attest"}"#).unwrap(), Command::Attest));
    assert!(matches!(serde_json::from_str::<Command>(r#"{"op":"finalize"}"#).unwrap(), Command::Finalize));
    for bad in [r#"{"op":"export_share"}"#, r#"{"op":"ATTEST"}"#,
                r#"{}"#, r#"[]"#, r#"{"op":"begin_round_two"}"#,
                r#"{"op":"begin_round_two","pinned_keys":[],"extra":1}"#] {
        assert!(serde_json::from_str::<Command>(bad).is_err(), "{bad}");
    }
    assert!(serde_json::from_str::<ChannelContext>(
        r#"{"worker_agent":[],"proposal_action":[],"session_id":[],"channel_id":[],"x":1}"#).is_err());
}

fn descriptor() -> GroupDescriptor {
    let members: Vec<Vec<u8>> = (1..=3).map(|m| vec![m; 39]).collect();
    GroupDescriptor {
        proposal_action: vec![44; 39],
        spec: SessionSpec { session_id: commitment("session", b"input-validation"),
            application_id: "org.example.any-application".into(),
            protocol_id: "frost-ed25519".into(), protocol_version: 1,
            context_hash: commitment("purpose", b"input-validation"),
            participants: members.clone(), threshold: 2, max_round: 6 },
        epoch: 1, dkg_transcript_hash: [5; 32], public_key_package_hash: [6; 32],
        group_verifying_key: vec![7; 32],
        encryption_key_binding_actions: (1..=3).map(|m| vec![m + 20; 39]).collect(),
    }
}

fn plan() -> SigningPlan {
    SigningPlan { schema: PLAN_SCHEMA, descriptor: descriptor(),
        operation_id: commitment("operation", b"1"), message: b"approve transfer #42".to_vec(),
        selected: vec![vec![1; 39], vec![3; 39]] }
}

#[test]
fn signing_plan_schema_roster_and_operation_id_are_validated() {
    plan().validate().unwrap();
    let refused = |f: &dyn Fn(&mut SigningPlan)| { let mut p = plan(); f(&mut p); p.validate().is_err() };
    assert!(refused(&|p| p.schema = PLAN_SCHEMA + 1));
    assert!(refused(&|p| p.schema = 0));
    assert!(refused(&|p| p.operation_id = [0; 32]));
    assert!(refused(&|p| p.operation_id = p.descriptor.spec.session_id));
    assert!(refused(&|p| p.message.clear()));
    assert!(refused(&|p| p.message = vec![1; 8 * 1024 + 1]));
    assert!(refused(&|p| p.selected = vec![vec![1; 39]]), "below the threshold");
    assert!(refused(&|p| p.selected = vec![vec![3; 39], vec![1; 39]]), "unsorted roster");
    assert!(refused(&|p| p.selected = vec![vec![1; 39], vec![1; 39]]), "duplicate signer");
    assert!(refused(&|p| p.selected = vec![vec![1; 39], vec![9; 39]]), "non-member signer");
    assert!(refused(&|p| p.descriptor.dkg_transcript_hash = [0; 32]));
    assert!(refused(&|p| p.descriptor.group_verifying_key = vec![7; 31]));
    assert!(refused(&|p| p.descriptor.encryption_key_binding_actions.pop().map(drop).unwrap_or(())));
    assert!(refused(&|p| p.descriptor.proposal_action = vec![44; 38]));
}

#[test]
fn signing_plan_json_refuses_unknown_and_missing_fields() {
    let clean = serde_json::to_value(plan()).unwrap();
    assert!(serde_json::from_value::<SigningPlan>(clean.clone()).is_ok());
    let mut extra = clean.clone();
    extra["note"] = serde_json::json!("hidden");
    assert!(serde_json::from_value::<SigningPlan>(extra).is_err());
    for field in ["schema", "descriptor", "operation_id", "message", "selected"] {
        let mut missing = clean.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<SigningPlan>(missing).is_err(), "missing {field}");
    }
    // A short operation id must not be padded or truncated into a valid one.
    let mut short = clean;
    short["operation_id"] = serde_json::json!(vec![1_u8; 31]);
    assert!(serde_json::from_value::<SigningPlan>(short).is_err());
}

// Documented gap: serde does not apply `deny_unknown_fields` to the unit
// variants of an internally tagged enum, so `Command::Attest` and
// `Command::Finalize` accept extra keys. The frame's HMAC is computed over the
// re-serialised body, so the extra keys are dropped before authentication.
#[test]
fn known_gap_unit_commands_ignore_unknown_fields() {
    assert!(matches!(serde_json::from_str::<Command>(r#"{"op":"attest","extra":1}"#).unwrap(), Command::Attest));
    assert!(matches!(serde_json::from_str::<Command>(r#"{"op":"finalize","extra":1}"#).unwrap(), Command::Finalize));
}

// Documented gap: the descriptor and its nested session spec do not set
// `deny_unknown_fields`, so a descriptor file may carry extra keys. The digest
// is taken over a re-serialisation, so extra keys never reach an attested hash.
#[test]
fn known_gap_descriptor_unknown_fields_are_ignored_but_cannot_change_the_digest() {
    let clean = descriptor();
    let mut value = serde_json::to_value(&clean).unwrap();
    value["smuggled"] = serde_json::json!("extra");
    value["spec"]["smuggled"] = serde_json::json!(1);
    let parsed: GroupDescriptor = serde_json::from_value(value).unwrap();
    assert_eq!(parsed, clean);
    assert_eq!(parsed.digest().unwrap(), clean.digest().unwrap());
}
