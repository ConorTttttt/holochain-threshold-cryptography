//! The whole proposal state machine against the mock chain and the simulated
//! 2-of-3 group: happy path, tampered bytes, duplicate approvals, approval by
//! a non-selected node, expiry, replay, uncertain broadcasts, restarts.
use holochain_mpc_vault::chain::{BroadcastError, Chain};
use holochain_mpc_vault::engine::*;
use holochain_mpc_vault::mock_chain::MockChain;
use holochain_mpc_vault::mock_node::MockNet;
use holochain_mpc_vault::store::Store;
use holochain_mpc_vault::util::{hex, holochain_b64, TestClock};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

const T: Duration = Duration::from_secs(10);
const RECIPIENT: [u8; 32] = [9; 32];

/// Private temp dir regardless of the host umask (it is 0002 on the dev host).
fn tmp() -> TempDir {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::Builder::new().tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

struct Rig {
    net: Arc<MockNet>,
    chain: Arc<MockChain>,
    clock: Arc<TestClock>,
    /// Engines for members 0, 1 and 2 (A, B, C) and their vault ids.
    nodes: Vec<(Engine, String, TempDir)>,
}

fn cfg() -> EngineConfig {
    EngineConfig { auto_broadcast: true, default_expiry_secs: 3600, confirm_poll: Duration::from_millis(20),
        confirm_budget: Duration::from_secs(5) }
}

fn open(dir: &TempDir, net: &Arc<MockNet>, idx: usize, chain: &Arc<MockChain>, clock: &Arc<TestClock>, cfg: EngineConfig) -> Engine {
    let mut node = net.node(idx);
    node.sign_wait = Duration::from_secs(2);
    let chain: Arc<dyn Chain> = chain.clone();
    Engine::open(Store::open(dir.path()).unwrap(), vec![chain], Arc::new(node), clock.clone(), cfg).unwrap()
}

async fn rig_with(cfg: EngineConfig) -> Rig {
    let net = MockNet::new();
    let chain = Arc::new(MockChain::new());
    let clock = Arc::new(TestClock::new(1_800_000_000));
    let mut nodes = Vec::new();
    for idx in 0..3 {
        let dir = tmp();
        let engine = open(&dir, &net, idx, &chain, &clock, cfg.clone());
        let vault = engine.create_vault("team", "mock").await.unwrap();
        if idx == 0 { chain.fund(&vault.address, 1_000_000); } // one address, funded once
        nodes.push((engine, vault.id, dir));
    }
    Rig { net, chain, clock, nodes }
}

async fn rig() -> Rig { rig_with(cfg()).await }

impl Rig {
    fn e(&self, i: usize) -> &Engine { &self.nodes[i].0 }
    fn v(&self, i: usize) -> &str { &self.nodes[i].1 }
    fn agent(&self, i: usize) -> String { holochain_b64(&self.net.members[i]) }
    /// A proposes a transfer that A and C (members 0 and 2) are to sign.
    fn request(&self, amount: &str, selected: &[usize]) -> NewProposal {
        NewProposal { vault_id: self.v(0).into(), recipient: hex(&RECIPIENT), amount: amount.into(), memo: None,
            selected_signers: Some(selected.iter().map(|i| self.agent(*i)).collect()), expires_in_secs: None }
    }
    async fn propose_ac(&self, amount: &str) -> ProposalView {
        self.e(0).create_proposal(&self.request(amount, &[0, 2])).await.unwrap()
    }
    /// The other operator imports A's plan into their own service.
    async fn import(&self, idx: usize, from: &ProposalView) -> Result<ProposalView, ApiError> {
        let plan = self.e(0).plan_of(&from.id).unwrap();
        self.e(idx).import_proposal(self.v(idx), plan, None).await
    }
    async fn approve(&self, idx: usize, p: &ProposalView) -> Result<ProposalView, ApiError> {
        self.e(idx).approve(&p.id, true, &p.message_sha256).await
    }
}

fn code<T>(r: Result<T, ApiError>) -> &'static str { match r { Ok(_) => "ok", Err(e) => e.code } }

#[tokio::test(flavor = "multi_thread")]
async fn happy_path_two_of_three_to_confirmed() {
    let r = rig().await;
    let p = r.propose_ac("1000").await;
    assert_eq!((p.state, p.confirmations.count, p.confirmations.required), (State::Proposed, 0, 2));
    assert_eq!(p.summary.amount.raw, "1000");
    assert_eq!(p.summary.recipient, hex(&RECIPIENT));
    assert_eq!(p.integrity.status, "verified");
    let c = r.import(2, &p).await.unwrap();
    assert_eq!(c.origin, Origin::Imported);
    assert_eq!(c.summary, p.summary, "both nodes decode the same bytes to the same summary");
    assert_eq!(c.message_sha256, p.message_sha256);

    let a1 = r.approve(0, &p).await.unwrap();
    assert_eq!(a1.local_task, Some(Task::Approving));
    let seen = r.e(0).wait_for(&p.id, |v| v.state == State::Approved && v.confirmations.count >= 1, T).await.unwrap();
    assert_eq!(seen.confirmations.count, 1, "one of two");
    r.approve(2, &c).await.unwrap();

    let done = r.e(0).wait_for(&p.id, |v| v.state == State::Confirmed, T).await.unwrap();
    assert_eq!(done.confirmations.count, 2);
    assert!(done.signature.is_some() && done.broadcast.as_ref().map_or(false, |b| !b.uncertain));
    let c_done = r.e(2).wait_for(&c.id, |v| v.state == State::Confirmed, T).await.unwrap();
    assert!(c_done.broadcast.is_none(), "the imported side never broadcasts; it observed the chain");
    assert_eq!(r.chain.broadcasts(), 1, "exactly one broadcast in total");
    assert_eq!(r.chain.balance_of(&hex(&RECIPIENT)), 1000);
    assert_eq!(r.net.sign_calls(), 2);
    let kinds: Vec<_> = r.e(0).events(0, 100).into_iter().map(|e| e.kind).collect();
    for k in ["vault.created", "proposal.created", "proposal.approved", "proposal.signed", "proposal.broadcast", "proposal.confirmed"] {
        assert!(kinds.iter().any(|x| x == k), "missing event {k}: {kinds:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn tampered_bytes_are_refused_everywhere() {
    let r = rig().await;
    let p = r.propose_ac("1000").await;
    // Disk tampering: the bytes change, the stored summary does not.
    r.e(0).tamper(&p.id, |rec| {
        let mut b = rec.message_hex.clone().into_bytes();
        b[2 * 75 + 1] = b'f';
        rec.message_hex = String::from_utf8(b).unwrap();
    });
    let v = r.e(0).get_proposal(&p.id).unwrap();
    assert_eq!(v.integrity.status, "mismatch");
    assert_eq!(code(r.approve(0, &p).await), "bytes_summary_mismatch");
    assert_eq!(code(r.e(0).broadcast(&p.id).await), "bytes_summary_mismatch");
    assert_eq!(r.net.approve_calls(), 0, "the approval tool was never reached");

    // Summary tampered, bytes intact.
    let q = r.propose_ac("2000").await;
    r.e(0).tamper(&q.id, |rec| rec.summary.recipient = hex(&[1; 32]));
    assert_eq!(r.e(0).get_proposal(&q.id).unwrap().integrity.status, "mismatch");
    assert_eq!(code(r.approve(0, &q).await), "bytes_summary_mismatch");

    // The plan's message swapped while the stored bytes stay.
    let s = r.propose_ac("3000").await;
    r.e(0).tamper(&s.id, |rec| rec.plan["message"][0] = json!(1));
    assert_eq!(r.e(0).get_proposal(&s.id).unwrap().integrity.status, "mismatch");
    assert_eq!(code(r.approve(0, &s).await), "bytes_summary_mismatch");
    assert_eq!(r.net.approve_calls(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn imports_decode_the_bytes_themselves() {
    let r = rig().await;
    let p = r.propose_ac("1000").await;
    let plan = r.e(0).plan_of(&p.id).unwrap();

    let mut garbage = plan.clone();
    garbage["message"] = json!([1, 2, 3]);
    assert_eq!(code(r.e(2).import_proposal(r.v(2), garbage, None).await), "bad_request");

    // Bytes that spend from another address are refused, not summarised.
    let other = r.chain.build_transfer(&[5; 32], &hex(&RECIPIENT), 10, None).unwrap();
    let mut foreign = plan.clone();
    foreign["message"] = json!(other);
    foreign["operation_id"] = json!(vec![7_u8; 32]);
    assert_eq!(code(r.e(2).import_proposal(r.v(2), foreign, None).await), "bad_request");

    let mut huge = plan.clone();
    huge["message"] = json!(vec![0_u8; 9000]);
    huge["operation_id"] = json!(vec![8_u8; 32]);
    assert_eq!(code(r.e(2).import_proposal(r.v(2), huge, None).await), "message_too_large");

    let mut other_group = plan.clone();
    other_group["descriptor"]["group_verifying_key"] = json!(vec![3_u8; 32]);
    assert_eq!(code(r.e(2).import_proposal(r.v(2), other_group, None).await), "bad_request");
    assert_eq!(code(r.e(2).import_proposal(r.v(2), json!({"schema": 1}), None).await), "bad_request");
    assert!(r.e(2).list_proposals(None, None).unwrap().is_empty(), "nothing was stored");
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_approvals_are_refused() {
    let r = rig().await;
    let p = r.propose_ac("1000").await;
    r.approve(0, &p).await.unwrap();
    // While the first is running.
    let again = code(r.approve(0, &p).await);
    assert!(again == "busy" || again == "already_approved", "got {again}");
    r.e(0).wait_for(&p.id, |v| v.local_task == Some(Task::Signing) || v.state != State::Proposed, T).await.unwrap();
    assert_eq!(code(r.approve(0, &p).await), "already_approved");
    assert_eq!(r.net.approve_calls(), 1, "the tool was called once");
    assert_eq!(code(r.e(0).reject(&p.id, None)), "already_approved", "an approval cannot be retracted");

    // The node-level tool refuses a duplicate too, when something else already wrote the approval.
    let q = r.propose_ac("2000").await;
    r.net.approve_as(2, &r.e(0).plan_of(&q.id).unwrap());
    let c = r.import(2, &q).await.unwrap();
    let failed = r.approve(2, &c).await.unwrap();
    assert_eq!(failed.local_task, Some(Task::Approving));
    let v = r.e(2).wait_for(&c.id, |v| v.local_task.is_none(), T).await.unwrap();
    assert_eq!(v.state, State::Proposed);
    let f = v.failure.expect("failure recorded");
    assert_eq!(f.step, "approve");
    assert!(f.reason.contains("already approved"));
    assert_eq!(r.net.sign_calls(), 1, "no signing after a failed approval (only the first proposal signed once)");
}

#[tokio::test(flavor = "multi_thread")]
async fn non_selected_node_cannot_approve() {
    let r = rig().await;
    let p = r.propose_ac("1000").await;
    let b = r.import(1, &p).await.unwrap();
    assert!(b.signers.iter().all(|s| !s.local));
    assert_eq!(code(r.approve(1, &b).await), "not_selected");
    assert_eq!(r.net.approve_calls(), 0, "refused before the approval tool");
    // Proposer excluded itself.
    let q = r.e(0).create_proposal(&r.request("5", &[1, 2])).await.unwrap();
    assert_eq!(code(r.approve(0, &q).await), "not_selected");
    // And the simulated tool itself refuses, as the real one does.
    let plan = r.e(0).plan_of(&p.id).unwrap();
    let node = r.net.node(1);
    let dir = tmp();
    use holochain_mpc_vault::node::Node;
    let msg = holochain_mpc_vault::node::PlanView::parse(&plan).unwrap().message;
    assert!(node.approve(&plan, &msg, dir.path()).unwrap_err().0.contains("not a selected signer"));
    // Signer selection is validated.
    assert_eq!(code(r.e(0).create_proposal(&r.request("5", &[0])).await), "bad_request");
    assert_eq!(code(r.e(0).create_proposal(&r.request("5", &[0, 0])).await), "bad_request");
    let mut unknown = r.request("5", &[0, 2]);
    unknown.selected_signers = Some(vec![r.agent(0), "uNotAMember".into()]);
    assert_eq!(code(r.e(0).create_proposal(&unknown).await), "bad_request");
}

#[tokio::test(flavor = "multi_thread")]
async fn confirmation_must_name_the_reviewed_bytes() {
    let r = rig().await;
    let p = r.propose_ac("1000").await;
    assert_eq!(code(r.e(0).approve(&p.id, true, &hex(&[0; 32])).await), "hash_mismatch");
    assert_eq!(code(r.e(0).approve(&p.id, false, &p.message_sha256).await), "bad_request");
    assert_eq!(r.net.approve_calls(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn expiry_applies_only_before_signing_starts() {
    let r = rig().await;
    let p = r.propose_ac("1000").await;
    let q = r.propose_ac("2000").await;
    // One approval only: q is approved by A (signing waits for C), p is untouched.
    r.approve(0, &q).await.unwrap();
    r.e(0).wait_for(&q.id, |v| v.confirmations.count == 1, T).await.unwrap();
    r.clock.advance(3601);
    let v = r.e(0).get_proposal(&p.id).unwrap();
    assert_eq!(v.state, State::Expired);
    assert_eq!(code(r.approve(0, &p).await), "expired");
    assert_eq!(code(r.e(0).reject(&p.id, None)), "bad_state");
    let late = r.e(0).get_proposal(&q.id).unwrap();
    assert_ne!(late.state, State::Expired, "signing already started on this node; it is not cancelled");
    // An imported-but-untouched proposal expires the same way.
    let c = r.import(2, &q).await;
    assert!(c.is_ok());
    r.clock.advance(7200);
    let c = r.e(2).list_proposals(None, None).unwrap();
    assert_eq!(c[0].state, State::Expired);
    assert!(r.e(0).events(0, 100).iter().any(|e| e.kind == "proposal.expired"));
}

#[tokio::test(flavor = "multi_thread")]
async fn replay_is_refused() {
    let r = rig().await;
    let p = r.propose_ac("1000").await;
    // Same bytes again.
    assert_eq!(code(r.e(0).create_proposal(&r.request("1000", &[0, 2])).await), "replay");
    // The same plan imported twice.
    r.import(2, &p).await.unwrap();
    assert_eq!(code(r.import(2, &p).await), "replay");
    // A plan reusing the operation id with different bytes.
    let mut plan = r.e(0).plan_of(&p.id).unwrap();
    let other = r.chain.build_transfer(&r.net.group_key(), &hex(&[4; 32]), 77, None).unwrap();
    plan["message"] = json!(other);
    assert_eq!(code(r.e(2).import_proposal(r.v(2), plan, None).await), "replay");

    // A rejected proposal's bytes may be proposed again.
    let q = r.propose_ac("2000").await;
    r.e(0).reject(&q.id, Some("wrong amount")).unwrap();
    assert!(r.e(0).create_proposal(&r.request("2000", &[0, 2])).await.is_ok());

    // After confirmation, neither another broadcast nor the chain moves funds again.
    r.approve(0, &p).await.unwrap();
    r.approve(2, &r.e(2).list_proposals(None, None).unwrap().into_iter().find(|x| x.operation_id == p.operation_id).unwrap()).await.unwrap();
    r.e(0).wait_for(&p.id, |v| v.state == State::Confirmed, T).await.unwrap();
    assert_eq!(code(r.e(0).broadcast(&p.id).await), "broadcast_attempted");
    assert_eq!(code(r.import(2, &p).await), "replay");
    assert_eq!(r.chain.broadcasts(), 1);
    assert_eq!(r.chain.balance_of(&hex(&RECIPIENT)), 1000);
    // Approving a finished proposal is refused.
    assert_eq!(code(r.approve(0, &p).await), "bad_state");
}

#[tokio::test(flavor = "multi_thread")]
async fn uncertain_broadcast_is_polled_never_resent() {
    let r = rig().await;
    r.chain.land_but_report_uncertain();
    r.chain.pending_polls(3);
    let p = r.propose_ac("1000").await;
    let c = r.import(2, &p).await.unwrap();
    r.approve(0, &p).await.unwrap();
    r.approve(2, &c).await.unwrap();
    let mid = r.e(0).wait_for(&p.id, |v| v.state == State::Broadcast, T).await.unwrap();
    assert!(mid.broadcast.unwrap().txid.is_some());
    let done = r.e(0).wait_for(&p.id, |v| v.state == State::Confirmed, T).await.unwrap();
    assert!(done.timeline.iter().any(|t| t.event.contains("outcome unknown")));
    assert_eq!(r.chain.broadcasts(), 1, "resolved by polling the signature, not by resending");
}

#[tokio::test(flavor = "multi_thread")]
async fn rejected_broadcast_and_chain_failure_are_terminal() {
    let r = rig().await;
    r.chain.fail_next_broadcast(BroadcastError::Rejected("insufficient funds for fee".into()));
    let p = r.propose_ac("1000").await;
    let c = r.import(2, &p).await.unwrap();
    r.approve(0, &p).await.unwrap();
    r.approve(2, &c).await.unwrap();
    let f = r.e(0).wait_for(&p.id, |v| v.state == State::Failed, T).await.unwrap();
    assert_eq!(f.failure.as_ref().unwrap().step, "broadcast");
    assert_eq!(code(r.e(0).broadcast(&p.id).await), "broadcast_attempted");
    assert_eq!(r.chain.broadcasts(), 1, "no automatic retry");
    // The signature exists on the other node, which may broadcast once by hand.
    let c_signed = r.e(2).wait_for(&c.id, |v| v.signature.is_some(), T).await.unwrap();
    assert_eq!(c_signed.state, State::Signed);

    // A transaction the chain accepts and then fails.
    r.chain.fail_on_chain("custom program error");
    let q = r.e(0).create_proposal(&r.request("2000", &[0, 2])).await.unwrap();
    let c2 = r.import(2, &q).await.unwrap();
    r.approve(0, &q).await.unwrap();
    r.approve(2, &c2).await.unwrap();
    let f = r.e(0).wait_for(&q.id, |v| v.state == State::Failed, T).await.unwrap();
    assert_eq!(f.failure.unwrap().step, "confirm");
}

#[tokio::test(flavor = "multi_thread")]
async fn imported_side_broadcasts_once_by_hand() {
    let mut c = cfg();
    c.auto_broadcast = false;
    let r = rig_with(c).await;
    let p = r.propose_ac("1000").await;
    let c = r.import(2, &p).await.unwrap();
    r.approve(0, &p).await.unwrap();
    r.approve(2, &c).await.unwrap();
    r.e(2).wait_for(&c.id, |v| v.state == State::Signed, T).await.unwrap();
    assert_eq!(code(r.e(2).broadcast("prop-nope").await), "not_found");
    assert_eq!(code(r.e(1).broadcast(&c.id).await), "not_found");
    r.e(2).broadcast(&c.id).await.unwrap();
    assert_eq!(code(r.e(2).broadcast(&c.id).await), "broadcast_attempted");
    // A's own broadcast sees it already landed and sends nothing.
    r.e(0).wait_for(&p.id, |v| v.state == State::Signed || v.state == State::Confirmed, T).await.unwrap();
    let a = r.e(0).wait_for(&p.id, |v| v.state == State::Confirmed, T).await.unwrap();
    assert!(a.broadcast.is_none());
    assert_eq!(r.chain.broadcasts(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn stale_reference_fails_without_retry() {
    let r = rig().await;
    let p = r.propose_ac("1000").await;
    let c = r.import(2, &p).await.unwrap();
    r.chain.advance(50); // the mock's recent-reference window passes while people deliberate
    r.approve(0, &p).await.unwrap();
    r.approve(2, &c).await.unwrap();
    let f = r.e(0).wait_for(&p.id, |v| v.state == State::Failed, T).await.unwrap();
    assert!(f.failure.unwrap().reason.contains("expired"));
    assert_eq!(r.chain.broadcasts(), 1);
    assert_eq!(r.chain.balance_of(&hex(&RECIPIENT)), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn signing_failure_is_terminal_and_never_retried() {
    let r = rig().await; // sign_wait is 2 s and C never approves
    let p = r.propose_ac("1000").await;
    r.approve(0, &p).await.unwrap();
    let f = r.e(0).wait_for(&p.id, |v| v.state == State::Failed, T).await.unwrap();
    let fail = f.failure.unwrap();
    assert_eq!(fail.step, "sign");
    assert!(fail.action.contains("Do not retry"));
    assert_eq!(r.net.sign_calls(), 1);
    assert_eq!(code(r.approve(0, &p).await), "bad_state");
    assert_eq!(r.chain.broadcasts(), 0);
}

/// Live finding (27 Oct): the real signing profile signs `signed_message(plan)`, a domain-separated wrapper,
/// so the group signature is valid over that wrapper and not over a chain transaction. The vault must notice,
/// keep nothing, broadcast nothing and say why.
#[tokio::test(flavor = "multi_thread")]
async fn a_signature_over_a_wrapper_is_never_kept_or_broadcast() {
    let r = rig().await;
    r.net.set_domain_separated(true);
    let p = r.propose_ac("1000").await;
    let c = r.import(2, &p).await.unwrap();
    r.approve(0, &p).await.unwrap();
    r.approve(2, &c).await.unwrap();
    let f = r.e(0).wait_for(&p.id, |v| v.state == State::Failed, T).await.unwrap();
    let fail = f.failure.unwrap();
    assert_eq!(fail.step, "attach");
    assert!(fail.reason.contains("domain-separated"), "{}", fail.reason);
    assert!(f.signature.is_none() && f.broadcast.is_none());
    assert_eq!(r.chain.broadcasts(), 0);
    assert_eq!(r.chain.balance_of(&hex(&RECIPIENT)), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn reject_is_local_and_final() {
    let r = rig().await;
    let p = r.propose_ac("1000").await;
    let rej = r.e(0).reject(&p.id, Some("not expected")).unwrap();
    assert_eq!(rej.state, State::Rejected);
    assert_eq!(code(r.approve(0, &p).await), "bad_state");
    assert_eq!(code(r.e(0).reject(&p.id, None)), "bad_state");
    assert_eq!(r.net.approve_calls(), 0, "rejecting never touches the node tools");
    assert!(rej.timeline.iter().any(|t| t.event.contains("not expected")));
    assert_eq!(code(r.e(0).reject("prop-missing", None)), "not_found");
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_reads_remote_approvals() {
    let r = rig().await;
    let p = r.propose_ac("1000").await;
    assert!(p.signers.iter().any(|s| s.approved.is_none()), "remote approval unknown until read");
    r.net.approve_as(2, &r.e(0).plan_of(&p.id).unwrap());
    let v = r.e(0).refresh(&p.id).await.unwrap();
    assert_eq!((v.state, v.confirmations.count), (State::Approved, 1));
    assert_eq!(v.signers.iter().filter(|s| s.approved == Some(true)).count(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn request_validation() {
    let r = rig().await;
    for amount in ["", "abc", "0", "1.5", "-4", "99999999999999999999999", " "] {
        assert_eq!(code(r.e(0).create_proposal(&r.request(amount, &[0, 2])).await), "bad_request", "amount {amount:?}");
    }
    let mut bad = r.request("5", &[0, 2]);
    bad.recipient = "nothex".into();
    assert_eq!(code(r.e(0).create_proposal(&bad).await), "bad_request");
    bad.recipient = hex(&r.net.group_key());
    assert_eq!(code(r.e(0).create_proposal(&bad).await), "bad_request", "no transfer to self");
    bad.recipient = hex(&RECIPIENT);
    bad.memo = Some("x".repeat(141));
    assert_eq!(code(r.e(0).create_proposal(&bad).await), "bad_request");
    bad.memo = None;
    bad.vault_id = "vault-nope".into();
    assert_eq!(code(r.e(0).create_proposal(&bad).await), "not_found");
    assert_eq!(code(r.e(0).create_vault("again", "mock").await), "vault_exists");
    assert_eq!(code(r.e(0).create_vault("x", "solana-devnet").await), "bad_request");
    let mut short = r.request("5", &[0, 2]);
    short.expires_in_secs = Some(5);
    assert_eq!(code(r.e(0).create_proposal(&short).await), "bad_request");
    let pre = r.e(0).preview(&r.request("12", &[0, 2])).await.unwrap();
    assert_eq!(pre.summary.amount.raw, "12");
    assert!(r.e(0).list_proposals(None, None).unwrap().is_empty(), "preview stores nothing");
    let vault = r.e(0).get_vault(r.v(0)).await.unwrap();
    assert_eq!(vault.balance.unwrap().raw, "1000000");
    assert_eq!((vault.threshold, vault.members.len()), (2, 3));
    assert_eq!(vault.members.iter().filter(|m| m.local).count(), 1);
    assert!(vault.notes.iter().any(|n| n.contains("Policy enforcement")));
    assert!(vault.notes.iter().any(|n| n.contains("new DKG")));
}

#[tokio::test(flavor = "multi_thread")]
async fn restart_settles_interrupted_work_and_keeps_state() {
    let r = rig().await;
    let p = r.propose_ac("1000").await;
    let q = r.propose_ac("2000").await;
    let (a_dir, _) = (r.nodes[0].2.path().to_path_buf(), ());
    // Simulate a crash: edit the persisted records as the dead process left them.
    let edit = |id: &str, f: &dyn Fn(&mut Value)| {
        let path = a_dir.join("proposals").join(format!("{id}.json"));
        let mut v: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        f(&mut v);
        std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
    };
    edit(&p.id, &|v| { v["local_task"] = json!("signing"); v["signing_started"] = json!(true); v["local_approved"] = json!(true); v["state"] = json!("approved"); });
    edit(&q.id, &|v| { v["local_task"] = json!("approving"); });
    let engine = open(&r.nodes[0].2, &r.net, 0, &r.chain, &r.clock, cfg());
    let p2 = engine.get_proposal(&p.id).unwrap();
    assert_eq!((p2.state, p2.local_task), (State::Failed, None));
    assert_eq!(p2.failure.unwrap().step, "sign");
    let q2 = engine.get_proposal(&q.id).unwrap();
    assert_eq!((q2.state, q2.local_task), (State::Proposed, None));
    assert_eq!(q2.failure.unwrap().step, "approve");
    assert_eq!(engine.list_proposals(None, None).unwrap().len(), 2);
    assert_eq!(engine.list_vaults().len(), 1);
    assert!(engine.events(0, 10).len() >= 2, "event log is reloaded");
}

#[tokio::test(flavor = "multi_thread")]
async fn restart_during_broadcast_polls_and_never_resends() {
    let r = rig().await;
    let p = r.propose_ac("1000").await;
    let c = r.import(2, &p).await.unwrap();
    r.chain.land_but_report_uncertain();
    r.approve(0, &p).await.unwrap();
    r.approve(2, &c).await.unwrap();
    r.e(0).wait_for(&p.id, |v| v.state == State::Confirmed, T).await.unwrap();
    let a_dir = r.nodes[0].2.path().to_path_buf();
    let path = a_dir.join("proposals").join(format!("{}.json", p.id));
    let mut v: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    v["state"] = json!("signed");
    v["local_task"] = json!("broadcasting");
    v["broadcast"]["uncertain"] = json!(true);
    std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
    let engine = open(&r.nodes[0].2, &r.net, 0, &r.chain, &r.clock, cfg());
    let done = engine.wait_for(&p.id, |v| v.state == State::Confirmed, T).await.unwrap();
    assert!(done.timeline.iter().any(|t| t.event.contains("restarted during the broadcast")));
    assert_eq!(r.chain.broadcasts(), 1);
}

#[test]
fn state_files_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tmp();
    let store = Store::open(dir.path()).unwrap();
    store.save("vaults", "vault-1", &json!({"a": 1})).unwrap();
    let mode = std::fs::metadata(dir.path().join("vaults/vault-1.json")).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    assert!(store.save("vaults", "../evil", &json!(1)).is_err(), "ids cannot escape the directory");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Store::open(dir.path()).is_err(), "a group-readable data dir is refused");
}
