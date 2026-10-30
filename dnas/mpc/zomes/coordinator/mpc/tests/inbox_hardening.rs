//! Stage 2C: coordinator inbox availability (R10 offline half, R11).
//! `npm run build:happ` is REQUIRED before executing these tests.
//!
//! The file uses only extern names and declares its own mirror of the
//! `get_inbox_slots` response, so it also compiles against the Stage 2B
//! coordinator. There the R11 tests fail; that run is the reproduction.
//!
//! Most tests put four agents on ONE conductor and call Bob's
//! `receive_protocol_message` with another agent's provenance and Bob's real
//! assigned capability secret: the same grant and provenance checks as
//! `call_remote`, without the network, so races and floods are cheap. The last
//! test goes through `send_protocol_message` across three conductors.
use hdk::prelude::*;
use holochain::sweettest::*;
use holochain_mpc_core::{commitment, Envelope, SessionSpec, MAX_MESSAGES_PER_SESSION};
use mpc::{DeliveryReceipt, IncomingMessage, PreparedGrant, ReceiptStatus, SendMessage};
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

/// Mirror of the Stage 2C `get_inbox_slots` response.
#[derive(Deserialize, Debug)]
struct StoredVariant { envelope: Envelope, storage_actions: Vec<ActionHash> }
#[derive(Deserialize, Debug)]
struct WithheldSlot { sender: Vec<u8>, round: u32, sequence: u64, variants: Vec<StoredVariant> }
#[derive(Deserialize, Debug)]
struct InboxSlots { envelopes: Vec<Envelope>, conflicts: Vec<WithheldSlot>, over_quota: Vec<WithheldSlot> }

const ALICE: usize = 0;
const BOB: usize = 1; // the recipient in every test
const CAROL: usize = 2;
const DAVE: usize = 3; // same DNA, not a session participant
/// Stage 2C per-sender share for a three-member session (operator decision).
const QUOTA_OF_THREE: usize = 2_048;
/// Both native clients refuse a larger `get_inbox` response.
const CLIENT_INBOX_LIMIT: usize = 4_096;
const RACE_ATTEMPTS: u64 = 200;

fn dna_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../workdir/mpc.dna")
}

fn spec_for(members: &[AgentPubKey], label: &[u8]) -> SessionSpec {
    let mut participants: Vec<Vec<u8>> = members.iter().map(|a| a.get_raw_39().to_vec()).collect();
    participants.sort();
    SessionSpec {
        session_id: commitment("stage2c-session", label),
        application_id: "org.example.stage2c-inbox".into(),
        protocol_id: "opaque-rounds".into(),
        protocol_version: 1,
        context_hash: commitment("stage2c-context", label),
        participants,
        threshold: 2,
        max_round: 8,
    }
}

struct Inbox {
    conductor: SweetConductor,
    cells: Vec<SweetCell>,
    zomes: Vec<SweetZome>,
    agents: Vec<AgentPubKey>,
    spec: SessionSpec,
    proposal: ActionHash,
    /// Bob's assigned grant; its assignees are Alice and Carol.
    secret: CapSecret,
}

async fn session(conductor: &SweetConductor, zomes: &[SweetZome], cells: &[SweetCell],
                 spec: &SessionSpec) -> ActionHash {
    let proposal: ActionHash = conductor.call(&zomes[ALICE], "propose_session", spec.clone()).await;
    await_consistency(cells).await.unwrap();
    for i in [ALICE, BOB, CAROL] {
        let _: ActionHash = conductor.call(&zomes[i], "accept_session", proposal.clone()).await;
    }
    await_consistency(cells).await.unwrap();
    proposal
}

async fn inbox_fixture(label: &str) -> Inbox {
    let mut conductor = SweetConductor::standard().await;
    let dna = SweetDnaFile::from_bundle(&dna_path()).await.unwrap();
    let apps = conductor.setup_apps(label, 4, &[dna]).await.unwrap();
    let cells = apps.cells_flattened();
    let zomes: Vec<SweetZome> = cells.iter().map(|c| c.zome("mpc")).collect();
    let agents: Vec<AgentPubKey> = cells.iter().map(|c| c.agent_pubkey().clone()).collect();
    let spec = spec_for(&agents[..3], label.as_bytes());
    let proposal = session(&conductor, &zomes, &cells, &spec).await;
    let grant: PreparedGrant = conductor.call(&zomes[BOB], "prepare_inbox_grant", proposal.clone()).await;
    Inbox { conductor, cells, zomes, agents, spec, proposal, secret: grant.cap_secret }
}

impl Inbox {
    fn raw(&self, who: usize) -> Vec<u8> { self.agents[who].get_raw_39().to_vec() }

    fn envelope(&self, sender: usize, round: u32, sequence: u64, payload: &[u8]) -> Envelope {
        Envelope::new(&self.spec, self.raw(sender), Some(self.raw(BOB)), round, sequence, payload.to_vec())
            .unwrap()
    }

    async fn deliver_as(&self, caller: usize, proposal: &ActionHash, envelope: Envelope)
        -> Result<DeliveryReceipt, String> {
        self.conductor.call_from_fallible(&self.agents[caller], Some(self.secret.clone()), &self.zomes[BOB],
            "receive_protocol_message", IncomingMessage { proposal: proposal.clone(), envelope }).await
            .map_err(|e| format!("{e:?}"))
    }

    async fn deliver(&self, sender: usize, round: u32, sequence: u64, payload: &[u8])
        -> Result<DeliveryReceipt, String> {
        self.deliver_as(sender, &self.proposal, self.envelope(sender, round, sequence, payload)).await
    }

    async fn inbox(&self) -> Result<Vec<Envelope>, String> {
        self.conductor.call_fallible(&self.zomes[BOB], "get_inbox", self.proposal.clone()).await
            .map_err(|e| format!("{e:?}"))
    }

    async fn slots(&self) -> Result<InboxSlots, String> {
        self.conductor.call_fallible(&self.zomes[BOB], "get_inbox_slots", self.proposal.clone()).await
            .map_err(|e| format!("{e:?}"))
    }
}

/// Runs every delivery on its own runtime task, so they really overlap.
async fn concurrently(f: &Arc<Inbox>, calls: Vec<(usize, u32, u64, Vec<u8>)>)
    -> Vec<Result<DeliveryReceipt, String>> {
    let handles: Vec<_> = calls.into_iter().map(|(who, round, sequence, payload)| {
        let f = f.clone();
        tokio::spawn(async move { f.deliver(who, round, sequence, &payload).await })
    }).collect();
    let mut results = Vec::with_capacity(handles.len());
    for handle in handles { results.push(handle.await.expect("delivery task panicked")); }
    results
}

fn stored(result: Result<DeliveryReceipt, String>, what: &str) -> DeliveryReceipt {
    let receipt = result.unwrap_or_else(|e| panic!("{what}: delivery refused: {}", short(&e)));
    assert_eq!(receipt.status, ReceiptStatus::Stored, "{what}");
    receipt
}

fn short(text: &str) -> String { text.chars().take(600).collect() }

/// The refusal names its kind, and nothing suggests resending.
fn refused_with(result: Result<DeliveryReceipt, String>, kind: &str, what: &str) -> String {
    let error = match result {
        Ok(receipt) => panic!("{what}: expected a `{kind}` refusal, got {receipt:?}"),
        Err(e) => e,
    };
    assert!(error.contains(&format!("{kind}: ")), "{what}: expected kind `{kind}`, got: {}", short(&error));
    assert!(!error.to_lowercase().contains("retry"), "{what}: error text must not advise a retry: {}", short(&error));
    error
}

/// R11 (security review R6). Two concurrent deliveries for one
/// (sender, round, sequence) slot with different payloads can both commit
/// under relaxed ordering. The Stage 2B `get_inbox` then fails for the whole
/// proposal; Stage 2C withholds only that slot and reports both variants.
#[tokio::test(flavor = "multi_thread")]
async fn r11_conflicting_pair_leaves_unrelated_slots_readable() {
    let f = Arc::new(inbox_fixture("r11-conflict").await);
    let (alice, carol) = (f.raw(ALICE), f.raw(CAROL));
    stored(f.deliver(CAROL, 1, 1, b"carol-round-1").await, "Carol before the attack");

    let mut won = None;
    let mut refusals = 0;
    for sequence in 1..=RACE_ATTEMPTS {
        let mut pair = concurrently(&f, vec![(ALICE, 2, sequence, b"alice-left".to_vec()),
                                             (ALICE, 2, sequence, b"alice-right".to_vec())]).await;
        let (right, left) = (pair.pop().unwrap(), pair.pop().unwrap());
        match (left, right) {
            (Ok(l), Ok(r)) if l.status == ReceiptStatus::Stored && r.status == ReceiptStatus::Stored => {
                won = Some((sequence, l.storage_action, r.storage_action));
                break;
            }
            (l, r) => refusals += usize::from(l.is_err()) + usize::from(r.is_err()),
        }
    }
    let (sequence, left_action, right_action) = won.unwrap_or_else(||
        panic!("no conflicting pair committed in {RACE_ATTEMPTS} concurrent attempts"));
    println!("R11 race: both variants committed at attempt {sequence} ({refusals} earlier refusals)");

    // An unrelated later slot: Carol's first signing-round message.
    stored(f.deliver(CAROL, 4, 7, b"carol-round-4").await, "Carol after the attack");

    let inbox = f.inbox().await;
    println!("get_inbox after the conflict: {}",
        inbox.as_ref().map(|v| format!("Ok({} envelopes)", v.len())).unwrap_or_else(|e| short(e)));
    let inbox = inbox.expect("one conflicting slot must not make the whole inbox unreadable");
    assert!(inbox.iter().any(|e| e.sender == carol && e.round == 1 && e.payload == b"carol-round-1"));
    assert!(inbox.iter().any(|e| e.sender == carol && e.round == 4 && e.payload == b"carol-round-4"));
    assert!(!inbox.iter().any(|e| e.sender == alice && e.round == 2 && e.sequence == sequence),
        "neither conflicting variant may be served as if it were authoritative");
    // The losing halves of earlier attempts left single-variant slots.
    assert_eq!(inbox.iter().filter(|e| e.sender == alice).count() as u64, sequence - 1);

    let slots = f.slots().await.expect("get_inbox_slots");
    assert_eq!(slots.envelopes, inbox, "get_inbox serves exactly the unconflicted slots");
    assert!(slots.over_quota.is_empty());
    assert_eq!(slots.conflicts.len(), 1, "only the attacked slot is withheld");
    let conflict = &slots.conflicts[0];
    assert_eq!((&conflict.sender, conflict.round, conflict.sequence), (&alice, 2, sequence));
    assert_eq!(conflict.variants.len(), 2, "both variants are kept as evidence");
    let payloads: BTreeSet<&[u8]> = conflict.variants.iter().map(|v| v.envelope.payload.as_slice()).collect();
    assert_eq!(payloads, BTreeSet::from([&b"alice-left"[..], &b"alice-right"[..]]));
    assert!(conflict.variants.iter().all(|v| v.storage_actions.len() == 1));
    let actions: BTreeSet<&ActionHash> = conflict.variants.iter().flat_map(|v| &v.storage_actions).collect();
    assert_eq!(actions.len(), 2);
    // Under relaxed ordering the action a concurrent `create` returns is
    // hashed before the commit rebases it onto the moved head, so a receipt
    // can name an action that is not on the chain. Record it; do not rely on it.
    let rebased = [&left_action, &right_action].into_iter().filter(|a| !actions.contains(a)).count();
    println!("receipt actions not found on the chain after the race: {rebased} of 2");
    let stored_left = conflict.variants.iter().find(|v| v.envelope.payload == b"alice-left").unwrap()
        .storage_actions[0].clone();

    // Repeating a stored variant writes nothing; a third payload is refused.
    let again = stored_or_already(f.deliver(ALICE, 2, sequence, b"alice-left").await);
    assert_eq!((again.status, &again.storage_action), (ReceiptStatus::AlreadyStored, &stored_left));
    refused_with(f.deliver(ALICE, 2, sequence, b"alice-third").await, "inbox_conflict", "third variant");
    stored(f.deliver(CAROL, 4, 8, b"carol-later").await, "Carol keeps delivering");
}

fn stored_or_already(result: Result<DeliveryReceipt, String>) -> DeliveryReceipt {
    result.unwrap_or_else(|e| panic!("repeat delivery refused: {}", short(&e)))
}

/// R11 capacity half. One sender floods distinct slots. Stage 2B has no
/// per-sender limit: it accepts the flood until the shared 16,384 capacity,
/// and already at 4,097 envelopes the recipient's native clients
/// (`conductor_client.rs`, the DKG relay) refuse the whole inbox, honest
/// senders' slots included. The flood stops there to keep the run short.
/// Stage 2C stops the flooder at its own share.
#[tokio::test(flavor = "multi_thread")]
async fn r11_one_sender_cannot_exhaust_another_senders_allocation() {
    let f = inbox_fixture("r11-flood").await;
    let (alice, carol) = (f.raw(ALICE), f.raw(CAROL));
    assert!(CLIENT_INBOX_LIMIT < MAX_MESSAGES_PER_SESSION);
    let started = std::time::Instant::now();
    let mut accepted = 0_usize;
    let mut refusal = None;
    for sequence in 1..=(CLIENT_INBOX_LIMIT as u64 + 1) {
        match f.deliver(ALICE, 5, sequence, &sequence.to_be_bytes()).await {
            Ok(receipt) => { assert_eq!(receipt.status, ReceiptStatus::Stored); accepted += 1; }
            Err(e) => { refusal = Some(e); break; }
        }
    }
    println!("flood: Alice stored {accepted} before refusal in {:?}: {}", started.elapsed(),
        refusal.as_deref().map(short).unwrap_or_default());

    let honest = f.deliver(CAROL, 1, 1, b"carol-after-flood").await;
    println!("Carol after the flood: {}", match &honest { Ok(r) => format!("{:?}", r.status), Err(e) => short(e) });
    let served = f.inbox().await.map(|v| v.len());
    println!("get_inbox after the flood: {served:?} envelopes (native clients refuse more than {CLIENT_INBOX_LIMIT})");
    stored(honest, "Carol must keep her own allocation");
    assert_eq!(accepted, QUOTA_OF_THREE, "Alice stops at her share");
    refused_with(Err(refusal.expect("flood never refused")), "inbox_sender_quota", "flood");

    let inbox = f.inbox().await.expect("get_inbox after the flood");
    assert!(inbox.len() <= CLIENT_INBOX_LIMIT, "the native clients refuse a larger inbox");
    assert_eq!(inbox.iter().filter(|e| e.sender == alice).count(), QUOTA_OF_THREE);
    assert!(inbox.iter().any(|e| e.sender == carol && e.payload == b"carol-after-flood"));
    // Carol can use her whole share as well.
    for sequence in 2..=QUOTA_OF_THREE as u64 {
        stored(f.deliver(CAROL, 5, sequence, b"c").await, "Carol fills her share");
    }
    refused_with(f.deliver(CAROL, 5, QUOTA_OF_THREE as u64 + 1, b"c").await, "inbox_sender_quota", "Carol over");
    let inbox = f.inbox().await.expect("get_inbox with both shares full");
    assert_eq!(inbox.len(), 2 * QUOTA_OF_THREE);
}

/// The write-side quota check reads the chain before writing, so concurrent
/// deliveries can all pass it. The served quota is enforced on read and
/// cannot be overrun; the overshoot is stored and reported, not served.
#[tokio::test(flavor = "multi_thread")]
async fn r11_concurrent_deliveries_cannot_overrun_the_served_quota() {
    let f = Arc::new(inbox_fixture("r11-race-quota").await);
    let (alice, carol) = (f.raw(ALICE), f.raw(CAROL));
    let headroom = 8;
    for sequence in 1..=(QUOTA_OF_THREE - headroom) as u64 {
        stored(f.deliver(ALICE, 5, sequence, b"fill").await, "fill");
    }
    let burst = 64_u64;
    let results = concurrently(&f, (1..=burst).map(|s| (ALICE, 6, s, b"burst".to_vec())).collect()).await;
    let burst_stored = results.iter().filter(|r| matches!(r, Ok(x) if x.status == ReceiptStatus::Stored)).count();
    let errors: Vec<&String> = results.iter().filter_map(|r| r.as_ref().err()).collect();
    println!("concurrent burst of {burst} with {headroom} places left: {burst_stored} stored, {} refused, write overshoot {}",
        errors.len(), burst_stored.saturating_sub(headroom));
    for e in &errors {
        assert!(e.contains("inbox_sender_quota: "), "burst refusal of another kind: {}", short(e));
    }
    refused_with(f.deliver(ALICE, 7, 1, b"after").await, "inbox_sender_quota", "after the burst");
    stored(f.deliver(CAROL, 1, 1, b"carol").await, "Carol during Alice's race");

    let total = QUOTA_OF_THREE - headroom + burst_stored;
    let inbox = f.inbox().await.expect("get_inbox after the race");
    assert_eq!(inbox.iter().filter(|e| e.sender == alice).count(), total.min(QUOTA_OF_THREE),
        "never more than the share is served");
    assert!(inbox.iter().any(|e| e.sender == carol));
    assert!(inbox.len() <= CLIENT_INBOX_LIMIT);
    let slots = f.slots().await.expect("get_inbox_slots");
    assert!(slots.conflicts.is_empty());
    assert_eq!(slots.over_quota.len(), total.saturating_sub(QUOTA_OF_THREE), "overshoot is reported");
    assert!(slots.over_quota.iter().all(|s| s.sender == alice && s.variants.len() == 1));
}

/// R10. Honest fan-in: two members deliver many distinct slots at once, as in
/// every DKG round. All must be stored (the 17 October strict-ordering
/// coordinator failed all but one with HeadMoved).
#[tokio::test(flavor = "multi_thread")]
async fn r10_concurrent_honest_fan_in_is_stored() {
    let f = Arc::new(inbox_fixture("r10-fan-in").await);
    let per_sender = 16_u64;
    let calls = (1..=per_sender).flat_map(|s| [(ALICE, 1, s, b"fan-in".to_vec()), (CAROL, 1, s, b"fan-in".to_vec())]);
    let results = concurrently(&f, calls.collect()).await;
    let failures: Vec<&String> = results.iter().filter_map(|r| r.as_ref().err()).collect();
    println!("fan-in of {}: {} stored, {} failed", results.len(), results.len() - failures.len(), failures.len());
    for e in failures.iter().take(3) { println!("  failure: {}", short(e)); }
    assert!(failures.is_empty(), "concurrent honest deliveries must not fail");
    let inbox = f.inbox().await.expect("get_inbox after fan-in");
    assert_eq!(inbox.len(), 2 * per_sender as usize);
}

/// The quota and the inbox are bound to the authenticated caller and to the
/// proposal's own session, never to envelope fields the caller controls.
#[tokio::test(flavor = "multi_thread")]
async fn membership_and_context_binding_survive_hardening() {
    let f = inbox_fixture("membership").await;
    let alice = f.raw(ALICE);
    stored(f.deliver(ALICE, 1, 1, b"alice-1").await, "Alice");

    // Dave is not an assignee of Bob's grant: the conductor refuses the call.
    let dave = f.deliver_as(DAVE, &f.proposal, f.envelope(ALICE, 1, 2, b"dave-as-alice")).await;
    assert!(dave.is_err(), "a non-member must not reach the inbox");
    // Carol may call, but not as Alice.
    refused_with(f.deliver_as(CAROL, &f.proposal, f.envelope(ALICE, 1, 3, b"carol-as-alice")).await,
        "inbox_unauthorized", "forged sender");
    // An envelope addressed to Carol cannot be stored in Bob's inbox.
    let mut to_carol = f.envelope(ALICE, 1, 4, b"to-carol");
    to_carol.recipient = Some(f.raw(CAROL));
    refused_with(f.deliver_as(ALICE, &f.proposal, to_carol).await, "inbox_unauthorized", "wrong recipient");
    // Malformed fields.
    let mut tampered = f.envelope(ALICE, 1, 5, b"payload");
    tampered.payload = b"other".to_vec();
    refused_with(f.deliver_as(ALICE, &f.proposal, tampered).await, "inbox_invalid_argument", "digest");
    let mut late = f.envelope(ALICE, 1, 6, b"late");
    late.round = f.spec.max_round + 1;
    refused_with(f.deliver_as(ALICE, &f.proposal, late).await, "inbox_invalid_argument", "round");
    let mut zero = f.envelope(ALICE, 1, 7, b"zero");
    zero.sequence = 0;
    refused_with(f.deliver_as(ALICE, &f.proposal, zero).await, "inbox_invalid_argument", "sequence");
    let unknown = ActionHash::from_raw_36(vec![7; 36]);
    refused_with(f.deliver_as(ALICE, &unknown, f.envelope(ALICE, 1, 8, b"x")).await, "inbox_missing", "proposal");

    // A second group with the same members: its envelopes cannot be filed
    // under the first proposal, and its inbox and share are separate.
    let other_spec = spec_for(&f.agents[..3], b"membership-other");
    let other = session(&f.conductor, &f.zomes, &f.cells, &other_spec).await;
    let foreign = Envelope::new(&other_spec, alice.clone(), Some(f.raw(BOB)), 1, 9, b"other-group".to_vec()).unwrap();
    refused_with(f.deliver_as(ALICE, &f.proposal, foreign.clone()).await, "inbox_invalid_argument", "session");
    stored(f.deliver_as(ALICE, &other, foreign).await, "the other group");

    let inbox = f.inbox().await.expect("get_inbox");
    assert_eq!(inbox.len(), 1);
    assert_eq!((&inbox[0].sender, inbox[0].payload.as_slice()), (&alice, &b"alice-1"[..]));
    let other_inbox: Vec<Envelope> = f.conductor.call(&f.zomes[BOB], "get_inbox", other).await;
    assert_eq!(other_inbox.len(), 1);
    assert_eq!(other_inbox[0].session_id, other_spec.session_id);
    let slots = f.slots().await.expect("get_inbox_slots");
    assert!(slots.conflicts.is_empty() && slots.over_quota.is_empty());
    // A non-member cannot read Bob's inbox either.
    let read: Result<Vec<Envelope>, _> = f.conductor.call_fallible(&f.zomes[DAVE], "get_inbox", f.proposal.clone()).await;
    assert!(format!("{:?}", read.unwrap_err()).contains("inbox_unauthorized: "));
}

/// Three conductors; Bob and Carol have each prepared an inbox grant.
struct Network {
    net: Arc<(SweetConductorBatch, Vec<SweetZome>)>,
    agents: Vec<AgentPubKey>,
    proposal: ActionHash,
    bob_secret: CapSecret,
    carol_secret: CapSecret,
}

async fn network_fixture(label: &str) -> Network {
    let mut conductors = SweetConductorBatch::standard(3).await;
    let dna = SweetDnaFile::from_bundle(&dna_path()).await.unwrap();
    let apps = conductors.setup_app(label, &[dna]).await.unwrap();
    let cells = apps.cells_flattened();
    let zomes: Vec<SweetZome> = cells.iter().map(|c| c.zome("mpc")).collect();
    let agents: Vec<AgentPubKey> = cells.iter().map(|c| c.agent_pubkey().clone()).collect();
    let spec = spec_for(&agents, label.as_bytes());
    let proposal: ActionHash = conductors[ALICE].call(&zomes[ALICE], "propose_session", spec).await;
    await_consistency(&cells).await.unwrap();
    for i in [ALICE, BOB, CAROL] {
        let _: ActionHash = conductors[i].call(&zomes[i], "accept_session", proposal.clone()).await;
    }
    await_consistency(&cells).await.unwrap();
    let bob: PreparedGrant = conductors[BOB].call(&zomes[BOB], "prepare_inbox_grant", proposal.clone()).await;
    let carol: PreparedGrant = conductors[CAROL].call(&zomes[CAROL], "prepare_inbox_grant", proposal.clone()).await;
    Network { net: Arc::new((conductors, zomes)), agents, proposal,
              bob_secret: bob.cap_secret, carol_secret: carol.cap_secret }
}

impl Network {
    fn to_bob(&self, round: u32, sequence: u64, payload: &[u8], secret: &CapSecret) -> SendMessage {
        SendMessage { proposal: self.proposal.clone(), recipient: self.agents[BOB].clone(), round, sequence,
                      payload: payload.to_vec(), recipient_cap_secret: secret.clone() }
    }

    /// `send_protocol_message` on `from`'s own conductor, as its own task.
    fn send(&self, from: usize, message: SendMessage)
        -> tokio::task::JoinHandle<Result<DeliveryReceipt, String>> {
        let net = self.net.clone();
        tokio::spawn(async move {
            net.0[from].call_fallible::<_, DeliveryReceipt>(&net.1[from], "send_protocol_message", message).await
                .map_err(|e| format!("{e:?}"))
        })
    }

    async fn bob_inbox(&self) -> Vec<Envelope> {
        self.net.0[BOB].call(&self.net.1[BOB], "get_inbox", self.proposal.clone()).await
    }
}

/// The sender sees the recipient's refusal kind through `call_remote`.
/// Holochain returns a remote guest error as `NetworkError` text, so the
/// Stage 2B sender reported every such refusal as a network failure.
#[tokio::test(flavor = "multi_thread")]
async fn send_protocol_message_keeps_the_remote_failure_kind() {
    let n = network_fixture("stage2c-send").await;
    let bob = n.bob_secret.clone();
    stored(n.send(ALICE, n.to_bob(1, 1, b"first", &bob)).await.unwrap(), "honest send");
    let conflict = refused_with(n.send(ALICE, n.to_bob(1, 1, b"second", &bob)).await.unwrap(),
        "inbox_conflict", "remote conflict");
    println!("remote conflict as seen by the sender: {}", short(&conflict));
    assert!(conflict.contains("not stored"), "a remote refusal is a certain outcome: {}", short(&conflict));
    let wrong_cap = refused_with(n.send(ALICE, n.to_bob(1, 2, b"x", &n.carol_secret)).await.unwrap(),
        "inbox_unauthorized", "wrong capability");
    assert!(wrong_cap.contains("not stored"));
    let self_send = SendMessage { recipient: n.agents[ALICE].clone(), ..n.to_bob(1, 3, b"x", &bob) };
    refused_with(n.send(ALICE, self_send).await.unwrap(), "inbox_invalid_argument", "send to self");
    assert_eq!(n.bob_inbox().await.len(), 1);
}

/// R10 over the network: concurrent honest fan-in through `call_remote`.
#[tokio::test(flavor = "multi_thread")]
async fn r10_network_fan_in_is_stored() {
    let n = network_fixture("stage2c-fan-in").await;
    let handles: Vec<_> = (1..=8_u64).flat_map(|s| [(ALICE, s), (CAROL, s)])
        .map(|(from, s)| n.send(from, n.to_bob(2, s, b"fan-in", &n.bob_secret))).collect();
    let mut results = Vec::new();
    for handle in handles { results.push(handle.await.expect("send task panicked")); }
    let failures: Vec<&String> = results.iter().filter_map(|r| r.as_ref().err()).collect();
    println!("network fan-in of {}: {} failed", results.len(), failures.len());
    for e in failures.iter().take(3) { println!("  network fan-in failure: {}", short(e)); }
    assert!(failures.is_empty(), "{} of {} network deliveries failed", failures.len(), results.len());
    assert_eq!(n.bob_inbox().await.len(), 16);
}
