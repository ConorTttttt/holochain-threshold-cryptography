//! Phase 3 deterministic simulation of 3 independent relay state machines.
//! This is NOT proof of authenticated Holochain API or independent machines:
//! `LocalPort` uses test-only in-process FROST controllers and `Network` is an
//! in-memory stand-in for authenticated zome responses.
use holochain_mpc_core::{commitment, Envelope, SessionSpec};
use holochain_mpc_dkg_worker::conductor_bridge::KeyEvidence;
use holochain_mpc_dkg_worker::relay::{LocalDkgNode, MpcTransport, Phase, RelayEngine, SendReceipt};
use holochain_mpc_dkg_worker::{Command, Controller, PeerKeyBinding, Reply};
use holochain_mpc_frost_ed25519::Binding;
use holochain_mpc_security::activation::GroupDescriptor;
use holochain_mpc_security::sealed::SealedPacket;
use std::collections::BTreeMap;
use std::sync::{Arc,Mutex};

#[derive(Default)]
struct Network {
    inbox: BTreeMap<Vec<u8>, Vec<Envelope>>,
    keys: Vec<KeyEvidence>,
    stop_send: bool,
    /// Key registrations not yet visible through this stand-in DHT.
    hidden_keys: Vec<Vec<u8>>,
}
struct Transport { shared: Arc<Mutex<Network>>, local: Vec<u8> }
impl MpcTransport for Transport {
    async fn register_key(&mut self, key: [u8;32]) -> Result<Vec<u8>,String> {
        let mut net=self.shared.lock().unwrap();
        if net.keys.iter().any(|record| record.author == self.local) {
            return Err("duplicate local key registration".into());
        }
        let action=vec![self.local[0].wrapping_add(9);39];
        net.keys.push(KeyEvidence {author:self.local.clone(),
            action:action.clone(),public_key:key});
        Ok(action)
    }
    async fn get_inbox(&mut self) -> Result<Vec<Envelope>,String> {
        Ok(self.shared.lock().unwrap().inbox.get(&self.local).cloned().unwrap_or_default())
    }
    async fn get_encryption_keys(&mut self) -> Result<Vec<KeyEvidence>,String> {
        let net = self.shared.lock().unwrap();
        Ok(net.keys.iter().filter(|k| !net.hidden_keys.contains(&k.author)).cloned().collect())
    }
    async fn publish(&mut self, env: &Envelope) -> Result<SendReceipt,String> {
        let mut net = self.shared.lock().unwrap();
        if net.stop_send { return Err("indeterminate network send".into()); }
        let recipient = env.recipient.clone().ok_or("no recipient")?;
        net.inbox.entry(recipient).or_default().push(env.clone());
        Ok(SendReceipt { action: vec![8;39], already_stored: false })
    }
}
struct LocalPort { id: Vec<u8>, binding: Binding, controller: Controller }
impl LocalPort {
    fn invoke(&mut self, cmd: Command) -> Result<Reply,String> { self.controller.handle(cmd) }
}
impl LocalDkgNode for LocalPort {
    fn initialize(&mut self) -> Result<([u8;32],Vec<Envelope>),String> {
        let Reply::Initialized { local_public_key, outbound } = self.invoke(
            Command::Init { binding:self.binding.clone(),local:self.id.clone() })? else {
            return Err("wrong initialized reply".into());
        };
        Ok((local_public_key,outbound))
    }
    fn deliver(&mut self, env: Envelope) -> Result<Vec<Envelope>,String> {
        let Reply::Delivered { outbound } = self.invoke(Command::Deliver {
            authenticated_sender:env.sender.clone(), envelope:env,
        })? else { return Err("wrong deliver reply".into()); };
        Ok(outbound)
    }
    fn attest(&mut self) -> Result<Vec<Envelope>,String> {
        let Reply::Attesting { outbound } = self.invoke(Command::Attest)? else {
            return Err("wrong attest reply".into());
        };
        Ok(outbound)
    }
    fn round_two(&mut self, records: &[KeyEvidence], own_key: [u8;32])
        -> Result<([u8;32],Vec<Envelope>),String> {
        if records.len() != self.binding.spec.participants.len() ||
            !records.iter().any(|r| r.author == self.id && r.public_key == own_key) {
            return Err("test key binding incomplete".into());
        }
        let pins: Vec<_> = records.iter().map(|r| PeerKeyBinding {
            member:r.author.clone(), public_key:r.public_key, action:r.action.clone(),
        }).collect();
        let Reply::RoundTwo { transcript_hash,outbound } = self.invoke(
            Command::BeginRoundTwo {pinned_keys:pins})? else {
            return Err("wrong round two reply".into());
        };
        Ok((transcript_hash,outbound))
    }
    fn finalize(&mut self) -> Result<GroupDescriptor,String> {
        let Reply::Completed {descriptor} = self.invoke(Command::Finalize)? else {
            return Err("wrong finalize reply".into());
        };
        Ok(descriptor)
    }
    fn validate_outbound(&self, out: &[Envelope]) -> Result<(),String> {
        for env in out {
            env.validate_against(&self.binding.spec).map_err(|e| e.to_string())?;
            if env.sender != self.id || env.recipient.is_none() { return Err("bad outbound".into()); }
            if env.round == 3 && !serde_json::from_slice::<SealedPacket>(&env.payload)
                .map(|p| p.structurally_valid()).unwrap_or(false) {
                return Err("unencrypted share".into());
            }
        }
        Ok(())
    }
}

fn make_binding() -> Binding {
    Binding::new(vec![0xc8;39], SessionSpec {
        session_id:commitment("relay-sim-session",b"test"),
        application_id:"org.example.relay.simulation".into(),
        protocol_id:"frost-ed25519".into(),protocol_version:1,
        context_hash:commitment("relay-sim-context",b"test"),
        participants:(1u8..=3).map(|i| vec![i;39]).collect(),
        threshold:2, max_round:6,
    }).unwrap()
}
fn make_relay(binding: &Binding, member: u8, network: Arc<Mutex<Network>>)
    -> RelayEngine<LocalPort, Transport> {
    let id = vec![member;39];
    RelayEngine::new(LocalPort { id:id.clone(), binding:binding.clone(),
        controller:Controller::default() },
        Transport {shared:network,local:id.clone()}, binding.clone(),id).unwrap()
}

#[tokio::test]
async fn three_automatic_relays_complete_dkg_without_manual_round_routing() {
    let binding = make_binding();
    let shared = Arc::new(Mutex::new(Network::default()));
    let mut parties: Vec<_> = (1..=3).map(|member| make_relay(&binding,member,shared.clone())).collect();
    for relay in &mut parties { assert_eq!(relay.start().await.unwrap().phase,Phase::Echo); }
    assert_eq!(shared.lock().unwrap().keys.len(),3,
        "each participant must register its own X25519 key");
    for _ in 0..20 {
        for relay in &mut parties {
            if relay.phase() != Phase::Complete { relay.poll_once().await.unwrap(); }
        }
        if parties.iter().all(|p| p.phase() == Phase::Complete) { break; }
    }
    assert!(parties.iter().all(|p| p.phase() == Phase::Complete), "all parties must finish");
    let result = parties[0].descriptor().unwrap();
    assert!(parties.iter().all(|p| p.descriptor().unwrap() == result));
    // Reaching completion does not make native KeyPackages available here.
}

#[tokio::test]
async fn publication_failure_permanently_poisoned() {
    let binding = make_binding();
    let shared = Arc::new(Mutex::new(Network {stop_send:true,..Default::default()}));
    let mut relay = make_relay(&binding,1,shared);
    assert!(relay.start().await.is_err());
    assert_eq!(relay.phase(),Phase::Aborted);
    assert!(relay.start().await.is_err());
}

#[tokio::test]
async fn conflicting_duplicate_inbox_and_cross_session_fail_closed() {
    let binding = make_binding();
    let shared = Arc::new(Mutex::new(Network::default()));
    let mut relay = make_relay(&binding,1,shared.clone());
    relay.start().await.unwrap();
    let mut input = Envelope::new(&binding.spec,vec![2;39],Some(vec![1;39]),1,1,
        b"bad broadcast content".to_vec()).unwrap();
    let mut other = input.clone(); other.payload = b"conflicting".to_vec();
    other.payload_hash = commitment("envelope-payload", &other.payload);
    shared.lock().unwrap().inbox.insert(vec![1;39],vec![input.clone(),other]);
    assert!(relay.poll_once().await.is_err());
    assert_eq!(relay.phase(),Phase::Aborted);

    input.session_id = [0x90;32];
    // Phase 3 requires the conductor to authenticate the inbox. Even a
    // trusted-but-incorrect response is rejected before worker delivery.
    let net3 = Arc::new(Mutex::new(Network::default()));
    let mut relay3 = make_relay(&binding,1,net3.clone());
    relay3.start().await.unwrap();
    net3.lock().unwrap().inbox.insert(vec![1;39],vec![input]);
    assert!(relay3.poll_once().await.is_err());
    assert_eq!(relay3.phase(),Phase::Aborted);
}

/// Holochain is eventually consistent: a peer's key registration can arrive
/// after its attestation. The relays must wait, not abort, and then finish.
#[tokio::test]
async fn late_visible_key_registration_waits_then_completes() {
    let binding = make_binding();
    let shared = Arc::new(Mutex::new(Network::default()));
    shared.lock().unwrap().hidden_keys.push(vec![3;39]);
    let mut parties: Vec<_> = (1..=3).map(|member| make_relay(&binding,member,shared.clone())).collect();
    for relay in &mut parties { relay.start().await.unwrap(); }
    for _ in 0..10 {
        for relay in &mut parties { relay.poll_once().await.unwrap(); }
    }
    assert!(parties.iter().all(|p| p.phase() == Phase::Attest), "must wait for the full key roster");
    shared.lock().unwrap().hidden_keys.clear();
    for _ in 0..20 {
        for relay in &mut parties {
            if relay.phase() != Phase::Complete { relay.poll_once().await.unwrap(); }
        }
    }
    assert!(parties.iter().all(|p| p.phase() == Phase::Complete));
}

/// A second, different key record for one member is a fork: fail closed.
#[tokio::test]
async fn forked_key_registration_aborts() {
    let binding = make_binding();
    let shared = Arc::new(Mutex::new(Network::default()));
    let mut parties: Vec<_> = (1..=3).map(|member| make_relay(&binding,member,shared.clone())).collect();
    for relay in &mut parties { relay.start().await.unwrap(); }
    shared.lock().unwrap().keys.push(KeyEvidence {
        author: vec![2;39], action: vec![0x55;39], public_key: [0x66;32] });
    let mut aborted = false;
    for _ in 0..10 {
        for relay in &mut parties {
            if relay.phase() == Phase::Aborted { continue; }
            if relay.poll_once().await.is_err() { aborted = true; }
        }
    }
    assert!(aborted && parties.iter().all(|p| p.phase() != Phase::Complete),
        "a forked registration must never reach Round 2");
}
