//! A simulated 2-of-3 group for tests. It holds one real Ed25519 key and
//! signs only when two selected signers have approved, which is what the real
//! flow guarantees. It repeats the real tools' refusals: non-selected
//! approvers, duplicate approvals, altered messages, a second signing run.
use crate::node::*;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

#[derive(Default)]
struct NetState {
    approvals: BTreeMap<[u8; 32], BTreeSet<Vec<u8>>>,
    signed_by: BTreeSet<([u8; 32], Vec<u8>)>,
    approve_calls: u32,
    sign_calls: u32,
}

pub struct MockNet {
    key: SigningKey,
    pub members: Vec<Vec<u8>>,
    state: Mutex<NetState>,
    cv: Condvar,
    /// Behave like the real signing profile, which signs a domain-separated wrapper, not the raw message.
    domain_separated: std::sync::atomic::AtomicBool,
}

impl MockNet {
    pub fn new() -> Arc<Self> {
        let members = (1..=3_u8).map(|i| { let mut a = vec![0x84, 0x20, 0x24]; a.extend([i; 32]); a.extend([0; 4]); a }).collect();
        Arc::new(Self { key: SigningKey::from_bytes(&[42; 32]), members, state: Mutex::default(), cv: Condvar::new(),
            domain_separated: Default::default() })
    }
    pub fn group_key(&self) -> [u8; 32] { self.key.verifying_key().to_bytes() }
    pub fn node(self: &Arc<Self>, index: usize) -> MockNode {
        MockNode { net: self.clone(), local: index, sign_wait: Duration::from_secs(5) }
    }
    pub fn set_domain_separated(&self, on: bool) { self.domain_separated.store(on, std::sync::atomic::Ordering::SeqCst); }
    pub fn approve_calls(&self) -> u32 { self.state.lock().unwrap().approve_calls }
    pub fn sign_calls(&self) -> u32 { self.state.lock().unwrap().sign_calls }
    /// An approval written by some other operator, outside any vault service.
    pub fn approve_as(&self, index: usize, plan: &Value) {
        let v = PlanView::parse(plan).unwrap();
        self.state.lock().unwrap().approvals.entry(v.operation_id).or_default().insert(self.members[index].clone());
        self.cv.notify_all();
    }
}

pub struct MockNode {
    net: Arc<MockNet>,
    pub local: usize,
    pub sign_wait: Duration,
}

impl Node for MockNode {
    fn group(&self) -> Result<GroupInfo, NodeError> {
        Ok(GroupInfo { group_key: self.net.group_key(), members: self.net.members.clone(), threshold: 2,
            local: self.net.members[self.local].clone() })
    }

    fn make_plan(&self, message: &[u8], selected: &[Vec<u8>], _work: &Path) -> Result<Value, NodeError> {
        let mut selected = selected.to_vec();
        selected.sort();
        let mut op = [0_u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut op);
        Ok(json!({"schema": 1, "operation_id": op.to_vec(), "message": message, "selected": selected,
            "descriptor": {"group_verifying_key": self.net.group_key().to_vec(),
                "spec": {"participants": self.net.members, "threshold": 2}}}))
    }

    fn approve(&self, plan: &Value, message: &[u8], _work: &Path) -> Result<(), NodeError> {
        let v = PlanView::parse(plan)?;
        let me = &self.net.members[self.local];
        if !v.selected.contains(me) { return Err("this agent is not a selected signer of the plan".into()); }
        if v.message != message { return Err("the plan's message differs from your --message-file; refusing to approve".into()); }
        let mut s = self.net.state.lock().unwrap();
        s.approve_calls += 1;
        if !s.approvals.entry(v.operation_id).or_default().insert(me.clone()) {
            return Err("this agent already approved this operation; refusing another write".into());
        }
        self.net.cv.notify_all();
        Ok(())
    }

    fn signing_status(&self, plan: &Value, _work: &Path) -> Result<ApprovalStatus, NodeError> {
        let v = PlanView::parse(plan)?;
        let s = self.net.state.lock().unwrap();
        let done = s.approvals.get(&v.operation_id);
        Ok(ApprovalStatus { activated: true,
            approvals: v.selected.iter().map(|a| (a.clone(), done.map_or(false, |d| d.contains(a)))).collect() })
    }

    fn sign(&self, plan: &Value, _work: &Path, _budget: u64) -> Result<SignedOutput, NodeError> {
        let v = PlanView::parse(plan)?;
        let me = self.net.members[self.local].clone();
        let mut s = self.net.state.lock().unwrap();
        s.sign_calls += 1;
        let deadline = std::time::Instant::now() + self.sign_wait;
        while v.selected.iter().filter(|a| s.approvals.get(&v.operation_id).map_or(false, |d| d.contains(*a))).count() < 2 {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() { return Err("timed out waiting for the other selected signer's approval".into()); }
            s = self.net.cv.wait_timeout(s, left).unwrap().0;
        }
        if !s.approvals[&v.operation_id].contains(&me) { return Err("this node has not approved".into()); }
        if !s.signed_by.insert((v.operation_id, me)) { return Err("deadline already registered for this operation".into()); }
        let signed_message = if self.net.domain_separated.load(std::sync::atomic::Ordering::SeqCst) {
            [b"holochain-mpc-frost/ed25519/signature/v1\0".as_slice(), &v.message].concat()
        } else { v.message.clone() };
        Ok(SignedOutput { signature: self.net.key.sign(&signed_message).to_bytes(), signed_message })
    }
}
