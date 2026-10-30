//! The boundary to this node's existing MPC tooling. The real implementation
//! (`cli_node`) runs the existing binaries as processes; the mock implements
//! the same refusals for tests.
use serde_json::Value;
use std::path::Path;

#[derive(Debug, PartialEq, Eq)]
pub struct NodeError(pub String);
impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(&self.0) }
}
impl From<&str> for NodeError { fn from(s: &str) -> Self { Self(s.into()) } }
impl From<String> for NodeError { fn from(s: String) -> Self { Self(s) } }

/// What this node knows about its completed group.
#[derive(Clone, Debug)]
pub struct GroupInfo {
    pub group_key: [u8; 32],
    /// Raw 39-byte Holochain agent keys, in the descriptor's participant order.
    pub members: Vec<Vec<u8>>,
    pub threshold: u16,
    pub local: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ApprovalStatus {
    pub activated: bool,
    pub approvals: Vec<(Vec<u8>, bool)>,
}

/// What the group signed. For a chain to accept the signature, `signed_message`
/// must equal the transaction bytes; the engine checks that before keeping it.
#[derive(Clone, Debug)]
pub struct SignedOutput {
    pub signature: [u8; 64],
    pub signed_message: Vec<u8>,
}

pub trait Node: Send + Sync {
    fn group(&self) -> Result<GroupInfo, NodeError>;
    /// `make-intent`: a PUBLIC plan whose message is `message`.
    fn make_plan(&self, message: &[u8], selected: &[Vec<u8>], work: &Path) -> Result<Value, NodeError>;
    /// `approve-intent` for this node only, with this node's own copy of the message.
    fn approve(&self, plan: &Value, message: &[u8], work: &Path) -> Result<(), NodeError>;
    /// `signing-status` (read-only).
    fn signing_status(&self, plan: &Value, work: &Path) -> Result<ApprovalStatus, NodeError>;
    /// Signing policy, signer and `mpc-sign`: blocks until this node holds the
    /// group signature or the run fails. `budget_secs` bounds the wait for the
    /// other signer. Never retried.
    fn sign(&self, plan: &Value, work: &Path, budget_secs: u64) -> Result<SignedOutput, NodeError>;
}

/// The few plan fields the vault reads. Everything else stays opaque.
#[derive(Clone, Debug)]
pub struct PlanView {
    pub operation_id: [u8; 32],
    pub message: Vec<u8>,
    pub selected: Vec<Vec<u8>>,
    pub group_key: [u8; 32],
    pub participants: Vec<Vec<u8>>,
    pub threshold: u16,
}

fn bytes(v: &Value) -> Option<Vec<u8>> {
    v.as_array()?.iter().map(|x| x.as_u64().and_then(|n| u8::try_from(n).ok())).collect()
}

impl PlanView {
    pub fn parse(plan: &Value) -> Result<Self, String> {
        let bad = || "not a signing plan".to_string();
        if plan.get("schema").and_then(Value::as_u64) != Some(1) { return Err("unsupported plan schema".into()); }
        let d = plan.get("descriptor").ok_or_else(bad)?;
        let spec = d.get("spec").ok_or_else(bad)?;
        let participants = spec.get("participants").and_then(Value::as_array).ok_or_else(bad)?
            .iter().map(|p| bytes(p).ok_or_else(bad)).collect::<Result<Vec<_>, _>>()?;
        let selected = plan.get("selected").and_then(Value::as_array).ok_or_else(bad)?
            .iter().map(|p| bytes(p).ok_or_else(bad)).collect::<Result<Vec<_>, _>>()?;
        let view = Self {
            operation_id: bytes(plan.get("operation_id").ok_or_else(bad)?).and_then(|b| b.try_into().ok()).ok_or_else(bad)?,
            message: bytes(plan.get("message").ok_or_else(bad)?).ok_or_else(bad)?,
            group_key: bytes(d.get("group_verifying_key").ok_or_else(bad)?).and_then(|b| b.try_into().ok()).ok_or_else(bad)?,
            threshold: spec.get("threshold").and_then(Value::as_u64).and_then(|t| u16::try_from(t).ok()).ok_or_else(bad)?,
            participants, selected,
        };
        if view.operation_id == [0; 32] || view.message.is_empty() || view.selected.is_empty()
            || view.selected.iter().any(|s| !view.participants.contains(s)) {
            return Err("invalid signing plan".into());
        }
        Ok(view)
    }
}
