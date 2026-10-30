//! The chain adapter boundary. Everything the vault shows a person is derived
//! by `decode` from the exact bytes that will be signed.
use crate::util::format_units;
use serde::{Deserialize, Serialize};

pub const MAX_MESSAGE: usize = 8 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Money {
    pub raw: String,
    pub decimals: u32,
    pub symbol: String,
    pub display: String,
}
impl Money {
    pub fn new(raw: u64, decimals: u32, symbol: &str) -> Self {
        Self { raw: raw.to_string(), decimals, symbol: symbol.into(), display: format_units(raw, decimals, symbol) }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub network: String,
    pub from: String,
    pub recipient: String,
    pub amount: Money,
    pub fee: Money,
    pub memo: Option<String>,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxStatus {
    /// Not seen (yet).
    Pending,
    Confirmed,
    /// Seen and failed on chain.
    Failed(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum BroadcastError {
    /// The network definitely did not accept the transaction.
    Rejected(String),
    /// The outcome is unknown (timeout, dropped connection). The transaction
    /// may still land. Resolve by polling its signature, never by resending.
    Uncertain(String),
}

#[derive(Debug, PartialEq, Eq)]
pub struct ChainError {
    pub message: String,
    /// The network or RPC failed, as opposed to the request being invalid.
    pub unavailable: bool,
}
impl ChainError {
    pub fn unavailable(message: impl Into<String>) -> Self { Self { message: message.into(), unavailable: true } }
}
impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(&self.message) }
}
impl From<&str> for ChainError { fn from(s: &str) -> Self { Self { message: s.into(), unavailable: false } } }
impl From<String> for ChainError { fn from(s: String) -> Self { Self { message: s, unavailable: false } } }

/// One Ed25519 chain. All methods block; callers run them off the async runtime.
pub trait Chain: Send + Sync {
    /// Stable name stored in vaults: `mock`, `solana-devnet`.
    fn id(&self) -> &'static str;
    /// The chain address for a group public key.
    fn address(&self, key: &[u8; 32]) -> String;
    /// Unsigned transaction bytes: exactly what the group will sign. Needs the
    /// network on chains that embed a recent block reference.
    fn build_transfer(&self, vault: &[u8; 32], recipient: &str, amount: u64, memo: Option<&str>)
        -> Result<Vec<u8>, ChainError>;
    /// Pure decode of the exact bytes. Refuses anything it does not fully
    /// recognise, and anything whose only required signer is not the vault.
    fn decode(&self, vault: &[u8; 32], bytes: &[u8]) -> Result<Summary, ChainError>;
    /// Verify `signature` over `bytes` under the vault key and return the wire
    /// transaction. Never returns a transaction with an invalid signature.
    fn attach_signature(&self, vault: &[u8; 32], bytes: &[u8], signature: &[u8; 64]) -> Result<Vec<u8>, ChainError>;
    /// The transaction id derivable from the signature alone.
    fn txid(&self, signature: &[u8; 64]) -> String;
    /// ONE submission. Called at most once per proposal.
    fn broadcast(&self, wire: &[u8]) -> Result<String, BroadcastError>;
    /// Read-only; safe to repeat.
    fn status(&self, txid: &str) -> Result<TxStatus, ChainError>;
    /// Read-only.
    fn balance(&self, address: &str) -> Result<Money, ChainError>;
    fn explorer_url(&self, _txid: &str) -> Option<String> { None }
}
