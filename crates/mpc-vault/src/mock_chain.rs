//! In-memory chain for the whole state machine. It verifies signatures like a
//! real chain, enforces a recent-reference window and refuses replays.
use crate::chain::*;
use crate::util::{hex, unhex_exact};
use ed25519_dalek::{Signature, VerifyingKey};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

const MAGIC: &[u8; 7] = b"MOCKTX1";
pub const FEE: u64 = 100;
const WINDOW: u64 = 5;
const LEN_FIXED: usize = 7 + 32 + 32 + 8 + 8 + 8 + 1;

#[derive(Default)]
struct Ledger {
    height: u64,
    balances: BTreeMap<String, u64>,
    seen: BTreeSet<String>,
    /// Test hooks.
    next_broadcast: Option<BroadcastError>,
    /// Land the transaction but report an uncertain outcome.
    land_but_uncertain: bool,
    pending_polls: u32,
    fail_on_chain: Option<String>,
    broadcasts: u32,
}

#[derive(Default)]
pub struct MockChain(Mutex<Ledger>);

impl MockChain {
    pub fn new() -> Self { Self::default() }
    pub fn fund(&self, address: &str, amount: u64) { *self.0.lock().unwrap().balances.entry(address.into()).or_default() += amount; }
    pub fn advance(&self, blocks: u64) { self.0.lock().unwrap().height += blocks; }
    pub fn fail_next_broadcast(&self, e: BroadcastError) { self.0.lock().unwrap().next_broadcast = Some(e); }
    pub fn land_but_report_uncertain(&self) { self.0.lock().unwrap().land_but_uncertain = true; }
    pub fn pending_polls(&self, n: u32) { self.0.lock().unwrap().pending_polls = n; }
    pub fn fail_on_chain(&self, why: &str) { self.0.lock().unwrap().fail_on_chain = Some(why.into()); }
    /// How many broadcast calls reached the chain (replay/retry assertions).
    pub fn broadcasts(&self) -> u32 { self.0.lock().unwrap().broadcasts }
    pub fn balance_of(&self, address: &str) -> u64 { self.0.lock().unwrap().balances.get(address).copied().unwrap_or(0) }
}

struct Parsed { from: [u8; 32], to: [u8; 32], amount: u64, fee: u64, height: u64, memo: Option<String> }

fn parse(bytes: &[u8]) -> Result<Parsed, ChainError> {
    if bytes.len() < LEN_FIXED || &bytes[..7] != MAGIC { return Err("not a mock transaction".into()); }
    let u64_at = |o: usize| u64::from_be_bytes(bytes[o..o + 8].try_into().unwrap());
    let memo_len = bytes[LEN_FIXED - 1] as usize;
    if bytes.len() != LEN_FIXED + memo_len { return Err("mock transaction has trailing or missing bytes".into()); }
    let memo = if memo_len == 0 { None } else {
        Some(String::from_utf8(bytes[LEN_FIXED..].to_vec()).map_err(|_| "memo is not UTF-8")?)
    };
    Ok(Parsed { from: bytes[7..39].try_into().unwrap(), to: bytes[39..71].try_into().unwrap(),
        amount: u64_at(71), fee: u64_at(79), height: u64_at(87), memo })
}

fn money(raw: u64) -> Money { Money::new(raw, 6, "MOCK") }

impl Chain for MockChain {
    fn id(&self) -> &'static str { "mock" }
    fn address(&self, key: &[u8; 32]) -> String { hex(key) }

    fn build_transfer(&self, vault: &[u8; 32], recipient: &str, amount: u64, memo: Option<&str>)
        -> Result<Vec<u8>, ChainError> {
        let to = unhex_exact::<32>(recipient).ok_or("recipient must be 64 hex characters")?;
        if &to == vault { return Err("recipient is the vault itself".into()); }
        if amount == 0 { return Err("amount must be positive".into()); }
        let memo = memo.unwrap_or("").as_bytes();
        if memo.len() > 100 { return Err("memo too long".into()); }
        let mut tx = MAGIC.to_vec();
        tx.extend_from_slice(vault);
        tx.extend_from_slice(&to);
        tx.extend_from_slice(&amount.to_be_bytes());
        tx.extend_from_slice(&FEE.to_be_bytes());
        tx.extend_from_slice(&self.0.lock().unwrap().height.to_be_bytes());
        tx.push(memo.len() as u8);
        tx.extend_from_slice(memo);
        Ok(tx)
    }

    fn decode(&self, vault: &[u8; 32], bytes: &[u8]) -> Result<Summary, ChainError> {
        let p = parse(bytes)?;
        if &p.from != vault { return Err("the transaction does not spend from this vault".into()); }
        if p.to == p.from || p.amount == 0 { return Err("transfer to self or of zero".into()); }
        Ok(Summary { network: "mock".into(), from: hex(&p.from), recipient: hex(&p.to), amount: money(p.amount),
            fee: money(p.fee), memo: p.memo,
            notes: vec![format!("valid for {WINDOW} blocks after block {}", p.height)] })
    }

    fn attach_signature(&self, vault: &[u8; 32], bytes: &[u8], signature: &[u8; 64]) -> Result<Vec<u8>, ChainError> {
        parse(bytes)?;
        VerifyingKey::from_bytes(vault).map_err(|_| "invalid vault key")?
            .verify_strict(bytes, &Signature::from_bytes(signature)).map_err(|_| "signature does not verify under the vault key")?;
        let mut wire = signature.to_vec();
        wire.extend_from_slice(bytes);
        Ok(wire)
    }

    fn txid(&self, signature: &[u8; 64]) -> String { hex(signature) }

    fn broadcast(&self, wire: &[u8]) -> Result<String, BroadcastError> {
        let mut l = self.0.lock().unwrap();
        l.broadcasts += 1;
        if let Some(e) = l.next_broadcast.take() { return Err(e); }
        if wire.len() < 64 { return Err(BroadcastError::Rejected("malformed".into())); }
        let (sig, msg) = wire.split_at(64);
        let p = parse(msg).map_err(|e| BroadcastError::Rejected(e.message))?;
        let sig: [u8; 64] = sig.try_into().unwrap();
        let ok = VerifyingKey::from_bytes(&p.from).ok()
            .map(|k| k.verify_strict(msg, &Signature::from_bytes(&sig)).is_ok()).unwrap_or(false);
        if !ok { return Err(BroadcastError::Rejected("invalid signature".into())); }
        let id = hex(&sig);
        if l.seen.contains(&id) { return Err(BroadcastError::Rejected("transaction already processed".into())); }
        if l.height > p.height + WINDOW { return Err(BroadcastError::Rejected("recent reference expired".into())); }
        let (from, to) = (hex(&p.from), hex(&p.to));
        let cost = p.amount.checked_add(p.fee).ok_or_else(|| BroadcastError::Rejected("overflow".into()))?;
        if l.balances.get(&from).copied().unwrap_or(0) < cost {
            return Err(BroadcastError::Rejected("insufficient funds".into()));
        }
        *l.balances.get_mut(&from).unwrap() -= cost;
        *l.balances.entry(to).or_default() += p.amount;
        l.seen.insert(id.clone());
        if std::mem::take(&mut l.land_but_uncertain) { return Err(BroadcastError::Uncertain("connection reset".into())); }
        Ok(id)
    }

    fn status(&self, txid: &str) -> Result<TxStatus, ChainError> {
        let mut l = self.0.lock().unwrap();
        if !l.seen.contains(txid) { return Ok(TxStatus::Pending); }
        if l.pending_polls > 0 { l.pending_polls -= 1; return Ok(TxStatus::Pending); }
        Ok(match &l.fail_on_chain { Some(w) => TxStatus::Failed(w.clone()), None => TxStatus::Confirmed })
    }

    fn balance(&self, address: &str) -> Result<Money, ChainError> {
        Ok(money(self.0.lock().unwrap().balances.get(address).copied().unwrap_or(0)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn key() -> SigningKey { SigningKey::from_bytes(&[7; 32]) }

    #[test]
    fn roundtrip_and_replay() {
        let chain = MockChain::new();
        let k = key();
        let vault = k.verifying_key().to_bytes();
        chain.fund(&hex(&vault), 10_000);
        let to = hex(&[9; 32]);
        let tx = chain.build_transfer(&vault, &to, 1_000, Some("hi")).unwrap();
        let s = chain.decode(&vault, &tx).unwrap();
        assert_eq!((s.amount.raw.as_str(), s.fee.raw.as_str(), s.memo.as_deref()), ("1000", "100", Some("hi")));
        let sig = k.sign(&tx).to_bytes();
        let wire = chain.attach_signature(&vault, &tx, &sig).unwrap();
        let id = chain.broadcast(&wire).unwrap();
        assert_eq!(chain.status(&id).unwrap(), TxStatus::Confirmed);
        assert_eq!(chain.balance_of(&to), 1_000);
        assert!(matches!(chain.broadcast(&wire), Err(BroadcastError::Rejected(m)) if m.contains("already")));
        assert_eq!(chain.balance_of(&to), 1_000, "a replay moved no funds");
    }

    #[test]
    fn refuses_bad_bytes_and_signatures() {
        let chain = MockChain::new();
        let k = key();
        let vault = k.verifying_key().to_bytes();
        let tx = chain.build_transfer(&vault, &hex(&[9; 32]), 5, None).unwrap();
        let mut longer = tx.clone();
        longer.push(0);
        assert!(chain.decode(&vault, &longer).is_err());
        assert!(chain.decode(&[1; 32], &tx).is_err(), "not spent from this vault");
        assert!(chain.attach_signature(&vault, &tx, &[0; 64]).is_err());
        let sig = k.sign(&tx).to_bytes();
        let mut other = tx.clone();
        other[75] ^= 1;
        assert!(chain.attach_signature(&vault, &other, &sig).is_err(), "signature is bound to the bytes");
        assert!(chain.build_transfer(&vault, &hex(&vault), 5, None).is_err());
    }
}
