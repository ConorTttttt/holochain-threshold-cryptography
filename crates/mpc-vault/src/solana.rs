//! Solana DEVNET adapter. The vault key is an ordinary Ed25519 key, so the
//! group signature is a valid transaction signature.
//!
//! Only one transaction shape is ever built or accepted for signing:
//!   [AdvanceNonceAccount]? , System Transfer , [Memo]?
//! with the vault as fee payer and the only signer. Anything else fails
//! closed in `decode`, so the approval screen can never summarise less than
//! what is signed.
//!
//! With a configured durable nonce account the transaction does not expire
//! after about a minute, which a human approval needs. Without one it uses a
//! recent blockhash and says so in the summary notes.
use crate::chain::*;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::{json, Value};
use std::time::Duration;

pub const DEVNET_RPC: &str = "https://api.devnet.solana.com";
const LAMPORTS_PER_SIGNATURE: u64 = 5_000;
const SYSTEM: [u8; 32] = [0; 32];
const NONCE_ACCOUNT_LEN: usize = 80;

fn b58(s: &str) -> Option<[u8; 32]> { bs58::decode(s).into_vec().ok()?.try_into().ok() }
fn program(s: &str) -> [u8; 32] { b58(s).expect("constant") }
fn memo_program() -> [u8; 32] { program("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr") }
fn recent_blockhashes() -> [u8; 32] { program("SysvarRecentB1ockHashes11111111111111111111") }
fn rent_sysvar() -> [u8; 32] { program("SysvarRent111111111111111111111111111111111") }
pub fn address(key: &[u8; 32]) -> String { bs58::encode(key).into_string() }

fn money(raw: u64) -> Money { Money::new(raw, 9, "SOL") }

// ------------------------------------------------------- message encoding

fn put_shortvec(out: &mut Vec<u8>, mut n: usize) {
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 { out.push(byte); return; }
        out.push(byte | 0x80);
    }
}

fn get_shortvec(b: &[u8], at: &mut usize) -> Result<usize, String> {
    let (mut n, mut shift) = (0_usize, 0);
    loop {
        let byte = *b.get(*at).ok_or("truncated transaction")?;
        *at += 1;
        n |= ((byte & 0x7f) as usize) << shift;
        if byte & 0x80 == 0 {
            // Canonical encodings only: no padding byte, at most 2 bytes for our sizes.
            if shift > 0 && byte == 0 { return Err("non-canonical length".into()); }
            return Ok(n);
        }
        shift += 7;
        if shift > 14 { return Err("length too large".into()); }
    }
}

#[derive(Clone)]
pub struct Meta { pub key: [u8; 32], pub signer: bool, pub writable: bool }
pub struct Instruction { pub program: [u8; 32], pub accounts: Vec<Meta>, pub data: Vec<u8> }

/// Compile a legacy message with `payer` first (signer, writable).
pub fn compile_message(payer: [u8; 32], ixs: &[Instruction], blockhash: [u8; 32]) -> Vec<u8> {
    let mut metas: Vec<Meta> = vec![Meta { key: payer, signer: true, writable: true }];
    let mut add = |m: Meta| match metas.iter_mut().find(|x| x.key == m.key) {
        Some(x) => { x.signer |= m.signer; x.writable |= m.writable; }
        None => metas.push(m),
    };
    for ix in ixs {
        for m in &ix.accounts { add(m.clone()); }
        add(Meta { key: ix.program, signer: false, writable: false });
    }
    let group = |s: bool, w: bool| metas.iter().filter(move |m| m.signer == s && m.writable == w).cloned().collect::<Vec<_>>();
    let ordered: Vec<Meta> = [group(true, true), group(true, false), group(false, true), group(false, false)].concat();
    let (signers, ro_signed) = (ordered.iter().filter(|m| m.signer).count(), group(true, false).len());
    let ro_unsigned = group(false, false).len();
    let index = |k: &[u8; 32]| ordered.iter().position(|m| &m.key == k).unwrap() as u8;
    let mut out = vec![signers as u8, ro_signed as u8, ro_unsigned as u8];
    put_shortvec(&mut out, ordered.len());
    for m in &ordered { out.extend_from_slice(&m.key); }
    out.extend_from_slice(&blockhash);
    put_shortvec(&mut out, ixs.len());
    for ix in ixs {
        out.push(index(&ix.program));
        put_shortvec(&mut out, ix.accounts.len());
        out.extend(ix.accounts.iter().map(|m| index(&m.key)));
        put_shortvec(&mut out, ix.data.len());
        out.extend_from_slice(&ix.data);
    }
    out
}

struct Parsed {
    signers: u8,
    ro_signed: u8,
    ro_unsigned: u8,
    keys: Vec<[u8; 32]>,
    ixs: Vec<(u8, Vec<u8>, Vec<u8>)>,
}

fn parse_message(b: &[u8]) -> Result<Parsed, String> {
    if b.first().map_or(true, |v| v & 0x80 != 0) { return Err("versioned messages are not supported".into()); }
    if b.len() < 3 { return Err("truncated transaction".into()); }
    let mut at = 3;
    let n = get_shortvec(b, &mut at)?;
    if n == 0 || n > 64 { return Err("bad account count".into()); }
    let mut keys = Vec::new();
    for _ in 0..n {
        keys.push(b.get(at..at + 32).ok_or("truncated transaction")?.try_into().unwrap());
        at += 32;
    }
    b.get(at..at + 32).ok_or("truncated transaction")?; // the recent blockhash or nonce value
    at += 32;
    let count = get_shortvec(b, &mut at)?;
    let mut ixs = Vec::new();
    for _ in 0..count {
        let program = *b.get(at).ok_or("truncated transaction")?;
        at += 1;
        let na = get_shortvec(b, &mut at)?;
        let accounts = b.get(at..at + na).ok_or("truncated transaction")?.to_vec();
        at += na;
        let nd = get_shortvec(b, &mut at)?;
        let data = b.get(at..at + nd).ok_or("truncated transaction")?.to_vec();
        at += nd;
        ixs.push((program, accounts, data));
    }
    if at != b.len() { return Err("trailing bytes after the transaction".into()); }
    Ok(Parsed { signers: b[0], ro_signed: b[1], ro_unsigned: b[2], keys, ixs })
}

// ------------------------------------------------------------------- RPC

pub struct Rpc {
    url: String,
    agent: ureq::Agent,
}

pub enum RpcError {
    /// The request may or may not have reached the node.
    Transport(String),
    /// The node answered with an error; the request was not executed.
    Node(String),
}
impl RpcError {
    fn text(&self) -> String { match self { Self::Transport(s) | Self::Node(s) => s.clone() } }
}

impl Rpc {
    pub fn new(url: &str) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(25)))
            .http_status_as_error(false)
            .build().into();
        Self { url: url.into(), agent }
    }

    pub fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let body = serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
            .map_err(|e| RpcError::Node(e.to_string()))?;
        let mut resp = self.agent.post(&self.url).header("content-type", "application/json").send(&body[..])
            .map_err(|e| RpcError::Transport(e.to_string()))?;
        let status = resp.status().as_u16();
        let text = resp.body_mut().read_to_string().map_err(|e| RpcError::Transport(e.to_string()))?;
        let parsed: Result<Value, _> = serde_json::from_str(&text);
        match parsed {
            Ok(v) if v.get("error").is_some() => Err(RpcError::Node(v["error"]["message"].as_str().unwrap_or("rpc error").to_owned())),
            Ok(v) if v.get("result").is_some() => Ok(v["result"].clone()),
            _ if (400..500).contains(&status) && status != 408 => Err(RpcError::Node(format!("HTTP {status}"))),
            _ => Err(RpcError::Transport(format!("HTTP {status}: unreadable answer"))),
        }
    }

    pub fn latest_blockhash(&self) -> Result<[u8; 32], String> {
        let v = self.call("getLatestBlockhash", json!([{"commitment": "finalized"}])).map_err(|e| e.text())?;
        v["value"]["blockhash"].as_str().and_then(b58).ok_or_else(|| "no blockhash in the answer".into())
    }

    pub fn balance(&self, address: &str) -> Result<u64, String> {
        let v = self.call("getBalance", json!([address, {"commitment": "confirmed"}])).map_err(|e| e.text())?;
        v["value"].as_u64().ok_or_else(|| "no balance in the answer".into())
    }

    pub fn account_data(&self, address: &str) -> Result<Option<Vec<u8>>, String> {
        let v = self.call("getAccountInfo", json!([address, {"encoding": "base64", "commitment": "confirmed"}])).map_err(|e| e.text())?;
        if v["value"].is_null() { return Ok(None); }
        let s = v["value"]["data"][0].as_str().ok_or("no account data")?;
        base64::engine::general_purpose::STANDARD.decode(s).map(Some).map_err(|e| e.to_string())
    }

    pub fn send(&self, wire: &[u8]) -> Result<String, RpcError> {
        let b64 = base64::engine::general_purpose::STANDARD.encode(wire);
        let v = self.call("sendTransaction", json!([b64, {"encoding": "base64", "preflightCommitment": "confirmed"}]))?;
        v.as_str().map(str::to_owned).ok_or_else(|| RpcError::Transport("no signature in the answer".into()))
    }
}

/// Read the stored blockhash of a durable nonce account owned by `authority`.
fn nonce_value(data: &[u8], authority: &[u8; 32]) -> Result<[u8; 32], String> {
    if data.len() != NONCE_ACCOUNT_LEN { return Err("not a nonce account".into()); }
    let initialised = u32::from_le_bytes(data[4..8].try_into().unwrap()) == 1;
    if !initialised { return Err("the nonce account is not initialised".into()); }
    if &data[8..40] != authority { return Err("the nonce account is not controlled by this vault".into()); }
    Ok(data[40..72].try_into().unwrap())
}

// ---------------------------------------------------------------- adapter

pub struct Solana {
    rpc: Rpc,
    /// Durable nonce account whose authority is the vault.
    nonce_account: Option<String>,
}

impl Solana {
    pub fn new(rpc_url: &str, nonce_account: Option<String>) -> Self {
        Self { rpc: Rpc::new(rpc_url), nonce_account }
    }
}

fn transfer_ix(from: [u8; 32], to: [u8; 32], lamports: u64) -> Instruction {
    let mut data = 2_u32.to_le_bytes().to_vec();
    data.extend_from_slice(&lamports.to_le_bytes());
    Instruction { program: SYSTEM, data,
        accounts: vec![Meta { key: from, signer: true, writable: true }, Meta { key: to, signer: false, writable: true }] }
}

fn advance_nonce_ix(nonce: [u8; 32], authority: [u8; 32]) -> Instruction {
    Instruction { program: SYSTEM, data: 4_u32.to_le_bytes().to_vec(), accounts: vec![
        Meta { key: nonce, signer: false, writable: true },
        Meta { key: recent_blockhashes(), signer: false, writable: false },
        Meta { key: authority, signer: true, writable: false }] }
}

impl Chain for Solana {
    fn id(&self) -> &'static str { "solana-devnet" }
    fn address(&self, key: &[u8; 32]) -> String { address(key) }

    fn build_transfer(&self, vault: &[u8; 32], recipient: &str, amount: u64, memo: Option<&str>) -> Result<Vec<u8>, ChainError> {
        let to = b58(recipient).ok_or("recipient is not a Solana address")?;
        if &to == vault { return Err("recipient is the vault itself".into()); }
        if to == SYSTEM || to == memo_program() || to == recent_blockhashes() {
            return Err("recipient is a system address".into());
        }
        let mut ixs = Vec::new();
        let blockhash = match &self.nonce_account {
            Some(acct) => {
                let nonce = b58(acct).ok_or("configured nonce account is not an address")?;
                if to == nonce { return Err("recipient is the nonce account".into()); }
                let data = self.rpc.account_data(acct).map_err(ChainError::unavailable)?.ok_or("the nonce account does not exist")?;
                let value = nonce_value(&data, vault)?;
                ixs.push(advance_nonce_ix(nonce, *vault));
                value
            }
            None => self.rpc.latest_blockhash().map_err(ChainError::unavailable)?,
        };
        ixs.push(transfer_ix(*vault, to, amount));
        if let Some(m) = memo.filter(|m| !m.is_empty()) {
            ixs.push(Instruction { program: memo_program(), accounts: vec![], data: m.as_bytes().to_vec() });
        }
        Ok(compile_message(*vault, &ixs, blockhash))
    }

    fn decode(&self, vault: &[u8; 32], bytes: &[u8]) -> Result<Summary, ChainError> {
        let m = parse_message(bytes)?;
        if m.signers != 1 || m.ro_signed != 0 || m.keys[0] != *vault {
            return Err("the vault must be the fee payer and the only signer".into());
        }
        let writable = |i: usize| i < m.keys.len().saturating_sub(m.ro_unsigned as usize);
        let key = |i: u8| m.keys.get(i as usize).copied().ok_or("instruction names an unknown account");
        let (mut nonce, mut transfer, mut memo) = (None, None, None);
        let mut used = vec![false; m.keys.len()];
        used[0] = true;
        for (n, (p, accts, data)) in m.ixs.iter().enumerate() {
            let prog = key(*p)?;
            used[*p as usize] = true;
            for a in accts { *used.get_mut(*a as usize).ok_or("instruction names an unknown account")? = true; }
            if prog == SYSTEM && data.len() == 4 && data[..] == 4_u32.to_le_bytes() {
                if n != 0 || nonce.is_some() { return Err("a nonce advance is only allowed as the first instruction".into()); }
                if accts.len() != 3 || key(accts[1])? != recent_blockhashes() || accts[2] != 0 || !writable(accts[0] as usize) {
                    return Err("unrecognised nonce advance".into());
                }
                nonce = Some(key(accts[0])?);
            } else if prog == SYSTEM && data.len() == 12 && data[..4] == 2_u32.to_le_bytes() {
                if transfer.is_some() || memo.is_some() { return Err("exactly one transfer is allowed".into()); }
                if accts.len() != 2 || accts[0] != 0 || !writable(accts[1] as usize) || accts[1] == 0 {
                    return Err("unrecognised transfer".into());
                }
                transfer = Some((key(accts[1])?, u64::from_le_bytes(data[4..].try_into().unwrap())));
            } else if prog == memo_program() && accts.is_empty() {
                if transfer.is_none() || memo.is_some() { return Err("a memo must follow the transfer, once".into()); }
                memo = Some(String::from_utf8(data.clone()).map_err(|_| "memo is not UTF-8")?);
            } else {
                return Err("the transaction contains an instruction the vault does not understand".into());
            }
        }
        if used.iter().any(|u| !u) { return Err("the transaction lists accounts that no instruction uses".into()); }
        let (to, lamports) = transfer.ok_or("no transfer in the transaction")?;
        if lamports == 0 { return Err("zero-value transfer".into()); }
        let mut notes = vec!["Base fee only; no priority fee.".to_owned()];
        match nonce {
            Some(n) => notes.push(format!("Durable nonce {}: stays valid until that nonce advances, so slow approvals are fine. Only one proposal per nonce value can land.", address(&n))),
            None => notes.push("Recent blockhash: it expires after roughly one to two minutes, so every approval must happen within that time or the transaction cannot land.".into()),
        }
        Ok(Summary { network: "solana-devnet".into(), from: address(vault), recipient: address(&to), amount: money(lamports),
            fee: money(LAMPORTS_PER_SIGNATURE), memo, notes })
    }

    fn attach_signature(&self, vault: &[u8; 32], bytes: &[u8], signature: &[u8; 64]) -> Result<Vec<u8>, ChainError> {
        parse_message(bytes)?;
        VerifyingKey::from_bytes(vault).map_err(|_| "invalid vault key")?
            .verify_strict(bytes, &Signature::from_bytes(signature)).map_err(|_| "signature does not verify under the vault key")?;
        let mut wire = vec![1_u8];
        wire.extend_from_slice(signature);
        wire.extend_from_slice(bytes);
        Ok(wire)
    }

    fn txid(&self, signature: &[u8; 64]) -> String { bs58::encode(signature).into_string() }

    fn broadcast(&self, wire: &[u8]) -> Result<String, BroadcastError> {
        match self.rpc.send(wire) {
            Ok(id) => Ok(id),
            Err(RpcError::Node(m)) => Err(BroadcastError::Rejected(m)),
            Err(RpcError::Transport(m)) => Err(BroadcastError::Uncertain(m)),
        }
    }

    fn status(&self, txid: &str) -> Result<TxStatus, ChainError> {
        let v = self.rpc.call("getSignatureStatuses", json!([[txid], {"searchTransactionHistory": true}]))
            .map_err(|e| ChainError::unavailable(e.text()))?;
        let s = &v["value"][0];
        if s.is_null() { return Ok(TxStatus::Pending); }
        if !s["err"].is_null() { return Ok(TxStatus::Failed(s["err"].to_string())); }
        Ok(match s["confirmationStatus"].as_str() { Some("confirmed" | "finalized") => TxStatus::Confirmed, _ => TxStatus::Pending })
    }

    fn balance(&self, address: &str) -> Result<Money, ChainError> {
        self.rpc.balance(address).map(money).map_err(ChainError::unavailable)
    }

    fn explorer_url(&self, txid: &str) -> Option<String> {
        Some(format!("https://explorer.solana.com/tx/{txid}?cluster=devnet"))
    }
}

// ------------------------------------------------- throwaway devnet setup

fn send_signed(rpc: &Rpc, message: &[u8], signers: &[&SigningKey]) -> Result<String, String> {
    let mut wire = Vec::new();
    put_shortvec(&mut wire, signers.len());
    for s in signers { wire.extend_from_slice(&s.sign(message).to_bytes()); }
    wire.extend_from_slice(message);
    rpc.send(&wire).map_err(|e| e.text())
}

/// Wait until a transaction is confirmed (read-only polling; used by setup only).
pub fn wait_confirmed(chain: &Solana, txid: &str, secs: u64) -> Result<(), String> {
    let end = std::time::Instant::now() + Duration::from_secs(secs);
    while std::time::Instant::now() < end {
        match chain.status(txid).map_err(|e| e.message)? {
            TxStatus::Confirmed => return Ok(()),
            TxStatus::Failed(e) => return Err(format!("transaction failed: {e}")),
            TxStatus::Pending => std::thread::sleep(Duration::from_secs(2)),
        }
    }
    Err("not confirmed in time".into())
}

pub fn request_airdrop(rpc: &Rpc, to: &str, lamports: u64) -> Result<String, String> {
    rpc.call("requestAirdrop", json!([to, lamports])).map_err(|e| e.text())?
        .as_str().map(str::to_owned).ok_or_else(|| "no signature in the answer".into())
}

/// Transfer from a throwaway devnet keypair (setup only, never the vault).
pub fn fund(rpc: &Rpc, from: &SigningKey, to: [u8; 32], lamports: u64) -> Result<String, String> {
    let payer = from.verifying_key().to_bytes();
    let msg = compile_message(payer, &[transfer_ix(payer, to, lamports)], rpc.latest_blockhash()?);
    send_signed(rpc, &msg, &[from])
}

/// Create and initialise a durable nonce account whose authority is `authority`.
pub fn create_nonce_account(rpc: &Rpc, funder: &SigningKey, nonce: &SigningKey, authority: [u8; 32]) -> Result<String, String> {
    let rent = rpc.call("getMinimumBalanceForRentExemption", json!([NONCE_ACCOUNT_LEN])).map_err(|e| e.text())?
        .as_u64().ok_or("no rent amount in the answer")?;
    let (f, n) = (funder.verifying_key().to_bytes(), nonce.verifying_key().to_bytes());
    let mut create = 0_u32.to_le_bytes().to_vec();
    create.extend_from_slice(&rent.to_le_bytes());
    create.extend_from_slice(&(NONCE_ACCOUNT_LEN as u64).to_le_bytes());
    create.extend_from_slice(&SYSTEM);
    let mut init = 6_u32.to_le_bytes().to_vec();
    init.extend_from_slice(&authority);
    let ixs = [
        Instruction { program: SYSTEM, data: create, accounts: vec![
            Meta { key: f, signer: true, writable: true }, Meta { key: n, signer: true, writable: true }] },
        Instruction { program: SYSTEM, data: init, accounts: vec![
            Meta { key: n, signer: true, writable: true },
            Meta { key: recent_blockhashes(), signer: false, writable: false },
            Meta { key: rent_sysvar(), signer: false, writable: false }] },
    ];
    let msg = compile_message(f, &ixs, rpc.latest_blockhash()?);
    send_signed(rpc, &msg, &[funder, nonce])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(nonce: Option<String>) -> Solana { Solana::new("http://127.0.0.1:9", nonce) }
    const VAULT: [u8; 32] = [1; 32];
    const TO: [u8; 32] = [2; 32];
    const HASH: [u8; 32] = [3; 32];

    fn plain() -> Vec<u8> { compile_message(VAULT, &[transfer_ix(VAULT, TO, 1_500_000)], HASH) }

    #[test]
    fn plain_transfer_matches_the_known_wire_layout() {
        let m = plain();
        let mut want = vec![1, 0, 1, 3];
        want.extend([1_u8; 32]);
        want.extend([2_u8; 32]);
        want.extend([0_u8; 32]); // system program
        want.extend(HASH);
        want.extend([1, 2, 2, 0, 1, 12, 2, 0, 0, 0]);
        want.extend(1_500_000_u64.to_le_bytes());
        assert_eq!(m, want);
        let s = chain(None).decode(&VAULT, &m).unwrap();
        assert_eq!((s.from.as_str(), s.recipient.as_str()), (address(&VAULT).as_str(), address(&TO).as_str()));
        assert_eq!((s.amount.raw.as_str(), s.amount.display.as_str(), s.fee.raw.as_str()), ("1500000", "0.0015 SOL", "5000"));
        assert!(s.notes.iter().any(|n| n.contains("Recent blockhash")));
    }

    #[test]
    fn durable_nonce_and_memo_decode() {
        let nonce = [4_u8; 32];
        let ixs = [advance_nonce_ix(nonce, VAULT), transfer_ix(VAULT, TO, 7),
            Instruction { program: memo_program(), accounts: vec![], data: b"rent".to_vec() }];
        let m = compile_message(VAULT, &ixs, HASH);
        let s = chain(None).decode(&VAULT, &m).unwrap();
        assert_eq!((s.amount.raw.as_str(), s.memo.as_deref()), ("7", Some("rent")));
        assert!(s.notes.iter().any(|n| n.contains("Durable nonce") && n.contains(&address(&nonce))));
    }

    #[test]
    fn refuses_everything_it_does_not_fully_understand() {
        let c = chain(None);
        let other = [9_u8; 32];
        // Someone else pays: the vault would only be a co-signer.
        assert!(c.decode(&other, &plain()).is_err());
        // Extra instruction: a second transfer, an unknown program, an unused account.
        let two = compile_message(VAULT, &[transfer_ix(VAULT, TO, 1), transfer_ix(VAULT, [5; 32], 1)], HASH);
        assert!(c.decode(&VAULT, &two).is_err());
        let unknown = compile_message(VAULT, &[transfer_ix(VAULT, TO, 1),
            Instruction { program: [8; 32], accounts: vec![Meta { key: VAULT, signer: true, writable: true }], data: vec![1] }], HASH);
        assert!(c.decode(&VAULT, &unknown).is_err());
        let mut unused = plain();
        unused[3] = 4;
        unused.splice(3 + 1 + 96..3 + 1 + 96, [7_u8; 32]);
        assert!(c.decode(&VAULT, &unused).is_err());
        // A transfer that moves funds from a second signer.
        let third = compile_message(VAULT, &[transfer_ix([6; 32], TO, 1)], HASH);
        assert!(c.decode(&VAULT, &third).is_err(), "two signers");
        // Trailing byte, truncation, version prefix, zero amount, nonce not first.
        let mut trailing = plain();
        trailing.push(0);
        assert!(c.decode(&VAULT, &trailing).is_err());
        assert!(c.decode(&VAULT, &plain()[..40]).is_err());
        let mut v0 = plain();
        v0[0] = 0x80;
        assert!(c.decode(&VAULT, &v0).is_err());
        assert!(c.decode(&VAULT, &compile_message(VAULT, &[transfer_ix(VAULT, TO, 0)], HASH)).is_err());
        let late = compile_message(VAULT, &[transfer_ix(VAULT, TO, 1), advance_nonce_ix([4; 32], VAULT)], HASH);
        assert!(c.decode(&VAULT, &late).is_err());
        assert!(c.decode(&VAULT, &[]).is_err());
    }

    #[test]
    fn build_refuses_bad_recipients_without_the_network() {
        let c = chain(None);
        assert!(c.build_transfer(&VAULT, "not base58 !!", 1, None).is_err());
        assert!(c.build_transfer(&VAULT, &address(&VAULT), 1, None).is_err());
        assert!(c.build_transfer(&VAULT, &address(&[0; 32]), 1, None).is_err());
        assert!(c.build_transfer(&VAULT, "11111", 1, None).is_err());
    }

    #[test]
    fn signature_must_verify_and_wire_is_one_signature_plus_message() {
        let c = chain(None);
        let k = SigningKey::from_bytes(&[11; 32]);
        let vault = k.verifying_key().to_bytes();
        let m = compile_message(vault, &[transfer_ix(vault, TO, 5)], HASH);
        let sig = k.sign(&m).to_bytes();
        let wire = c.attach_signature(&vault, &m, &sig).unwrap();
        assert_eq!((wire[0], &wire[1..65], &wire[65..]), (1, &sig[..], &m[..]));
        assert_eq!(c.txid(&sig), bs58::encode(sig).into_string());
        assert!(c.attach_signature(&vault, &m, &[0; 64]).is_err());
        let mut other = m.clone();
        *other.last_mut().unwrap() ^= 1;
        assert!(c.attach_signature(&vault, &other, &sig).is_err());
    }

    #[test]
    fn nonce_account_data_is_checked() {
        let mut d = vec![0_u8; 80];
        d[4] = 1;
        d[8..40].copy_from_slice(&VAULT);
        d[40..72].copy_from_slice(&HASH);
        assert_eq!(nonce_value(&d, &VAULT).unwrap(), HASH);
        assert!(nonce_value(&d, &TO).is_err(), "another authority");
        d[4] = 0;
        assert!(nonce_value(&d, &VAULT).is_err(), "uninitialised");
        assert!(nonce_value(&d[..79], &VAULT).is_err());
    }

    #[test]
    fn shortvec_roundtrip_and_canonical() {
        for n in [0_usize, 1, 127, 128, 300, 16_383] {
            let mut b = Vec::new();
            put_shortvec(&mut b, n);
            let mut at = 0;
            assert_eq!(get_shortvec(&b, &mut at).unwrap(), n);
            assert_eq!(at, b.len());
        }
        assert!(get_shortvec(&[0x80, 0x00], &mut 0).is_err());
    }
}
