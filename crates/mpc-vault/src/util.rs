//! Small helpers: hex, time, RFC 3339 formatting, ids, a clock for tests.
use rand::RngCore;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.is_ascii() { return None; }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

pub fn unhex_exact<const N: usize>(s: &str) -> Option<[u8; N]> {
    unhex(s)?.try_into().ok()
}

pub fn sha256(b: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(b).into()
}

pub fn random_hex(n: usize) -> String {
    let mut b = vec![0_u8; n];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex(&b)
}

/// Constant-time equality for secrets of any length.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() ^ b.len()) as u8;
    for i in 0..a.len().max(b.len()) {
        diff |= a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0);
    }
    diff == 0
}

/// Holochain's base64 text form of a 39-byte key: `u` + URL-safe base64, no padding.
pub fn holochain_b64(raw: &[u8]) -> String {
    use base64::Engine;
    format!("u{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw))
}

/// Seconds since the Unix epoch, injectable so expiry can be tested.
pub trait Clock: Send + Sync {
    fn now(&self) -> u64;
}

pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) }
}

pub struct TestClock(AtomicU64);
impl TestClock {
    pub fn new(start: u64) -> Self { Self(AtomicU64::new(start)) }
    pub fn advance(&self, secs: u64) { self.0.fetch_add(secs, Ordering::SeqCst); }
}
impl Clock for TestClock {
    fn now(&self) -> u64 { self.0.load(Ordering::SeqCst) }
}

/// `2026-10-27T12:34:56Z`
pub fn rfc3339(secs: u64) -> String {
    let (days, rem) = ((secs / 86_400) as i64, secs % 86_400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// Display text for an integer amount in base units.
pub fn format_units(raw: u64, decimals: u32, symbol: &str) -> String {
    let scale = 10_u64.pow(decimals);
    let (whole, frac) = (raw / scale, raw % scale);
    if frac == 0 { return format!("{whole} {symbol}"); }
    let frac = format!("{frac:0width$}", width = decimals as usize);
    format!("{whole}.{} {symbol}", frac.trim_end_matches('0'))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn formats() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_793_000_000), "2026-10-26T07:33:20Z");
        assert_eq!(format_units(1_000_000, 9, "SOL"), "0.001 SOL");
        assert_eq!(format_units(2_000_000_000, 9, "SOL"), "2 SOL");
        assert_eq!(unhex("0aff"), Some(vec![10, 255]));
        assert_eq!(unhex("0g"), None);
        assert!(ct_eq(b"abc", b"abc") && !ct_eq(b"abc", b"abd") && !ct_eq(b"abc", b"ab"));
    }
}
