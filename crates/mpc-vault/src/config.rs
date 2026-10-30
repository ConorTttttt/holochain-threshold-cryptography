//! Service configuration and startup checks. Everything is refused rather than defaulted:
//! loopback listen address only, private token file, devnet RPC only.
use crate::cli_node::NodeConfig;
use serde::Deserialize;
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SolanaConfig {
    pub rpc_url: Option<String>,
    /// Durable nonce account whose authority is the vault (see `mpc-vault solana-setup`).
    pub nonce_account: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: String,
    pub token_file: PathBuf,
    pub data_dir: PathBuf,
    /// Static UI served under /ui/.
    pub ui_dir: Option<PathBuf>,
    pub auto_broadcast: Option<bool>,
    pub default_expiry_secs: Option<u64>,
    pub solana: Option<SolanaConfig>,
    pub node: NodeConfig,
}

pub fn listen_addr(s: &str) -> Result<SocketAddr, String> {
    let addr: SocketAddr = s.parse().map_err(|_| "listen must be ip:port, for example 127.0.0.1:8787")?;
    if !addr.ip().is_loopback() { return Err("the vault service listens on a loopback address only".into()); }
    Ok(addr)
}

/// Devnet or a local validator only.
pub fn check_rpc(url: &str) -> Result<(), String> {
    let host_ok = url.starts_with("http://127.0.0.1") || url.starts_with("http://localhost")
        || (url.starts_with("https://") && url.contains("devnet"));
    if host_ok { Ok(()) } else { Err("this development build talks to a Solana devnet or local RPC only".into()) }
}

pub fn read_token(path: &Path) -> Result<Vec<u8>, String> {
    if !path.is_absolute() { return Err("token_file must be an absolute path".into()); }
    let info = std::fs::symlink_metadata(path).map_err(|e| format!("token file: {e}"))?;
    if !info.is_file() || info.permissions().mode() & 0o077 != 0 || info.uid() != unsafe { libc::geteuid() } {
        return Err("the token file must be a regular 0600 file owned by this user (create one with `mpc-vault gen-token`)".into());
    }
    let token = std::fs::read_to_string(path).map_err(|e| e.to_string())?.trim().to_owned();
    if token.len() < 32 { return Err("the token must be at least 32 characters".into()); }
    Ok(token.into_bytes())
}

pub fn gen_token(path: &Path) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)
        .map_err(|e| format!("cannot create {} (it must not exist): {e}", path.display()))?;
    f.write_all(format!("{}\n", crate::util::random_hex(32)).as_bytes()).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn loopback_and_devnet_only() {
        assert!(listen_addr("127.0.0.1:8787").is_ok() && listen_addr("[::1]:1").is_ok());
        assert!(listen_addr("0.0.0.0:8787").is_err() && listen_addr("192.168.1.2:80").is_err() && listen_addr("nope").is_err());
        assert!(check_rpc("https://api.devnet.solana.com").is_ok() && check_rpc("http://127.0.0.1:8899").is_ok());
        assert!(check_rpc("https://api.mainnet-beta.solana.com").is_err() && check_rpc("http://example.com").is_err());
    }
    #[test]
    fn token_file_must_be_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t");
        gen_token(&p).unwrap();
        assert!(gen_token(&p).is_err(), "never overwrites");
        assert_eq!(read_token(&p).unwrap().len(), 64);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(read_token(&p).is_err());
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&p, "short").unwrap();
        assert!(read_token(&p).is_err());
    }
}
