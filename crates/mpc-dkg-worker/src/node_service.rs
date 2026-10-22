//! v0.3.8 experimental, Linux-only local node service. NOT a Holochain client.
//!
//! A one-ceremony, single-connection Unix socket API gated by the existing
//! ceremony-bound HMAC and fail-closed encrypted DKG journal. An operator must
//! obtain/pin the Holochain agent and proposal from a trusted conductor and
//! provision a private directory (0700). Key files (0600) are NOT backed by
//! Lair or an OS keyring and must be considered development-only material.
use crate::ipc::{AuthFrame, ChannelContext};
use crate::{AuthenticatedController, Command};
use crate::transport_channel::DurableTransportChannel;
use holochain_mpc_runtime::{transport_key::TransportKeyBinding, MasterKey, RuntimeStore};
use serde::{Deserialize, Serialize};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub const MAX_IPC_LINE: usize = 512 * 1024;
const CONFIG: &str = "node.json";
const IPC_KEY: &str = "ipc.key";
const STATE_KEY: &str = "storage.key";
const DATABASE: &str = "journal.sqlite";
const TRANSPORT_DATABASE: &str = "transport.sqlite";
const SOCKET: &str = "controller.sock";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig { pub schema: u8, pub context: ChannelContext }

fn invalid(msg: &'static str) -> io::Error { io::Error::new(io::ErrorKind::PermissionDenied, msg) }

/// Hex decoding used only for PUBLIC agent/action/session identifiers in CLI.
/// Secret key bytes are never passed as command-line arguments.
pub fn decode_hex_exact<const N: usize>(value: &str) -> io::Result<[u8; N]> {
    if value.len() != N * 2 { return Err(invalid("wrong hex identifier length")); }
    let mut out = [0_u8; N];
    for (i, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let c = |b: u8| -> io::Result<u8> { match b {
            b'0'..=b'9' => Ok(b - b'0'), b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10), _ => Err(invalid("bad hex digit")),
        }};
        out[i] = c(chunk[0])? * 16 + c(chunk[1])?;
    }
    Ok(out)
}

fn owner_id() -> u32 { unsafe { libc::geteuid() } }
fn private_directory(path: &Path) -> io::Result<()> {
    if !path.is_absolute() { return Err(invalid("state directory must be absolute")); }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() ||
        metadata.uid() != owner_id() || metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(invalid("state directory must be owned by this user and mode 0700"));
    }
    Ok(())
}
fn private_file(path: &Path) -> io::Result<File> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() ||
        metadata.uid() != owner_id() || metadata.permissions().mode() & 0o777 != 0o600 ||
        metadata.nlink() != 1 {
        return Err(invalid("node file must be private regular file, mode 0600, no hard links"));
    }
    OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path)
}
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}
fn read_key(path: &Path) -> io::Result<Zeroizing<[u8; 32]>> {
    let mut file = private_file(path)?;
    if file.metadata()?.len() != 32 { return Err(invalid("secret file must contain exactly 32 bytes")); }
    let mut key = Zeroizing::new([0_u8; 32]);
    file.read_exact(&mut *key)?;
    if key.iter().all(|&b| b == 0) { return Err(invalid("unprovisioned node key")); }
    Ok(key)
}
fn random_key() -> io::Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0_u8; 32]);
    let mut random = File::open("/dev/urandom")?;
    random.read_exact(&mut *key)?;
    Ok(key)
}
fn read_config(dir: &Path) -> io::Result<NodeConfig> {
    private_directory(dir)?;
    let file = private_file(&dir.join(CONFIG))?;
    if file.metadata()?.len() > 8192 { return Err(invalid("oversized node config")); }
    let config: NodeConfig = serde_json::from_reader(file)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if config.schema != 1 { return Err(invalid("unsupported node configuration schema")); }
    config.context.validate().map_err(|_| invalid("invalid pinned node context"))?;
    Ok(config)
}

/// Transport encryption custody is distinct from non-resumable FROST DKG.
/// The trusted caller must independently pin `dna` against the authenticated
/// conductor cell: node.json pins agent/proposal/session, but not the DNA.
///
/// Creation is explicit and exclusive, never replacing a partial/old DB.
/// `transport.sqlite` is separate from the FROST `journal.sqlite` and uses
/// the existing development-only storage.key (not hardware-backed).
/// Recovery NEVER generates or replaces a key. Neither path begins DKG.
pub fn transport_public_key(state_dir: &Path, dna: [u8; 39], create: bool)
    -> io::Result<[u8; 32]>
{
    Ok(open_transport_channel(state_dir, dna, create)?.2.public_key())
}

/// Native-only custody helper. No secret bytes cross the signer or conductor
/// interfaces. Recovery can perform SQLite housekeeping; it is not read-only.
pub(crate) fn open_transport_channel(state_dir: &Path, dna: [u8;39], create: bool)
    -> io::Result<(RuntimeStore, TransportKeyBinding, DurableTransportChannel)>
{
    let config = read_config(state_dir)?;
    if dna == [0; 39] { return Err(invalid("zero DNA identity")); }
    let agent: [u8; 39] = config.context.worker_agent.as_slice().try_into()
        .map_err(|_| invalid("invalid pinned agent"))?;
    let proposal: [u8; 39] = config.context.proposal_action.as_slice().try_into()
        .map_err(|_| invalid("invalid pinned proposal"))?;
    let binding = TransportKeyBinding {
        dna, agent, proposal, session: config.context.session_id,
    };
    let master = read_key(&state_dir.join(STATE_KEY))?;
    let database = state_dir.join(TRANSPORT_DATABASE);

    if create {
        // This prevents accidental or racing reinitialisation, including
        // reusing an aborted/partially written transport DB.
        let file = OpenOptions::new().write(true).create_new(true).mode(0o600)
            .custom_flags(libc::O_NOFOLLOW).open(&database)?;
        file.sync_all()?;
        drop(file);
        File::open(state_dir)?.sync_all()?;
    } else {
        // No implicit recovery-time DB creation, symlink or hard-link follow.
        let _ = private_file(&database)?;
    }
    let mut store = RuntimeStore::open(&database, MasterKey::from_bytes(*master))
        .map_err(|_| invalid("transport database unavailable or invalid"))?;
    let channel = if create {
        DurableTransportChannel::provision_new(&mut store, &binding)
    } else {
        DurableTransportChannel::recover(&store, &binding)
    }.map_err(|_| invalid("transport key creation/recovery refused"))?;
    Ok((store, binding, channel))
}

#[cfg(test)]
mod transport_key_node_tests {
    use super::*;
    use std::{process, time::{SystemTime, UNIX_EPOCH}};

    #[test]
    fn transport_key_node_isolated_from_dkg_and_recovers() {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "mpc-transport-node-{}-{stamp}", process::id()));
        let context = ChannelContext { worker_agent: vec![11; 39],
            proposal_action: vec![12; 39], session_id: [13; 32], channel_id: [14; 32] };
        provision(&dir, context).unwrap();
        let db = dir.join(TRANSPORT_DATABASE);
        let dkg = dir.join(DATABASE);
        assert!(transport_public_key(&dir, [15; 39], false).is_err());
        assert!(!db.exists());
        let original = transport_public_key(&dir, [15; 39], true).unwrap();
        assert_ne!(original, [0; 32]);
        assert_eq!(fs::metadata(&db).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(transport_public_key(&dir, [15; 39], true).is_err());
        assert!(transport_public_key(&dir, [16; 39], false).is_err());
        assert_eq!(transport_public_key(&dir, [15; 39], false).unwrap(), original);
        assert!(!dkg.exists(), "transport operations must not open the DKG journal");
        fs::remove_dir_all(dir).unwrap();
    }
}

/// Provision one ceremony. All paths and key files are created exclusively.
/// A new Holochain proposal MUST use a different directory; NEVER reset a
/// completed or aborted directory to bypass persistent DKG tombstones.
pub fn provision(state_dir: &Path, context: ChannelContext) -> io::Result<()> {
    if !state_dir.is_absolute() { return Err(invalid("state directory must be absolute")); }
    context.validate().map_err(|_| invalid("invalid Holochain context"))?;
    DirBuilder::new().mode(0o700).create(state_dir)?; // fail if exists
    private_directory(state_dir)?;
    let ipc_key = random_key()?;
    let state_key = random_key()?;
    if *ipc_key == *state_key { return Err(invalid("identical independently generated keys")); }
    write_private(&state_dir.join(IPC_KEY), &ipc_key[..])?;
    write_private(&state_dir.join(STATE_KEY), &state_key[..])?;
    let config = NodeConfig { schema: 1, context };
    let json = serde_json::to_vec_pretty(&config)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    write_private(&state_dir.join(CONFIG), &json)?;
    File::open(state_dir)?.sync_all()?;
    Ok(())
}

/// This represents one independently launched worker service; it has no
/// implicit conductor access. An already trusted, authenticated bridge may
/// submit verified envelopes using AuthFrame<Command> over the private socket.
pub fn serve(state_dir: &Path) -> io::Result<()> {
    let config = read_config(state_dir)?;
    let ipc_key = read_key(&state_dir.join(IPC_KEY))?;
    let master_key = read_key(&state_dir.join(STATE_KEY))?;
    let database = state_dir.join(DATABASE);
    match fs::symlink_metadata(&database) {
        Ok(meta) => {
            if !meta.is_file() || meta.file_type().is_symlink() || meta.uid() != owner_id() ||
                meta.permissions().mode() & 0o077 != 0 {
                return Err(invalid("database file must be private and not a symlink"));
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => (),
        Err(e) => return Err(e),
    }
    let mut controller = AuthenticatedController::new_durable(
        *ipc_key, config.context, &database, MasterKey::from_bytes(*master_key))
        .map_err(|_| invalid("invalid, altered or previously started DKG state"))?;
    // SQLite files live below the 0700 state directory; ensure that a newly
    // created main database is also private for safe movement/backup handling.
    if database.exists() {
        fs::set_permissions(&database, fs::Permissions::from_mode(0o600))?;
    }
    let socket_path = state_dir.join(SOCKET);
    // Never unlink somebody else's socket or silently reuse an old endpoint.
    if fs::symlink_metadata(&socket_path).is_ok() { return Err(invalid("socket already exists")); }
    let listener = UnixListener::bind(&socket_path)?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
    let (stream, _) = listener.accept()?;
    drop(listener);
    let result = serve_connection(&mut controller, stream);
    // The socket is created in our private directory and may be removed after
    // the single-connection process ends. The journal remains permanent.
    let _ = fs::remove_file(&socket_path);
    result
}

fn serve_connection(controller: &mut AuthenticatedController, mut stream: UnixStream) -> io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    loop {
        let mut line = Vec::new();
        // Hard line size bound BEFORE allocating untrusted input.
        let count = (&mut reader).take((MAX_IPC_LINE + 1) as u64).read_until(b'\n', &mut line)?;
        if count == 0 { return Ok(()); }
        if count > MAX_IPC_LINE || line.last() != Some(&b'\n') {
            return Err(invalid("oversized or unterminated command"));
        }
        let frame: AuthFrame<Command> = serde_json::from_slice(&line)
            .map_err(|_| invalid("malformed command frame"))?;
        let reply = controller.handle(frame).map_err(|_| invalid("unauthorized or invalid command"))?;
        let data = serde_json::to_vec(&reply)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if data.len() + 1 > MAX_IPC_LINE { return Err(invalid("oversized reply")); }
        stream.write_all(&data)?;
        stream.write_all(b"\n")?;
        stream.flush()?;
    }
}

/// Load private per-node bridge credentials only from the securely permissioned
/// state directory. The returned key is zeroized on drop. The conductor-facing
/// process MUST itself verify the cell identity and session before connecting.
pub(crate) fn bridge_credentials(dir: &Path) -> io::Result<(ChannelContext, Zeroizing<[u8;32]>)> {
    let config = read_config(dir)?;
    let key = read_key(&dir.join(IPC_KEY))?;
    Ok((config.context, key))
}

/// Read only public, owner-controlled node identity without exporting keys.
pub fn pinned_context(dir: &Path) -> io::Result<ChannelContext> {
    Ok(read_config(dir)?.context)
}

pub fn config_path(dir: &Path) -> PathBuf { dir.join(CONFIG) }
pub fn socket_path(dir: &Path) -> PathBuf { dir.join(SOCKET) }
pub fn key_path(dir: &Path) -> PathBuf { dir.join(IPC_KEY) }

#[cfg(test)]
mod tests {
    use super::*;
    fn context() -> ChannelContext { ChannelContext {
        worker_agent: vec![1;39], proposal_action: vec![9;39],
        session_id: [3;32], channel_id: [4;32],
    }}
    #[test]
    fn private_state_files_and_reentry_denied() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("node-1");
        provision(&dir, context()).unwrap();
        assert!(provision(&dir, context()).is_err());
        for file in ["node.json", "ipc.key", "storage.key"] {
            assert_eq!(fs::metadata(dir.join(file)).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        let mut bad = context(); bad.worker_agent.clear();
        assert!(provision(&temp.path().join("invalid"), bad).is_err());
    }
    #[test]
    fn rejects_key_symlink_and_loose_permissions() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("node");
        provision(&dir, context()).unwrap();
        fs::set_permissions(dir.join("ipc.key"), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_key(&dir.join("ipc.key")).is_err());
        fs::set_permissions(dir.join("ipc.key"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(dir.join("ipc.key"), dir.join("old.key")).unwrap();
        std::os::unix::fs::symlink(dir.join("old.key"), dir.join("ipc.key")).unwrap();
        assert!(read_key(&dir.join("ipc.key")).is_err());
    }
    #[test]
    fn public_identifier_hex_enforced() {
        assert_eq!(decode_hex_exact::<3>("AB00ff").unwrap(), [171,0,255]);
        assert!(decode_hex_exact::<3>("ABxxff").is_err());
        assert!(decode_hex_exact::<3>("00").is_err());
    }
}
