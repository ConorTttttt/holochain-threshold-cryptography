//! v0.4.0 PRELIMINARY: real app-WebSocket authentication and local cell pinning.
//!
//! This deliberately does not yet submit zome calls. App authentication
//! establishes the *client's* permission to access an installed app; it does
//! NOT by itself authenticate an arbitrary remote conductor or prove a source
//! chain. For now, only a loopback app interface is allowed. The operator
//! must control the local conductor and provision its app token separately.
use crate::connection_policy::{ConductorPin, ObservedApp, ObservedCell};
use holochain_conductor_api::{AppAuthenticationRequest, AppInfo, AppRequest, AppResponse, CellInfo};
use holochain_websocket::{connect, ConnectRequest, WebsocketConfig};
use std::sync::Arc;
use std::fs::{self, OpenOptions};
use std::io::{Read, Result as IoResult};
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use zeroize::Zeroizing;

fn invalid(msg: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, msg)
}

/// Reads a pre-issued app authentication token. Requires 0600 regular file
/// owned by the current uid, no symlinks/hardlinks. Never prints the token.
/// The ADMIN interface is intentionally never contacted by this tool.
pub fn read_app_token(path: &Path) -> IoResult<Zeroizing<Vec<u8>>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() ||
        metadata.permissions().mode() & 0o777 != 0o600 ||
        metadata.uid() != unsafe { libc::geteuid() } || metadata.nlink() != 1 ||
        metadata.len() == 0 || metadata.len() > 4096 {
        return Err(invalid("authentication token must be a private regular 0600 file"));
    }
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path)?;
    // Recheck actual opened inode as a best-effort race protection.
    let opened = file.metadata()?;
    if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
        return Err(invalid("app token changed while opening"));
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    file.take(4097).read_to_end(&mut *buf)?;
    if buf.len() != metadata.len() as usize { return Err(invalid("app token size changed")); }
    Ok(buf)
}

/// Convert the authenticated app API's typed response to an independently
/// testable representation. Only directly provisioned cells are eligible;
/// clones are not admitted as substitutes for the pinned original role.
fn observed_app(info: &AppInfo) -> ObservedApp {
    let mut cells = Vec::new();
    for (role, infos) in &info.cell_info {
        for cell in infos {
            if let CellInfo::Provisioned(provisioned) = cell {
                cells.push(ObservedCell {
                    role: role.to_string(),
                    dna_hash: provisioned.cell_id.dna_hash().get_raw_39().to_vec(),
                    agent: provisioned.cell_id.agent_pubkey().get_raw_39().to_vec(),
                });
            }
        }
    }
    ObservedApp {
        installed_app_id: info.installed_app_id.to_string(),
        agent: info.agent_pub_key.get_raw_39().to_vec(),
        cells,
    }
}

/// Connect with a pre-issued token and pin the exact app/agent/DNA role.
/// No worker commands are emitted until this barrier succeeds. This is a
/// genuine app-WebSocket request, NOT a Sweettest in-process conductor call.
///
/// App authentication proves only the *client* is authorized. The conductor
/// must already be a trusted local service: the app-interface token is not
/// a TLS/server-authentication credential.
pub async fn authenticate_and_pin(
    addr: SocketAddr,
    origin: &str,
    token_path: &Path,
    pin: &ConductorPin,
) -> Result<(), String> {
    if !addr.ip().is_loopback() || addr.port() == 0 {
        return Err("only local-loopback app interfaces are supported".into());
    }
    let suffix = origin.strip_prefix("http://localhost");
    let acceptable = match suffix {
        Some("") => true,
        Some(port) if port.starts_with(':') => port[1..].parse::<u16>().map(|p| p != 0).unwrap_or(false),
        _ => false,
    };
    if origin.len() > 256 || !acceptable {
        return Err("Origin must be a local HTTP origin configured on the app interface".into());
    }
    let token = read_app_token(token_path).map_err(|e| e.to_string())?;
    let request: ConnectRequest = addr.into();
    let request = request.try_set_header("Origin", origin)
        .map_err(|e| format!("invalid Origin header: {e}"))?;
    let (sender, mut receiver) = connect(Arc::new(WebsocketConfig::CLIENT_DEFAULT), request)
        .await.map_err(|e| format!("local app socket unavailable: {e}"))?;

    // The WebsocketReceiver MUST be polled while requests are made, otherwise
    // holochain_websocket cannot dispatch the matching RPC responses.
    let pump = tokio::spawn(async move {
        while receiver.recv::<AppResponse>().await.is_ok() {}
    });
    let result = async {
        sender.authenticate(AppAuthenticationRequest { token: token.to_vec() })
            .await.map_err(|e| format!("app authentication failed: {e}"))?;
        let response: AppResponse = sender.request(AppRequest::AppInfo)
            .await.map_err(|e| format!("app info RPC failed: {e}"))?;
        let info = match response {
            AppResponse::AppInfo(Some(info)) => info,
            AppResponse::Error(err) => return Err(format!("conductor rejected AppInfo: {err:?}")),
            _ => return Err("app info request returned an unexpected response".into()),
        };
        pin.verify(&observed_app(&info)).map_err(str::to_owned)
    }.await;
    pump.abort();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::symlink;
    #[test]
    fn private_token_files_only_and_no_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("token");
        let mut f = std::fs::File::create(&file).unwrap();
        f.write_all(&[5_u8; 32]).unwrap();
        drop(f);
        assert!(read_app_token(&file).is_err());
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(&*read_app_token(&file).unwrap(), &[5_u8; 32]);
        let link = tmp.path().join("symlink");
        symlink(&file, &link).unwrap();
        assert!(read_app_token(&link).is_err());
        let hardlink = tmp.path().join("hardlink");
        fs::hard_link(&file, &hardlink).unwrap();
        assert!(read_app_token(&file).is_err());
    }
}

/// Typed, bounded results of approved MPC zome calls. `ZomeCalled` on its own
/// is not considered success: a reply must deserialize to the expected shape.
#[derive(Debug)]
pub enum MpcZomeResult {
    Inbox(Vec<holochain_mpc_core::Envelope>),
    ProbeSession {spec: holochain_mpc_core::SessionSpec, accepted: Vec<Vec<u8>>, ready: bool},
    EncryptionKeys(Vec<crate::conductor_bridge::KeyEvidence>),
    KeyRegistration { action: Vec<u8> },
    DeliveryReceipt { already_stored: bool, action: Vec<u8> },
}

#[derive(serde::Deserialize, Debug)]
struct KeyRecordWire {
    action: holochain_zome_types::prelude::ActionHash,
    author: holochain_zome_types::prelude::AgentPubKey,
    public_key: [u8; 32],
}

#[derive(serde::Deserialize, Debug)]
struct ReceiptWire {
    status: ReceiptStatusWire,
    storage_action: holochain_zome_types::prelude::ActionHash,
}

#[derive(serde::Deserialize, Debug)]
enum ReceiptStatusWire { Stored, AlreadyStored }

fn decode_mpc_response(
    operation: crate::signed_call_policy::MpcCall,
    pin: &ConductorPin,
    io: holochain_zome_types::prelude::ExternIO,
) -> Result<MpcZomeResult, String> {
    use crate::signed_call_policy::MpcCall;
    match operation {
        MpcCall::GetProbeSessionStatus => {
            #[derive(serde::Deserialize, Debug)]
            struct Status {spec: holochain_mpc_core::SessionSpec, accepted: Vec<holochain_zome_types::prelude::AgentPubKey>, ready_observed: bool}
            let s: Status=io.decode().map_err(|_| "invalid probe session status")?;
            Ok(MpcZomeResult::ProbeSession {spec:s.spec,accepted:s.accepted.into_iter().map(|a|a.get_raw_39().to_vec()).collect(),ready:s.ready_observed})
        }
        MpcCall::GetInbox => {
            let inbox: Vec<holochain_mpc_core::Envelope> = io.decode()
                .map_err(|_| "conductor returned an invalid inbox response")?;
            if inbox.len() > 4096 || inbox.iter().any(|env| {
                env.session_id != pin.node.session_id ||
                env.sender == pin.node.worker_agent ||
                env.recipient.as_deref() != Some(pin.node.worker_agent.as_slice()) && env.recipient.is_some() ||
                env.payload.len() > holochain_mpc_core::MAX_PAYLOAD_BYTES ||
                env.payload_hash != holochain_mpc_core::commitment("envelope-payload", &env.payload)
            }) {
                return Err("inbox contains messages outside pinned ceremony".into());
            }
            Ok(MpcZomeResult::Inbox(inbox))
        }
        MpcCall::GetEncryptionKeyBindings => {
            let records: Vec<KeyRecordWire> = io.decode()
                .map_err(|_| "conductor returned invalid encryption-key records")?;
            if records.len() > 4096 || records.iter().any(|r| r.public_key == [0;32]) {
                return Err("encryption key record policy violation".into());
            }
            Ok(MpcZomeResult::EncryptionKeys(records.into_iter().map(|r| {
                crate::conductor_bridge::KeyEvidence {
                    action: r.action.get_raw_39().to_vec(),
                    author: r.author.get_raw_39().to_vec(),
                    public_key: r.public_key,
                }
            }).collect()))
        }
        MpcCall::RegisterEncryptionKey => {
            let action: holochain_zome_types::prelude::ActionHash = io.decode()
                .map_err(|_| "conductor returned invalid key registration action")?;
            Ok(MpcZomeResult::KeyRegistration { action:action.get_raw_39().to_vec() })
        }
        MpcCall::SendProtocolMessage => {
            let receipt: ReceiptWire = io.decode()
                .map_err(|_| "conductor returned invalid delivery receipt")?;
            Ok(MpcZomeResult::DeliveryReceipt {
                already_stored: matches!(receipt.status, ReceiptStatusWire::AlreadyStored),
                action: receipt.storage_action.get_raw_39().to_vec(),
            })
        }
    }
}

/// Submit a pre-signed, *explicitly allowlisted* MPC call. The caller must
/// obtain a real agent signature from a trusted signer BEFORE calling here.
/// This function deliberately cannot sign, mint tokens, grant capabilities or
/// select an arbitrary target cell. A fresh app socket is independently
/// authenticated and pinned in the very same connection that submits the RPC.
///
/// For now each call reconnects; automatic relay and durable retry sequencing
/// belong in the next increment. Retrying a signed call requires a NEW nonce
/// and a fresh agent signature rather than reusing an old signed blob.
pub async fn submit_signed_mpc_call(
    addr: SocketAddr,
    origin: &str,
    token_path: &Path,
    pin: &ConductorPin,
    operation: crate::signed_call_policy::MpcCall,
    signed: holochain_conductor_api::ZomeCallParamsSigned,
) -> Result<MpcZomeResult, String> {
    crate::signed_call_policy::validate_signed_call(pin, operation, &signed)?;
    if !addr.ip().is_loopback() || addr.port() == 0 {
        return Err("only local-loopback app interfaces are supported".into());
    }
    let valid_origin = origin.strip_prefix("http://localhost").is_some_and(|part| {
        part.is_empty() || part.strip_prefix(':')
            .is_some_and(|port| port.parse::<u16>().is_ok_and(|n| n != 0))
    });
    if origin.len() > 256 || !valid_origin {
        return Err("invalid local app Origin".into());
    }
    let token = read_app_token(token_path).map_err(|e| e.to_string())?;
    let request: ConnectRequest = addr.into();
    let request = request.try_set_header("Origin", origin)
        .map_err(|e| format!("invalid Origin header: {e}"))?;
    let (sender, mut receiver) = connect(Arc::new(WebsocketConfig::CLIENT_DEFAULT), request)
        .await.map_err(|e| format!("local app socket unavailable: {e}"))?;
    let pump = tokio::spawn(async move {
        while receiver.recv::<AppResponse>().await.is_ok() {}
    });
    let result = async {
        sender.authenticate(AppAuthenticationRequest { token: token.to_vec() })
            .await.map_err(|e| format!("app authentication failed: {e}"))?;
        let info_response: AppResponse = sender.request(AppRequest::AppInfo)
            .await.map_err(|e| format!("AppInfo request failed: {e}"))?;
        let info = match info_response {
            AppResponse::AppInfo(Some(info)) => info,
            _ => return Err("authenticated app info missing or rejected".into()),
        };
        pin.verify(&observed_app(&info)).map_err(str::to_owned)?;
        let response: AppResponse = sender.request(AppRequest::CallZome(Box::new(signed)))
            .await.map_err(|e| format!("signed MPC RPC failed: {e}"))?;
        match response {
            AppResponse::ZomeCalled(io) => decode_mpc_response(operation, pin, *io),
            // Do not expose Debug formatting of conductor errors: it may
            // include fields that belong to a capability grant.
            AppResponse::Error(_) => Err("signed MPC zome call rejected by conductor".into()),
            _ => Err("wrong response type for signed MPC zome call".into()),
        }
    }.await;
    pump.abort();
    result
}
