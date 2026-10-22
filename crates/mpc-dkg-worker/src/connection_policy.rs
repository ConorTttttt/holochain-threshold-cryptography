//! Fail-closed, *offline* policy for binding an authenticated app-interface
//! response to the provisioned local MPC node. No network credentials here.
//! App-info is trusted ONLY after Holochain app-websocket authentication to
//! a loopback conductor controlled by the same operator.
use crate::ipc::ChannelContext;
use std::net::SocketAddr;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedCell {
    pub role: String,
    pub dna_hash: Vec<u8>,
    pub agent: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedApp {
    pub installed_app_id: String,
    pub agent: Vec<u8>,
    pub cells: Vec<ObservedCell>,
}

#[derive(Clone, Debug)]
pub struct ConductorPin {
    pub app_id: String,
    pub role: String,
    pub dna_hash: Vec<u8>,
    pub node: ChannelContext,
}

impl ConductorPin {
    pub fn verify(&self, observed: &ObservedApp) -> Result<(), &'static str> {
        self.node.validate().map_err(|_| "invalid node ceremony binding")?;
        if self.app_id.is_empty() || self.role.is_empty() ||
            self.dna_hash.len() != 39 || self.dna_hash.iter().all(|b| *b == 0) {
            return Err("incomplete or invalid conductor pin");
        }
        if observed.installed_app_id != self.app_id ||
            observed.agent != self.node.worker_agent {
            return Err("app token belongs to another app or agent");
        }
        // Never resolve the role ambiguously (e.g. a clone or two cells).
        let mut found = false;
        for cell in &observed.cells {
            if cell.role == self.role {
                if found { return Err("duplicate or cloned MPC cell in pinned role"); }
                if cell.agent != self.node.worker_agent || cell.dna_hash != self.dna_hash {
                    return Err("app cell does not match pinned agent and DNA");
                }
                found = true;
            }
        }
        if !found { return Err("pinned MPC cell is missing"); }
        Ok(())
    }
}

/// Only loopback app interfaces are accepted. Token authentication is not
/// remote-server authentication; binding to arbitrary network sockets would
/// allow a malicious remote endpoint to collect the token.
pub fn parse_local_app_socket(input: &str) -> Result<SocketAddr, &'static str> {
    let addr: SocketAddr = input.parse().map_err(|_| "use a numeric loopback IP:port")?;
    if !addr.ip().is_loopback() || addr.port() == 0 {
        return Err("app interface MUST be loopback and nonzero port");
    }
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pin() -> ConductorPin {
        ConductorPin {
            app_id: "org.test.mpc".into(), role: "mpc".into(),
            dna_hash: vec![0xdb; 39],
            node: ChannelContext { worker_agent: vec![0x84; 39],
                proposal_action: vec![0x86; 39], session_id: [7; 32],
                channel_id: [8; 32] },
        }
    }
    fn observed() -> ObservedApp {
        ObservedApp { installed_app_id: "org.test.mpc".into(), agent: vec![0x84; 39],
            cells: vec![ObservedCell { role: "mpc".into(),
                dna_hash: vec![0xdb; 39], agent: vec![0x84; 39] }] }
    }
    #[test]
    fn exact_app_role_agent_and_dna_required() {
        pin().verify(&observed()).unwrap();
        let mut other = observed();
        other.installed_app_id = "org.evil".into();
        assert!(pin().verify(&other).is_err());
        other = observed(); other.agent = vec![1;39];
        assert!(pin().verify(&other).is_err());
        other = observed(); other.cells[0].agent = vec![1;39];
        assert!(pin().verify(&other).is_err());
        other = observed(); other.cells[0].dna_hash = vec![2;39];
        assert!(pin().verify(&other).is_err());
        other = observed(); other.cells[0].role = "mpc-clone".into();
        assert!(pin().verify(&other).is_err());
    }
    #[test]
    fn absent_and_duplicate_cells_fail_closed() {
        let mut other = observed(); other.cells.clear();
        assert!(pin().verify(&other).is_err());
        other = observed(); other.cells.push(other.cells[0].clone());
        assert!(pin().verify(&other).is_err());
        other = observed(); other.cells.push(ObservedCell {
            role:"other".into(), dna_hash:vec![4;39], agent:vec![1;39],
        });
        pin().verify(&other).unwrap();
    }
    #[test]
    fn only_numeric_loopback_websocket_addresses() {
        assert!(parse_local_app_socket("127.0.0.1:12345").is_ok());
        assert!(parse_local_app_socket("[::1]:12345").is_ok());
        for bad in ["0.0.0.0:12345", "192.168.1.2:12345", "localhost:12345",
            "127.0.0.1:0", "127.0.0.1", "198.51.100.5:9"] {
            assert!(parse_local_app_socket(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn malformed_node_pins_rejected() {
        let mut cfg = pin(); cfg.dna_hash.clear();
        assert!(cfg.verify(&observed()).is_err());
        cfg = pin(); cfg.node.worker_agent.clear();
        assert!(cfg.verify(&observed()).is_err());
    }
}
