//! Phase 5C-C: native transport-key adapter, deliberately independent of DKG.
//!
//! Only a trusted caller may build `TransportKeyBinding` from pinned conductor
//! evidence. This helper neither starts nor resumes FROST DKG and never touches
//! the existing DKG checkpoint/tombstone machinery. Do not call it with an
//! existing live-node database until explicit deployment migration is reviewed.
use holochain_mpc_runtime::{transport_key::TransportKeyBinding, RuntimeStore};
use holochain_mpc_security::sealed::NativeChannelKey;

/// Owns a restored native X25519 encryption key, never serializable or logged.
/// The key is NOT the agent's Holochain/Lair Ed25519 signing key.
pub struct DurableTransportChannel {
    key: NativeChannelKey,
}

impl DurableTransportChannel {
    /// Create and commit a new key before exposing its corresponding public
    /// key. A pre-existing row is always an error; never regenerate on restart.
    pub fn provision_new(
        store: &mut RuntimeStore,
        binding: &TransportKeyBinding,
    ) -> Result<Self, String> {
        let secret = store.create_transport_key(binding).map_err(|e| e.to_string())?;
        let key = NativeChannelKey::from_secret_bytes(&secret).map_err(|e| e.to_string())?;
        Ok(Self { key })
    }

    /// Restore precisely the stored key. Missing, corrupted or differently
    /// bound records fail closed; recovery never triggers DKG initialization.
    pub fn recover(
        store: &RuntimeStore,
        binding: &TransportKeyBinding,
    ) -> Result<Self, String> {
        let secret = store.load_transport_key(binding).map_err(|e| e.to_string())?;
        let key = NativeChannelKey::from_secret_bytes(&secret).map_err(|e| e.to_string())?;
        Ok(Self { key })
    }

    /// The only identity data safe to publish. Publication still requires
    /// independent signed registration and exact action/author pinning.
    pub fn public_key(&self) -> [u8; 32] {
        self.key.public_key()
    }

    /// Use the existing authenticated encryption API; do not extract secrets.
    pub fn native(&self) -> &NativeChannelKey {
        &self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use holochain_mpc_runtime::MasterKey;
    use std::{
        fs::{self, DirBuilder}, os::unix::fs::DirBuilderExt,
        path::{Path, PathBuf}, process,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn binding() -> TransportKeyBinding {
        TransportKeyBinding {
            dna: [1; 39], agent: [2; 39], proposal: [3; 39], session: [4; 32],
        }
    }

    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
            let dir = std::env::temp_dir().join(format!(
                "mpc-phase5cc-transport-{}-{}", process::id(), stamp,
            ));
            DirBuilder::new().mode(0o700).create(&dir).unwrap();
            Self(dir)
        }
        fn db(&self) -> &Path { &self.0 }
    }
    impl Drop for TestDir {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
    }

    #[test]
    fn sqlite_reopen_preserves_the_native_public_key() {
        let dir = TestDir::new();
        let db = dir.db().join("transport.sqlite");
        let original = {
            let mut store = RuntimeStore::open(&db, MasterKey::from_bytes([8; 32])).unwrap();
            let channel = DurableTransportChannel::provision_new(&mut store, &binding()).unwrap();
            let public = channel.public_key();
            assert_ne!(public, [0; 32]);
            assert!(DurableTransportChannel::provision_new(&mut store, &binding()).is_err());
            public
        };
        let store = RuntimeStore::open(&db, MasterKey::from_bytes([8; 32])).unwrap();
        let recovered = DurableTransportChannel::recover(&store, &binding()).unwrap();
        assert_eq!(original, recovered.public_key());
    }

    #[test]
    fn wrong_binding_and_master_key_fail_closed() {
        let dir = TestDir::new();
        let db = dir.db().join("transport.sqlite");
        {
            let mut store = RuntimeStore::open(&db, MasterKey::from_bytes([8; 32])).unwrap();
            assert!(DurableTransportChannel::recover(&store, &binding()).is_err());
            DurableTransportChannel::provision_new(&mut store, &binding()).unwrap();
            let mut other = binding();
            other.dna[0] ^= 1;
            assert!(DurableTransportChannel::recover(&store, &other).is_err());
            other = binding();
            other.session[0] ^= 1;
            assert!(DurableTransportChannel::recover(&store, &other).is_err());
        }
        let wrong = RuntimeStore::open(&db, MasterKey::from_bytes([9; 32])).unwrap();
        assert!(DurableTransportChannel::recover(&wrong, &binding()).is_err());
    }

    #[test]
    fn zero_secret_cannot_be_imported() {
        assert!(NativeChannelKey::from_secret_bytes(&[0; 32]).is_err());
    }

    /// A and B hold distinct, write-once X25519 identities. A seals a packet,
    /// both independent SQLite stores close, and B must decrypt only with its
    /// recovered key, exact peer public key, and exact ceremony/header.
    /// This is an OFFLINE cryptographic regression test, not a Holochain
    /// protocol send and not a FROST-DKG round transition.
    #[test]
    fn recovered_agents_exchange_authenticated_ciphertext() {
        use holochain_mpc_core::{commitment, SessionSpec};
        use holochain_mpc_security::{sealed::ChannelHeader, Ceremony};

        let dir = TestDir::new();
        let a_db = dir.db().join("agent-a.sqlite");
        let b_db = dir.db().join("agent-b.sqlite");
        let a = TransportKeyBinding {
            agent: [1; 39], ..binding()
        };
        let b = TransportKeyBinding {
            agent: [2; 39], ..binding()
        };
        assert_ne!(a.agent, b.agent);

        let a_public = {
            let mut store = RuntimeStore::open(&a_db, MasterKey::from_bytes([8; 32])).unwrap();
            DurableTransportChannel::provision_new(&mut store, &a)
                .unwrap().public_key()
        };
        let b_public = {
            let mut store = RuntimeStore::open(&b_db, MasterKey::from_bytes([9; 32])).unwrap();
            DurableTransportChannel::provision_new(&mut store, &b)
                .unwrap().public_key()
        };
        assert_ne!(a_public, b_public);

        let ceremony = Ceremony {
            proposal_action: a.proposal.to_vec(),
            spec: SessionSpec {
                session_id: a.session,
                application_id: "org.example.mpc.transport-test".into(),
                protocol_id: "frost-ed25519".into(),
                protocol_version: 1,
                context_hash: commitment("test-transport-context", b"offline-only"),
                participants: vec![a.agent.to_vec(), b.agent.to_vec()],
                threshold: 2,
                max_round: 6,
            },
        };
        let header = ChannelHeader {
            sender: a.agent.to_vec(),
            recipient: b.agent.to_vec(),
            round: 1,
            sequence: 1,
        };
        let plaintext = b"offline retained-key ciphertext regression";

        // A has been restarted: its original channel and DB connection were
        // dropped above. Recovering MUST NOT generate a replacement.
        let mut packet = {
            let store = RuntimeStore::open(&a_db, MasterKey::from_bytes([8; 32])).unwrap();
            let channel = DurableTransportChannel::recover(&store, &a).unwrap();
            assert_eq!(channel.public_key(), a_public);
            channel.native().seal(&ceremony, header.clone(), b_public, plaintext).unwrap()
        };
        // B has independently restarted as well.
        let store = RuntimeStore::open(&b_db, MasterKey::from_bytes([9; 32])).unwrap();
        let recipient = DurableTransportChannel::recover(&store, &b).unwrap();
        assert_eq!(recipient.public_key(), b_public);
        let clear = recipient.native().open(&ceremony, &header, a_public, &packet).unwrap();
        assert_eq!(clear.as_slice(), &plaintext[..]);

        // Never trust the claimed sender_key field: it must equal independently
        // pinned, author-signed evidence (modeled by a_public in this test).
        assert!(recipient.native().open(&ceremony, &header, [5; 32], &packet).is_err());
        let mut wrong_header = header.clone();
        wrong_header.sequence += 1;
        assert!(recipient.native().open(&ceremony, &wrong_header, a_public, &packet).is_err());
        let other_ceremony = Ceremony {
            proposal_action: vec![7; 39],
            spec: ceremony.spec.clone(),
        };
        assert!(recipient.native().open(&other_ceremony, &header, a_public, &packet).is_err());
        packet.ciphertext[0] ^= 1;
        assert!(recipient.native().open(&ceremony, &header, a_public, &packet).is_err());
    }
}
