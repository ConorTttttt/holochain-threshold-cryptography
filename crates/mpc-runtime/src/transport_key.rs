//! Phase 5C-C: write-once, ceremony-bound native transport key storage.
//!
//! Development-only key custody: storage is encrypted with the existing
//! node master key, which currently lives on the same machine as the DB.
//! This does NOT provide hardware anti-rollback or change non-resumable DKG.
use super::{RResult, RuntimeError, RuntimeStore};
use chacha20poly1305::{
    aead::{rand_core::RngCore, Aead, AeadCore, KeyInit, OsRng, Payload},
    XChaCha20Poly1305, XNonce,
};
use rusqlite::{params, OptionalExtension};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportKeyBinding {
    pub dna: [u8; 39],
    pub agent: [u8; 39],
    pub proposal: [u8; 39],
    pub session: [u8; 32],
}

impl TransportKeyBinding {
    fn validate(&self) -> RResult<()> {
        if self.dna == [0; 39]
            || self.agent == [0; 39]
            || self.proposal == [0; 39]
            || self.session == [0; 32]
        {
            return Err(RuntimeError::Wire("invalid transport-key binding"));
        }
        Ok(())
    }
}

fn aad(binding: &TransportKeyBinding) -> Vec<u8> {
    let mut bytes = b"holochain-mpc/transport-key/v1".to_vec();
    for item in [
        binding.dna.as_slice(),
        binding.agent.as_slice(),
        binding.proposal.as_slice(),
        binding.session.as_slice(),
    ] {
        bytes.extend_from_slice(&(item.len() as u64).to_be_bytes());
        bytes.extend_from_slice(item);
    }
    bytes
}

impl RuntimeStore {
    /// Generate and durably insert one native X25519 secret scalar seed.
    ///
    /// The caller must derive its public key from the returned zeroising
    /// material and must not publish that key until this call succeeds.
    /// Existing records are NEVER replaced, including after failed DKG.
    pub fn create_transport_key(
        &mut self,
        binding: &TransportKeyBinding,
    ) -> RResult<Zeroizing<[u8; 32]>> {
        binding.validate()?;
        let mut secret = Zeroizing::new([0_u8; 32]);
        OsRng.fill_bytes(&mut secret[..]);
        if secret.iter().all(|b| *b == 0) {
            return Err(RuntimeError::Crypto);
        }

        let cipher = XChaCha20Poly1305::new_from_slice(&self.key.0[..])
            .map_err(|_| RuntimeError::Crypto)?;
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &secret[..],
                    aad: &aad(binding),
                },
            )
            .map_err(|_| RuntimeError::Crypto)?;

        let tx = self.transaction()?;
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO transport_keys
             (proposal, agent, dna, session, version, nonce, ciphertext)
             VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6)",
            params![
                binding.proposal.as_slice(),
                binding.agent.as_slice(),
                binding.dna.as_slice(),
                binding.session.as_slice(),
                nonce.as_slice(),
                ciphertext,
            ],
        )?;
        if inserted != 1 {
            return Err(RuntimeError::Conflict("transport key already provisioned"));
        }
        tx.commit()?;
        Ok(secret)
    }

    /// Recover the previously stored secret; never generate a replacement.
    /// Full identity and ciphertext integrity are required to match.
    pub fn load_transport_key(
        &self,
        binding: &TransportKeyBinding,
    ) -> RResult<Zeroizing<[u8; 32]>> {
        binding.validate()?;
        let row: Option<(Vec<u8>, Vec<u8>, i64, Vec<u8>, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT dna, session, version, nonce, ciphertext FROM transport_keys
                 WHERE proposal = ?1 AND agent = ?2",
                params![binding.proposal.as_slice(), binding.agent.as_slice()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((dna, session, version, nonce, ciphertext)) = row else {
            return Err(RuntimeError::Conflict("transport key not provisioned"));
        };
        if dna.as_slice() != binding.dna.as_slice()
            || session.as_slice() != binding.session.as_slice()
            || version != 1
            || nonce.len() != 24
            || ciphertext.len() != 48
        {
            return Err(RuntimeError::Conflict("transport-key binding or record invalid"));
        }

        let cipher = XChaCha20Poly1305::new_from_slice(&self.key.0[..])
            .map_err(|_| RuntimeError::Crypto)?;
        let clear = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: ciphertext.as_slice(),
                        aad: &aad(binding),
                    },
                )
                .map_err(|_| RuntimeError::Crypto)?,
        );
        if clear.len() != 32 {
            return Err(RuntimeError::Crypto);
        }
        let mut secret = Zeroizing::new([0_u8; 32]);
        secret.copy_from_slice(clear.as_slice());
        if secret.iter().all(|b| *b == 0) {
            return Err(RuntimeError::Crypto);
        }
        Ok(secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MasterKey;
    use std::{fs, os::unix::fs::DirBuilderExt, path::Path, process};

    fn binding() -> TransportKeyBinding {
        TransportKeyBinding {
            dna: [1; 39],
            agent: [2; 39],
            proposal: [3; 39],
            session: [4; 32],
        }
    }

    fn memory_store(key: u8) -> RuntimeStore {
        RuntimeStore::open(Path::new(":memory:"), MasterKey::from_bytes([key; 32]))
            .expect("open test store")
    }

    #[test]
    fn first_write_and_recovery_are_identical() {
        let mut store = memory_store(7);
        let expected = store.create_transport_key(&binding()).unwrap();
        let recovered = store.load_transport_key(&binding()).unwrap();
        assert_eq!(&expected[..], &recovered[..]);
        assert!(store.create_transport_key(&binding()).is_err());
        assert_eq!(&expected[..], &store.load_transport_key(&binding()).unwrap()[..]);
    }

    #[test]
    fn mismatched_identity_is_refused() {
        let mut store = memory_store(7);
        store.create_transport_key(&binding()).unwrap();
        let mut other = binding();
        other.dna[0] ^= 1;
        assert!(store.load_transport_key(&other).is_err());
        other = binding();
        other.session[0] ^= 1;
        assert!(store.load_transport_key(&other).is_err());
        other = binding();
        other.agent[0] ^= 1;
        assert!(store.load_transport_key(&other).is_err());
        other = binding();
        other.proposal[0] ^= 1;
        assert!(store.load_transport_key(&other).is_err());
    }

    #[test]
    fn missing_key_is_not_automatically_generated() {
        let store = memory_store(7);
        assert!(store.load_transport_key(&binding()).is_err());
    }

    #[test]
    fn corrupted_ciphertext_is_refused() {
        let mut store = memory_store(7);
        store.create_transport_key(&binding()).unwrap();
        store
            .connection
            .execute("UPDATE transport_keys SET ciphertext = zeroblob(48)", [])
            .unwrap();
        assert!(store.load_transport_key(&binding()).is_err());
    }

    #[test]
    fn survives_database_reopen_but_refuses_wrong_master_key() {
        // Use a fresh, unpredictable test directory; never open a live node.
        let mut random = [0_u8; 16];
        OsRng.fill_bytes(&mut random);
        let directory = std::env::temp_dir().join(format!(
            "mpc-channel-key-test-{}-{:x?}",
            process::id(), random
        ));
        fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let path = directory.join("test.sqlite");
        let original = {
            let mut store = RuntimeStore::open(&path, MasterKey::from_bytes([7; 32])).unwrap();
            store.create_transport_key(&binding()).unwrap()
        };
        {
            let store = RuntimeStore::open(&path, MasterKey::from_bytes([7; 32])).unwrap();
            let restored = store.load_transport_key(&binding()).unwrap();
            assert_eq!(&original[..], &restored[..]);
        }
        {
            let store = RuntimeStore::open(&path, MasterKey::from_bytes([8; 32])).unwrap();
            assert!(store.load_transport_key(&binding()).is_err());
        }
        fs::remove_dir_all(directory).unwrap();
    }
}
