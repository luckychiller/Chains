use crate::crypto::ratchet::RatchetState;
use crate::models::{Body, Chain, ChainsResult, Header};
use sled;
use std::collections::HashMap;

pub mod gc;

/// Persistent storage manager using Sled.
///
/// Responsible for reading and writing Chains, Headers, and Bodies to disk.
pub struct Storage {
    db: sled::Db,
}

/// Builds the sled key for a header. The sequence is zero-padded so that
/// lexicographic key order matches numeric sequence order in `scan_prefix`.
pub(crate) fn header_key(chain_id: &[u8; 32], sequence: u64) -> String {
    format!("header:{}:{:016x}", hex::encode(chain_id), sequence)
}

impl Storage {
    /// Opens a new storage instance at the specified path.
    pub fn new(path: &str) -> ChainsResult<Self> {
        let db = sled::open(path)?;
        Ok(Storage { db })
    }

    /// Stores a Header for a specific chain.
    pub fn store_header(
        &self,
        chain_id: &[u8; 32],
        sequence: u64,
        header: &Header,
    ) -> ChainsResult<()> {
        let key = header_key(chain_id, sequence);
        let value = bincode::serialize(header)?;
        self.db.insert(key.as_bytes(), value)?;
        Ok(())
    }

    /// Retrieves a Header by its sequence number.
    pub fn get_header(&self, chain_id: &[u8; 32], sequence: u64) -> ChainsResult<Option<Header>> {
        let key = header_key(chain_id, sequence);
        if let Some(value) = self.db.get(key.as_bytes())? {
            let header: Header = bincode::deserialize(&value)?;
            Ok(Some(header))
        } else {
            Ok(None)
        }
    }

    /// Stores a block Body.
    pub fn store_body(&self, block_id: &[u8; 32], body: &Body) -> ChainsResult<()> {
        let key = format!("body:{}", hex::encode(block_id));
        let value = bincode::serialize(body)?;
        self.db.insert(key.as_bytes(), value)?;
        Ok(())
    }

    /// Retrieves a block Body.
    pub fn get_body(&self, block_id: &[u8; 32]) -> ChainsResult<Option<Body>> {
        let key = format!("body:{}", hex::encode(block_id));
        if let Some(value) = self.db.get(key.as_bytes())? {
            let body: Body = bincode::deserialize(&value)?;
            Ok(Some(body))
        } else {
            Ok(None)
        }
    }

    /// Updates the latest known sequence number for a chain.
    pub fn update_latest_sequence(&self, chain_id: &[u8; 32], sequence: u64) -> ChainsResult<()> {
        let key = format!("latest:{}", hex::encode(chain_id));
        let value = bincode::serialize(&sequence)?;
        self.db.insert(key.as_bytes(), value)?;
        Ok(())
    }

    /// Retrieves the latest known sequence number for a chain.
    pub fn get_latest_sequence(&self, chain_id: &[u8; 32]) -> ChainsResult<u64> {
        let key = format!("latest:{}", hex::encode(chain_id));
        if let Some(value) = self.db.get(key.as_bytes())? {
            let seq: u64 = bincode::deserialize(&value)?;
            Ok(seq)
        } else {
            Ok(0)
        }
    }

    /// Checks if a chain exists in the local database.
    pub fn chain_exists(&self, chain_id: &[u8; 32]) -> ChainsResult<bool> {
        let key = format!("chain:{}", hex::encode(chain_id));
        Ok(self.db.contains_key(key.as_bytes())?)
    }

    /// Marks a chain as existing in the local database.
    pub fn create_chain(&self, chain_id: &[u8; 32]) -> ChainsResult<()> {
        let key = format!("chain:{}", hex::encode(chain_id));
        self.db.insert(key.as_bytes(), b"")?;
        self.update_latest_sequence(chain_id, 0)?;
        Ok(())
    }

    /// Lists all chain IDs found in the local database.
    pub fn list_chains(&self) -> ChainsResult<Vec<[u8; 32]>> {
        let mut chains = Vec::new();
        for kv in self.db.scan_prefix(b"chain:") {
            let (key, _) = kv?;
            let key_str = std::str::from_utf8(&key)?;
            if let Some(hex_id) = key_str.strip_prefix("chain:") {
                if let Ok(id_bytes) = hex::decode(hex_id) {
                    if id_bytes.len() == 32 {
                        let mut id = [0u8; 32];
                        id.copy_from_slice(&id_bytes);
                        chains.push(id);
                    }
                }
            }
        }
        Ok(chains)
    }

    /// Reconstructs a full Chain from disk (Warning: expensive for large chains).
    pub fn get_chain(&self, chain_id: &[u8; 32]) -> ChainsResult<Option<Chain>> {
        if !self.chain_exists(chain_id)? {
            return Ok(None);
        }

        let mut headers = Vec::new();
        let mut bodies = HashMap::new();
        let prefix = format!("header:{}:", hex::encode(chain_id));

        for kv in self.db.scan_prefix(prefix.as_bytes()) {
            let (_, value) = kv?;
            let header: Header = bincode::deserialize(&value)?;
            headers.push(header.clone());

            if let Some(body) = self.get_body(&header.block_id)? {
                bodies.insert(header.block_id, body);
            }
        }

        let chain = Chain {
            id: *chain_id,
            headers,
            bodies,
        };
        chain.validate()?;
        Ok(Some(chain))
    }

    pub fn store_ratchet_session(
        &self,
        session_id: &[u8; 32],
        state: &RatchetState,
    ) -> ChainsResult<()> {
        let key = format!("ratchet:{}", hex::encode(session_id));
        let value = bincode::serialize(state)?;
        self.db.insert(key.as_bytes(), value)?;
        Ok(())
    }

    pub fn get_ratchet_session(&self, session_id: &[u8; 32]) -> ChainsResult<Option<RatchetState>> {
        let key = format!("ratchet:{}", hex::encode(session_id));
        if let Some(value) = self.db.get(key.as_bytes())? {
            let state: RatchetState = bincode::deserialize(&value)?;
            Ok(Some(state))
        } else {
            Ok(None)
        }
    }

    pub fn list_epoch_keys(&self, chain_id: &[u8; 32]) -> ChainsResult<Vec<[u8; 32]>> {
        let mut keys = Vec::new();
        let prefix = format!("epoch:{}:", hex::encode(chain_id));
        for kv in self.db.scan_prefix(prefix.as_bytes()) {
            let (key, value) = kv?;
            let key_str = std::str::from_utf8(&key)?;
            if let Some(_rest) = key_str.strip_prefix(&prefix) {
                let mut k = [0u8; 32];
                k.copy_from_slice(&value);
                keys.push(k);
            }
        }
        Ok(keys)
    }

    pub fn store_epoch_key(
        &self,
        chain_id: &[u8; 32],
        epoch: u64,
        key: &[u8; 32],
    ) -> ChainsResult<()> {
        let db_key = format!("epoch:{}:{}", hex::encode(chain_id), epoch);
        self.db.insert(db_key.as_bytes(), key)?;
        Ok(())
    }

    pub fn get_epoch_key(&self, chain_id: &[u8; 32], epoch: u64) -> ChainsResult<Option<[u8; 32]>> {
        let db_key = format!("epoch:{}:{}", hex::encode(chain_id), epoch);
        if let Some(value) = self.db.get(db_key.as_bytes())? {
            let mut k = [0u8; 32];
            k.copy_from_slice(&value);
            Ok(Some(k))
        } else {
            Ok(None)
        }
    }
}
