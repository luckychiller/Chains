use sled;
use crate::header::Header;
use crate::body::Body;
use crate::chain::Chain;
use std::collections::HashMap;

pub struct Storage {
    db: sled::Db,
}

type MyResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

impl Storage {
    pub fn new(path: &str) -> MyResult<Self> {
        let db = sled::open(path)?;
        Ok(Storage { db })
    }

    pub fn store_chain(&self, chain: &Chain) -> MyResult<()> {
        // Store the chain ID to indicate existence
        let key = format!("chain:{}", hex::encode(chain.id));
        self.db.insert(key.as_bytes(), b"")?;

        // Store headers
        for header in &chain.headers {
            self.store_header(&chain.id, header.sequence, header)?;
        }

        // Store bodies
        for body in chain.bodies.values() {
            self.store_body(&body.block_id, body)?;
        }

        // Update latest sequence
        if let Some(last) = chain.headers.last() {
            self.update_latest_sequence(&chain.id, last.sequence)?;
        }

        Ok(())
    }

    pub fn get_chain(&self, chain_id: &[u8; 32]) -> MyResult<Option<Chain>> {
        let key = format!("chain:{}", hex::encode(chain_id));
        if self.db.contains_key(key.as_bytes())? {
            let mut headers = Vec::new();
            let mut bodies = HashMap::new();

            // Get all headers for this chain
            let prefix = format!("header:{}:", hex::encode(chain_id));
            for kv in self.db.scan_prefix(prefix.as_bytes()) {
                let (_key, value) = kv?;
                let header: Header = bincode::deserialize(&value).map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
                headers.push(header.clone());

                // Get body
                let body_key = format!("body:{}", hex::encode(header.block_id));
                if let Some(body_value) = self.db.get(body_key.as_bytes())? {
                    let body: Body = bincode::deserialize(&body_value).map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
                    bodies.insert(header.block_id, body);
                }
            }

            // Headers should be in sequence order due to key ordering
            let chain = Chain { id: *chain_id, headers, bodies };
            chain.validate()?;
            Ok(Some(chain))
        } else {
            Ok(None)
        }
    }

    pub fn store_header(&self, chain_id: &[u8; 32], sequence: u64, header: &Header) -> MyResult<()> {
        let key = format!("header:{}:{:x}", hex::encode(chain_id), sequence);
        let value = bincode::serialize(header).map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        self.db.insert(key.as_bytes(), value)?;
        Ok(())
    }

    pub fn get_header(&self, chain_id: &[u8; 32], sequence: u64) -> MyResult<Option<Header>> {
        let key = format!("header:{}:{:x}", hex::encode(chain_id), sequence);
        if let Some(value) = self.db.get(key.as_bytes())? {
            let header: Header = bincode::deserialize(&value).map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            Ok(Some(header))
        } else {
            Ok(None)
        }
    }

    pub fn store_body(&self, block_id: &[u8; 32], body: &Body) -> MyResult<()> {
        let key = format!("body:{}", hex::encode(block_id));
        let value = bincode::serialize(body).map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        self.db.insert(key.as_bytes(), value)?;
        Ok(())
    }

    pub fn get_body(&self, block_id: &[u8; 32]) -> MyResult<Option<Body>> {
        let key = format!("body:{}", hex::encode(block_id));
        if let Some(value) = self.db.get(key.as_bytes())? {
            let body: Body = bincode::deserialize(&value).map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            Ok(Some(body))
        } else {
            Ok(None)
        }
    }

    pub fn update_latest_sequence(&self, chain_id: &[u8; 32], sequence: u64) -> MyResult<()> {
        let key = format!("latest:{}", hex::encode(chain_id));
        let value = bincode::serialize(&sequence).map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        self.db.insert(key.as_bytes(), value)?;
        Ok(())
    }

    pub fn get_latest_sequence(&self, chain_id: &[u8; 32]) -> MyResult<u64> {
        let key = format!("latest:{}", hex::encode(chain_id));
        if let Some(value) = self.db.get(key.as_bytes())? {
            let seq: u64 = bincode::deserialize(&value).map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            Ok(seq)
        } else {
            Ok(0)
        }
    }

    pub fn list_chains(&self) -> MyResult<Vec<[u8; 32]>> {
        let mut chains = Vec::new();
        let prefix = b"chain:";
        for kv in self.db.scan_prefix(prefix) {
            let (key, _value) = kv?;
            let key_str = std::str::from_utf8(&key).map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
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

    pub fn create_chain(&self, chain_id: &[u8; 32]) -> MyResult<()> {
        let key = format!("chain:{}", hex::encode(chain_id));
        self.db.insert(key.as_bytes(), b"")?;
        self.update_latest_sequence(chain_id, 0)?;
        Ok(())
    }

    pub fn chain_exists(&self, chain_id: &[u8; 32]) -> MyResult<bool> {
        let key = format!("chain:{}", hex::encode(chain_id));
        Ok(self.db.contains_key(key.as_bytes())?)
    }
}