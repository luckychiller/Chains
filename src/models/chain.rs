use crate::models::body::Body;
use crate::models::header::{ChainsResult, Header};
use ed25519_dalek::SigningKey;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// A high-level representation of an append-only cryptographic stream.
#[derive(Clone, Debug)]
pub struct Chain {
    /// The unique identifier of the chain (Public Key).
    pub id: [u8; 32],
    /// Ordered list of headers in the chain.
    pub headers: Vec<Header>,
    /// Map of block_id to the actual block Body.
    pub bodies: HashMap<[u8; 32], Body>,
}

impl Chain {
    /// Initializes a new empty chain with a given ID.
    pub fn new(id: [u8; 32]) -> Self {
        Chain {
            id,
            headers: Vec::new(),
            bodies: HashMap::new(),
        }
    }

    /// Exhaustively validates the cryptographic integrity of the entire chain.
    pub fn validate(&self) -> ChainsResult<()> {
        if self.headers.is_empty() {
            return Ok(());
        }

        for (i, header) in self.headers.iter().enumerate() {
            let expected_seq = (i + 1) as u64;
            if header.sequence != expected_seq {
                return Err(format!(
                    "Sequence error at {}: expected {}, got {}",
                    i, expected_seq, header.sequence
                )
                .into());
            }

            if header.chain_id != self.id {
                return Err(format!("Chain ID mismatch at seq {}", header.sequence).into());
            }

            if i == 0 {
                if header.prev_hash != [0u8; 32] {
                    return Err("Genesis must have zero prev_hash".into());
                }
            } else if header.prev_hash != self.headers[i - 1].block_id {
                return Err(format!("Hash chain broken at seq {}", header.sequence).into());
            }

            if let Some(body) = self.bodies.get(&header.block_id) {
                if header.body_hash != body.body_hash() {
                    return Err(format!("Body hash mismatch at seq {}", header.sequence).into());
                }
            } else {
                return Err(format!("Body missing at seq {}", header.sequence).into());
            }

            header.verify()?;
        }

        Ok(())
    }

    /// Appends a new block to the chain.
    pub fn append(
        &self,
        data: Vec<u8>,
        ttl: u32,
        signing_key: &SigningKey,
        encryption_key: Option<&[u8; 32]>,
    ) -> ChainsResult<Chain> {
        let mut new_chain = self.clone();
        let sequence = (new_chain.headers.len() + 1) as u64;
        let prev_hash = new_chain
            .headers
            .last()
            .map(|h| h.block_id)
            .unwrap_or([0u8; 32]);
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        let mut body = if let Some(key) = encryption_key {
            Body::new_encrypted([0; 32], &data, key)?
        } else {
            Body::new([0; 32], data)
        };

        let header = Header::new(
            new_chain.id,
            signing_key.verifying_key().to_bytes(),
            sequence,
            timestamp,
            prev_hash,
            body.body_hash(),
            ttl,
            signing_key,
        );

        body.block_id = header.block_id;
        new_chain.headers.push(header);
        new_chain.bodies.insert(body.block_id, body);

        Ok(new_chain)
    }
}
