use serde::{Deserialize, Serialize};
use ed25519_dalek::SigningKey;

use crate::crypto;

type MyResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;


#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Header {
    pub block_id: [u8; 32],
    pub chain_id: [u8; 32],
    pub author_id: [u8; 32],
    pub sequence: u64,
    pub timestamp: u64,
    pub prev_hash: [u8; 32],
    pub body_hash: [u8; 32],
    pub ttl: u32,
    pub signature: Vec<u8>,
}

impl Header {
    pub fn new(
        chain_id: [u8; 32],
        author_id: [u8; 32],
        sequence: u64,
        timestamp: u64,
        prev_hash: [u8; 32],
        body_hash: [u8; 32],
        ttl: u32,
        signing_key: &SigningKey,
    ) -> Self {
        let mut header = Header {
            block_id: [0; 32],
            chain_id,
            author_id,
            sequence,
            timestamp,
            prev_hash,
            body_hash,
            ttl,
            signature: vec![],
        };

        let signing_data = header.signing_data();
        let sig = crypto::sign(signing_key, &signing_data);
        header.signature = sig.to_vec();

        header.block_id = crypto::blake3_hash(&header.serialized_without_id());

        header
    }

    fn signing_data(&self) -> Vec<u8> {
        [&self.prev_hash[..], &self.body_hash[..], &self.sequence.to_le_bytes()[..]]
            .concat()
    }

    fn serialized_without_id(&self) -> Vec<u8> {
        bincode::serialize(&(
            self.chain_id,
            self.author_id,
            self.sequence,
            self.timestamp,
            self.prev_hash,
            self.body_hash,
            self.ttl,
            &self.signature,
        ))
        .unwrap()
    }

    pub fn verify(&self) -> MyResult<()> {
        let computed_id = crypto::blake3_hash(&self.serialized_without_id());
        if self.block_id != computed_id {
            return Err("Block ID mismatch".into());
        }

        let sig_bytes: [u8; 64] = self.signature.as_slice().try_into()
            .map_err(|_| "Invalid signature length: expected 64 bytes")?;
        crypto::verify(&self.author_id, &self.signing_data(), &sig_bytes)
            .map_err(|e| format!("Signature verification failed: {}", e).into())
    }
}
