use crate::crypto::hashing;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};

/// A specialized Result type for Chains operations.
pub type ChainsResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// The lightweight metadata of a block.
///
/// Headers are designed to be gossiped quickly across the network to verify
/// the integrity and order of a stream without requiring the full payload.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// BLAKE3 hash of the serialized header (excluding this field).
    pub block_id: [u8; 32],
    /// Ed25519 Public Key identifying the chain/topic.
    pub chain_id: [u8; 32],
    /// Ed25519 Public Key of the block author.
    pub author_id: [u8; 32],
    /// Monotonically increasing sequence number.
    pub sequence: u64,
    /// Unix timestamp of block creation.
    pub timestamp: u64,
    /// block_id of the preceding block in the chain.
    pub prev_hash: [u8; 32],
    /// BLAKE3 hash of the (potentially encrypted) body ciphertext.
    pub body_hash: [u8; 32],
    /// Time-to-live in seconds (0 = persistent).
    pub ttl: u32,
    /// Ed25519 signature of the header data.
    pub signature: Vec<u8>,
}

impl Header {
    /// Creates and signs a new Header.
    #[allow(clippy::too_many_arguments)] // constructor mirrors the wire format
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
        header.signature = signing_key.sign(&signing_data).to_bytes().to_vec();
        header.block_id = hashing::blake3_hash(&header.serialized_without_id());

        header
    }

    /// Data used for signing: every field except `block_id` and `signature`,
    /// so no field can be tampered with after signing.
    fn signing_data(&self) -> Vec<u8> {
        bincode::serialize(&(
            self.chain_id,
            self.author_id,
            self.sequence,
            self.timestamp,
            self.prev_hash,
            self.body_hash,
            self.ttl,
        ))
        .unwrap()
    }

    /// Serializes the header excluding the block_id for hashing.
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

    /// Verifies the cryptographic signature and block_id integrity.
    pub fn verify(&self) -> ChainsResult<()> {
        let computed_id = hashing::blake3_hash(&self.serialized_without_id());
        if self.block_id != computed_id {
            return Err("Block ID mismatch".into());
        }

        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let key = VerifyingKey::from_bytes(&self.author_id)
            .map_err(|e| format!("Invalid author key: {}", e))?;
        let sig_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid signature length")?;
        let signature = Signature::from_bytes(&sig_bytes);

        key.verify(&self.signing_data(), &signature)
            .map_err(|e| format!("Signature verification failed: {}", e).into())
    }
}
