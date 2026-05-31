/// Core hashing utilities using BLAKE3.
pub mod hashing {
    /// Computes the 32-byte BLAKE3 hash of the input data.
    pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
        blake3::hash(data).into()
    }
}

/// Double Ratchet encryption for private messaging.
pub mod ratchet;

/// Rotational Epoch Keys for public streaming.
pub mod epoch;

/// Key generation and management.
pub mod keys {
    use ed25519_dalek::SigningKey;
    use rand::random;

    /// Generates a random Ed25519 signing key.
    pub fn generate_signing_key() -> SigningKey {
        let secret: [u8; 32] = random();
        SigningKey::from_bytes(&secret)
    }
}
