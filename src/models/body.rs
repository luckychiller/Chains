use serde::{Deserialize, Serialize};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng, AeadCore},
    XChaCha20Poly1305, XNonce,
};
use crate::crypto::hashing;
use crate::models::header::ChainsResult;

/// The heavyweight payload of a block.
///
/// Bodies contain the actual data (e.g., chat messages, video frames) and
/// can be encrypted using XChaCha20-Poly1305.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Body {
    /// Links the body to its corresponding Header.
    pub block_id: [u8; 32],
    /// Encryption algorithm used (e.g., "none" or "XChaCha20-Poly1305").
    pub encryption_algo: String,
    /// 24-byte nonce used for XChaCha20.
    pub nonce: [u8; 24],
    /// The actual data, potentially encrypted.
    pub ciphertext: Vec<u8>,
}

impl Body {
    /// Creates a new unencrypted Body.
    pub fn new(block_id: [u8; 32], data: Vec<u8>) -> Self {
        Body {
            block_id,
            encryption_algo: "none".to_string(),
            nonce: [0; 24],
            ciphertext: data,
        }
    }

    /// Creates a new Body encrypted with XChaCha20-Poly1305.
    pub fn new_encrypted(block_id: [u8; 32], data: &[u8], key: &[u8; 32]) -> ChainsResult<Self> {
        let cipher = XChaCha20Poly1305::new(key.into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        
        let ciphertext = cipher.encrypt(&nonce, data)
            .map_err(|e| format!("Encryption failed: {}", e))?;

        let mut nonce_bytes = [0u8; 24];
        nonce_bytes.copy_from_slice(nonce.as_slice());

        Ok(Body {
            block_id,
            encryption_algo: "XChaCha20-Poly1305".to_string(),
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    /// Decrypts the body using the provided 32-byte key.
    pub fn decrypt(&self, key: &[u8; 32]) -> ChainsResult<Vec<u8>> {
        if self.encryption_algo == "none" {
            return Ok(self.ciphertext.clone());
        }

        if self.encryption_algo != "XChaCha20-Poly1305" {
            return Err(format!("Unsupported algorithm: {}", self.encryption_algo).into());
        }

        let cipher = XChaCha20Poly1305::new(key.into());
        let nonce = XNonce::from_slice(&self.nonce);

        let plaintext = cipher.decrypt(nonce, self.ciphertext.as_slice())
            .map_err(|e| format!("Decryption failed: {}", e))?;

        Ok(plaintext)
    }

    /// Returns the BLAKE3 hash of the ciphertext.
    pub fn body_hash(&self) -> [u8; 32] {
        hashing::blake3_hash(&self.ciphertext)
    }
}
