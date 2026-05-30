use serde::{Deserialize, Serialize};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng, AeadCore},
    XChaCha20Poly1305, XNonce,
};

use crate::crypto;

type MyResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Body {
    pub block_id: [u8; 32],
    pub encryption_algo: String,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

impl Body {
    pub fn new(block_id: [u8; 32], data: Vec<u8>) -> Self {
        Body {
            block_id,
            encryption_algo: "none".to_string(),
            nonce: [0; 24],
            ciphertext: data,
        }
    }

    pub fn new_encrypted(block_id: [u8; 32], data: &[u8], key: &[u8; 32]) -> MyResult<Self> {
        let cipher = XChaCha20Poly1305::new(key.into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng); // 24-byte nonce
        
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

    pub fn decrypt(&self, key: &[u8; 32]) -> MyResult<Vec<u8>> {
        if self.encryption_algo == "none" {
            return Ok(self.ciphertext.clone());
        }

        if self.encryption_algo != "XChaCha20-Poly1305" {
            return Err(format!("Unsupported encryption algorithm: {}", self.encryption_algo).into());
        }

        let cipher = XChaCha20Poly1305::new(key.into());
        let nonce = XNonce::from_slice(&self.nonce);

        let plaintext = cipher.decrypt(nonce, self.ciphertext.as_slice())
            .map_err(|e| format!("Decryption failed: {}", e))?;

        Ok(plaintext)
    }

    pub fn body_hash(&self) -> [u8; 32] {
        crypto::blake3_hash(&self.ciphertext)
    }
}

