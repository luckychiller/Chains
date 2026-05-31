use rand::random;
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng, AeadCore},
    XChaCha20Poly1305, XNonce,
};
use crate::models::ChainsResult;

#[derive(Clone, Debug)]
pub struct EpochKey {
    pub epoch: u64,
    pub key: [u8; 32],
    pub created_at: u64,
}

#[derive(Clone, Debug)]
pub struct EpochManager {
    current_epoch: u64,
    keys: Vec<EpochKey>,
    banned: Vec<[u8; 32]>,
}

impl EpochManager {
    pub fn new() -> Self {
        let key = generate_epoch_key();
        EpochManager {
            current_epoch: 1,
            keys: vec![EpochKey { epoch: 1, key, created_at: current_time() }],
            banned: Vec::new(),
        }
    }

    pub fn current_key(&self) -> &[u8; 32] {
        &self.keys.last().unwrap().key
    }

    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    pub fn rotate(&mut self) -> [u8; 32] {
        self.current_epoch += 1;
        let key = generate_epoch_key();
        self.keys.push(EpochKey {
            epoch: self.current_epoch,
            key,
            created_at: current_time(),
        });
        key
    }

    pub fn ban_user(&mut self, user_id: &[u8; 32]) {
        if !self.banned.contains(user_id) {
            self.banned.push(*user_id);
        }
    }

    pub fn is_banned(&self, user_id: &[u8; 32]) -> bool {
        self.banned.contains(user_id)
    }

    pub fn encrypt_for_subscriber(&self, subscriber_key: &[u8; 32], epoch: u64) -> ChainsResult<Vec<u8>> {
        let ek = self.keys.iter().find(|k| k.epoch == epoch)
            .ok_or_else(|| format!("Epoch {} not found", epoch))?;
        let cipher = XChaCha20Poly1305::new_from_slice(subscriber_key)
            .map_err(|e| format!("Invalid subscriber key: {}", e))?;
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, &ek.key[..])
            .map_err(|e| format!("Encrypt epoch key failed: {}", e))?;
        let mut out = epoch.to_le_bytes().to_vec();
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn decrypt_epoch_key(my_key: &[u8; 32], data: &[u8]) -> ChainsResult<([u8; 32], u64)> {
        if data.len() < 32 {
            return Err("Invalid epoch key data".into());
        }
        let (epoch_bytes, rest) = data.split_at(8);
        let epoch = u64::from_le_bytes(epoch_bytes.try_into().unwrap());
        let (nonce_bytes, ciphertext) = rest.split_at(24);
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(nonce_bytes);
        let nonce_ref = XNonce::from_slice(&nonce);
        let cipher = XChaCha20Poly1305::new_from_slice(my_key)
            .map_err(|e| format!("Invalid key: {}", e))?;
        let plaintext = cipher.decrypt(nonce_ref, ciphertext)
            .map_err(|e| format!("Decrypt epoch key failed: {}", e))?;
        let mut epoch_key = [0u8; 32];
        epoch_key.copy_from_slice(&plaintext);
        Ok((epoch_key, epoch))
    }

    pub fn key_count(&self) -> usize {
        self.keys.len()
    }
}

fn generate_epoch_key() -> [u8; 32] {
    random()
}

fn current_time() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}
