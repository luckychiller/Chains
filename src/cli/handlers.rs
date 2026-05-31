use std::sync::Arc;
use tokio::sync::Mutex;
use crate::models::{Header, Body, ChainsResult};
use crate::storage::Storage;
use ed25519_dalek::SigningKey;
use std::time::{SystemTime, UNIX_EPOCH};

/// Handles local storage operations for the CLI.
pub struct CommandHandlers;

impl CommandHandlers {
    pub async fn append_local(
        storage: &Arc<Mutex<Storage>>,
        signing_key: &SigningKey,
        chain_id: [u8; 32],
        data: &str,
        ttl: u32,
        encryption_key: Option<&[u8; 32]>,
    ) -> ChainsResult<()> {
        let storage_lock = storage.lock().await;
        if !storage_lock.chain_exists(&chain_id)? {
            return Err("Chain not found.".into());
        }

        let latest_seq = storage_lock.get_latest_sequence(&chain_id)?;
        let sequence = latest_seq + 1;
        let prev_hash = if sequence == 1 { [0u8; 32] } else {
            storage_lock.get_header(&chain_id, sequence - 1)?.ok_or("Prev header missing")?.block_id
        };

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let mut body = if let Some(key) = encryption_key {
            Body::new_encrypted([0; 32], data.as_bytes(), key)?
        } else {
            Body::new([0; 32], data.as_bytes().to_vec())
        };

        let header = Header::new(
            chain_id,
            signing_key.verifying_key().to_bytes(),
            sequence,
            timestamp,
            prev_hash,
            body.body_hash(),
            ttl,
            signing_key,
        );

        body.block_id = header.block_id;
        storage_lock.store_header(&chain_id, sequence, &header)?;
        storage_lock.store_body(&body.block_id, &body)?;
        storage_lock.update_latest_sequence(&chain_id, sequence)?;

        println!("Appended block {} to {}", sequence, hex::encode(chain_id));
        Ok(())
    }

    pub async fn show_chain(
        storage: &Arc<Mutex<Storage>>,
        chain_id: [u8; 32],
        encryption_key: Option<&[u8; 32]>,
    ) -> ChainsResult<()> {
        let storage = storage.lock().await;
        let latest = storage.get_latest_sequence(&chain_id)?;
        println!("Chain: {} ({} blocks)\n", hex::encode(chain_id), latest);

        for seq in 1..=latest {
            if let Some(header) = storage.get_header(&chain_id, seq)? {
                let data_str = if let Some(body) = storage.get_body(&header.block_id)? {
                    if body.encryption_algo != "none" {
                        if let Some(key) = encryption_key {
                            body.decrypt(key).map(|p| String::from_utf8_lossy(&p).to_string())
                                .unwrap_or_else(|e| format!("<decryption error: {}>", e))
                        } else { "<encrypted>".to_string() }
                    } else { String::from_utf8_lossy(&body.ciphertext).to_string() }
                } else { "<missing body>".to_string() };

                println!("[{}] id={}.. data={:?}", header.sequence, hex::encode(&header.block_id[..4]), data_str);
            }
        }
        Ok(())
    }
}
