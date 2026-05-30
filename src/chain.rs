use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use ed25519_dalek::SigningKey;
use hex;

use crate::header::Header;
use crate::body::Body;

type MyResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Debug)]
pub struct Chain {
    pub id: [u8; 32],
    pub headers: Vec<Header>,
    pub bodies: HashMap<[u8; 32], Body>,
}

impl Chain {
    pub fn new(id: [u8; 32]) -> Self {
        Chain {
            id,
            headers: Vec::new(),
            bodies: HashMap::new(),
        }
    }

    pub fn validate(&self) -> MyResult<()> {
        if self.headers.is_empty() {
            return Ok(());
        }

        for (i, header) in self.headers.iter().enumerate() {
            let expected_seq = (i + 1) as u64;
            if header.sequence != expected_seq {
                return Err(
                    format!("Sequence discontinuity at index {}: expected {}, got {}",
                        i, expected_seq, header.sequence).into()
                );
            }

            if header.chain_id != self.id {
                return Err(
                    format!("Header chain_id mismatch at sequence {}", header.sequence).into()
                );
            }

            if i == 0 {
                if header.prev_hash != [0u8; 32] {
                    return Err("Genesis header must have zero prev_hash".into());
                }
            } else {
                if header.prev_hash != self.headers[i - 1].block_id {
                    return Err(
                        format!("Hash chain broken at sequence {}", header.sequence).into()
                    );
                }
            }

            if let Some(body) = self.bodies.get(&header.block_id) {
                let expected = body.body_hash();
                if header.body_hash != expected {
                    return Err(
                        format!("Body hash mismatch at sequence {}: expected {}.., got {}..",
                            header.sequence,
                            hex::encode(&expected[..4]),
                            hex::encode(&header.body_hash[..4]),
                        ).into()
                    );
                }
            } else {
                return Err(
                    format!("Body missing for header at sequence {}", header.sequence).into()
                );
            }

            header.verify()?;
        }

        Ok(())
    }

    pub fn append(
        &self,
        data: Vec<u8>,
        ttl: u32,
        signing_key: &SigningKey,
        encryption_key: Option<&[u8; 32]>,
    ) -> MyResult<Chain> {
        let mut new_chain = self.clone();

        let sequence = new_chain.headers.len() as u64 + 1;
        let prev_hash = if sequence == 1 {
            [0u8; 32]
        } else {
            new_chain.headers.last().unwrap().block_id
        };

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();

        let body = if let Some(key) = encryption_key {
            Body::new_encrypted([0; 32], &data, key)?
        } else {
            Body::new([0; 32], data)
        };
        let body_hash = body.body_hash();

        let author_id = signing_key.verifying_key().to_bytes();

        let header = Header::new(
            new_chain.id,
            author_id,
            sequence,
            timestamp,
            prev_hash,
            body_hash,
            ttl,
            signing_key,
        );

        let mut body = body;
        body.block_id = header.block_id;

        new_chain.headers.push(header);
        new_chain.bodies.insert(body.block_id, body);

        Ok(new_chain)
    }

    pub fn get_body(&self, block_id: &[u8; 32]) -> Option<&Body> {
        self.bodies.get(block_id)
    }

    pub fn get_header(&self, sequence: u64) -> Option<&Header> {
        if sequence == 0 || sequence > self.headers.len() as u64 {
            None
        } else {
            self.headers.get((sequence - 1) as usize)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_signing_key;

    #[test]
    fn test_chain_append_and_validate() -> MyResult<()> {
        let chain_id: [u8; 32] = [1; 32];
        let signing_key = generate_signing_key();
        let chain = Chain::new(chain_id);

        let chain = chain.append(b"Hello Chains".to_vec(), 0, &signing_key, None)?;
        assert_eq!(chain.headers.len(), 1);
        assert_eq!(chain.headers[0].sequence, 1);

        let chain = chain.append(b"Second block".to_vec(), 0, &signing_key, None)?;
        assert_eq!(chain.headers.len(), 2);
        assert_eq!(chain.headers[1].sequence, 2);
        assert_eq!(chain.headers[1].prev_hash, chain.headers[0].block_id);

        chain.validate()?;

        Ok(())
    }

    #[test]
    fn test_chain_encryption() -> MyResult<()> {
        let chain_id: [u8; 32] = [2; 32];
        let signing_key = generate_signing_key();
        let encryption_key: [u8; 32] = [42; 32];
        let chain = Chain::new(chain_id);

        let plaintext = b"Top secret data";
        let chain = chain.append(plaintext.to_vec(), 0, &signing_key, Some(&encryption_key))?;
        
        let body = chain.get_body(&chain.headers[0].block_id).unwrap();
        assert_eq!(body.encryption_algo, "XChaCha20-Poly1305");
        assert_ne!(body.ciphertext, plaintext);

        let decrypted = body.decrypt(&encryption_key)?;
        assert_eq!(decrypted, plaintext);

        Ok(())
    }
}
