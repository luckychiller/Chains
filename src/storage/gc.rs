use crate::models::{ChainsResult, Header};
use crate::storage::Storage;

const SNAPSHOT_INTERVAL: u64 = 10_000;

#[derive(Debug)]
pub struct GcStats {
    pub bodies_pruned: u64,
    pub headers_pruned: u64,
    pub snapshots_created: u64,
    pub bytes_freed: u64,
}

impl Storage {
    pub fn collect_garbage(&self, chain_id: &[u8; 32]) -> ChainsResult<GcStats> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut stats = GcStats {
            bodies_pruned: 0,
            headers_pruned: 0,
            snapshots_created: 0,
            bytes_freed: 0,
        };

        let latest = self.get_latest_sequence(chain_id)?;
        if latest == 0 {
            return Ok(stats);
        }

        let mut expired_sequences = Vec::new();
        for seq in 1..=latest {
            if let Some(header) = self.get_header(chain_id, seq)? {
                if header.ttl > 0 && (header.timestamp + header.ttl as u64) < now {
                    expired_sequences.push((seq, header.block_id, header.ttl));
                }
            }
        }

        for (seq, block_id, _ttl) in &expired_sequences {
            if let Some(body) = self.get_body(block_id)? {
                stats.bytes_freed += bincode::serialize(&body)?.len() as u64;
            }
            self.delete_body(block_id)?;
            stats.bodies_pruned += 1;

            if latest - *seq >= SNAPSHOT_INTERVAL {
                self.delete_header(chain_id, *seq)?;
                stats.headers_pruned += 1;
            }
        }

        if latest > 0 && latest % SNAPSHOT_INTERVAL == 0 {
            self.create_state_snapshot(chain_id, latest)?;
            stats.snapshots_created += 1;
        }

        Ok(stats)
    }

    pub fn delete_body(&self, block_id: &[u8; 32]) -> ChainsResult<()> {
        let key = format!("body:{}", hex::encode(block_id));
        self.db.remove(key.as_bytes())?;
        Ok(())
    }

    pub fn delete_header(&self, chain_id: &[u8; 32], sequence: u64) -> ChainsResult<()> {
        let key = crate::storage::header_key(chain_id, sequence);
        self.db.remove(key.as_bytes())?;
        Ok(())
    }

    pub fn create_state_snapshot(&self, chain_id: &[u8; 32], up_to_seq: u64) -> ChainsResult<()> {
        let mut headers = Vec::new();
        for seq in 1..=up_to_seq {
            if let Some(header) = self.get_header(chain_id, seq)? {
                headers.push(header);
            }
        }

        let snapshot_key = format!("snapshot:{}:{}", hex::encode(chain_id), up_to_seq);
        let data = bincode::serialize(&headers)?;
        self.db.insert(snapshot_key.as_bytes(), data)?;
        self.update_latest_sequence(chain_id, up_to_seq)?;
        Ok(())
    }

    pub fn get_snapshot(&self, chain_id: &[u8; 32], seq: u64) -> ChainsResult<Option<Vec<Header>>> {
        let key = format!("snapshot:{}:{}", hex::encode(chain_id), seq);
        if let Some(value) = self.db.get(key.as_bytes())? {
            let headers: Vec<Header> = bincode::deserialize(&value)?;
            Ok(Some(headers))
        } else {
            Ok(None)
        }
    }

    pub fn prune_headers_before_snapshot(
        &self,
        chain_id: &[u8; 32],
        snapshot_seq: u64,
    ) -> ChainsResult<u64> {
        let mut pruned = 0u64;
        for seq in 1..snapshot_seq {
            if let Some(header) = self.get_header(chain_id, seq)? {
                self.delete_header(chain_id, seq)?;
                self.delete_body(&header.block_id)?;
                pruned += 1;
            }
        }
        Ok(pruned)
    }
}
