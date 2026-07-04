//! Tests for TTL garbage collection and state snapshotting.

use chains::crypto::keys::generate_signing_key;
use chains::models::{Body, Header};
use chains::storage::Storage;
use ed25519_dalek::SigningKey;
use tempfile::TempDir;

const SNAPSHOT_INTERVAL: u64 = 10_000;

fn temp_storage() -> (Storage, TempDir) {
    let dir = TempDir::new().unwrap();
    let storage = Storage::new(dir.path().join("db").to_str().unwrap()).unwrap();
    (storage, dir)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Stores a block at an explicit sequence with an explicit timestamp,
/// so tests can create already-expired blocks.
fn store_block_at(
    storage: &Storage,
    key: &SigningKey,
    chain_id: [u8; 32],
    sequence: u64,
    ttl: u32,
    timestamp: u64,
) -> Header {
    let prev_hash = storage
        .get_header(&chain_id, sequence.saturating_sub(1))
        .unwrap()
        .map(|h| h.block_id)
        .unwrap_or([0u8; 32]);

    let mut body = Body::new([0u8; 32], format!("block {}", sequence).into_bytes());
    let header = Header::new(
        chain_id,
        key.verifying_key().to_bytes(),
        sequence,
        timestamp,
        prev_hash,
        body.body_hash(),
        ttl,
        key,
    );
    body.block_id = header.block_id;

    storage.store_header(&chain_id, sequence, &header).unwrap();
    storage.store_body(&body.block_id, &body).unwrap();
    if sequence > storage.get_latest_sequence(&chain_id).unwrap() {
        storage.update_latest_sequence(&chain_id, sequence).unwrap();
    }
    header
}

#[test]
fn gc_on_empty_chain_is_a_noop() {
    let (storage, _dir) = temp_storage();
    let chain_id = [1u8; 32];
    storage.create_chain(&chain_id).unwrap();
    let stats = storage.collect_garbage(&chain_id).unwrap();
    assert_eq!(stats.bodies_pruned, 0);
    assert_eq!(stats.headers_pruned, 0);
}

#[test]
fn gc_prunes_expired_bodies_but_keeps_headers() {
    let (storage, _dir) = temp_storage();
    let key = generate_signing_key();
    let chain_id = [1u8; 32];
    storage.create_chain(&chain_id).unwrap();

    // Expired an hour ago (ttl 60s, written 2h ago).
    let expired = store_block_at(&storage, &key, chain_id, 1, 60, now() - 7200);
    // Fresh block, same ttl.
    let fresh = store_block_at(&storage, &key, chain_id, 2, 60, now());

    let stats = storage.collect_garbage(&chain_id).unwrap();
    assert_eq!(stats.bodies_pruned, 1);
    assert!(stats.bytes_freed > 0);

    // Expired: body gone, header retained to preserve chain integrity.
    assert!(storage.get_body(&expired.block_id).unwrap().is_none());
    assert!(storage.get_header(&chain_id, 1).unwrap().is_some());

    // Fresh: untouched.
    assert!(storage.get_body(&fresh.block_id).unwrap().is_some());
}

#[test]
fn gc_never_touches_ttl_zero_blocks() {
    let (storage, _dir) = temp_storage();
    let key = generate_signing_key();
    let chain_id = [1u8; 32];
    storage.create_chain(&chain_id).unwrap();

    // ttl = 0 means persist forever, even with an ancient timestamp.
    let eternal = store_block_at(&storage, &key, chain_id, 1, 0, 1);

    let stats = storage.collect_garbage(&chain_id).unwrap();
    assert_eq!(stats.bodies_pruned, 0);
    assert!(storage.get_body(&eternal.block_id).unwrap().is_some());
}

#[test]
fn gc_prunes_headers_only_beyond_snapshot_interval() {
    let (storage, _dir) = temp_storage();
    let key = generate_signing_key();
    let chain_id = [1u8; 32];
    storage.create_chain(&chain_id).unwrap();

    // One expired block at seq 1, then advance the chain tip far past the
    // snapshot interval (sparse: only the tip block actually exists).
    store_block_at(&storage, &key, chain_id, 1, 60, now() - 7200);
    let tip = SNAPSHOT_INTERVAL + 1;
    store_block_at(&storage, &key, chain_id, tip, 0, now());

    let stats = storage.collect_garbage(&chain_id).unwrap();
    assert_eq!(stats.bodies_pruned, 1);
    assert_eq!(
        stats.headers_pruned, 1,
        "old expired header should be pruned"
    );
    assert!(storage.get_header(&chain_id, 1).unwrap().is_none());
    assert!(storage.get_header(&chain_id, tip).unwrap().is_some());
}

#[test]
fn snapshot_round_trip() {
    let (storage, _dir) = temp_storage();
    let key = generate_signing_key();
    let chain_id = [1u8; 32];
    storage.create_chain(&chain_id).unwrap();

    for seq in 1..=5 {
        store_block_at(&storage, &key, chain_id, seq, 0, now());
    }

    storage.create_state_snapshot(&chain_id, 5).unwrap();
    let snapshot = storage.get_snapshot(&chain_id, 5).unwrap().unwrap();
    assert_eq!(snapshot.len(), 5);
    for (i, header) in snapshot.iter().enumerate() {
        assert_eq!(header.sequence, (i + 1) as u64);
        header.verify().unwrap();
    }
    assert!(storage.get_snapshot(&chain_id, 99).unwrap().is_none());
}

#[test]
fn prune_headers_before_snapshot_clears_history() {
    let (storage, _dir) = temp_storage();
    let key = generate_signing_key();
    let chain_id = [1u8; 32];
    storage.create_chain(&chain_id).unwrap();

    let mut block_ids = Vec::new();
    for seq in 1..=5 {
        block_ids.push(store_block_at(&storage, &key, chain_id, seq, 0, now()).block_id);
    }
    storage.create_state_snapshot(&chain_id, 5).unwrap();

    let pruned = storage.prune_headers_before_snapshot(&chain_id, 5).unwrap();
    assert_eq!(pruned, 4);

    for seq in 1..5 {
        assert!(storage.get_header(&chain_id, seq).unwrap().is_none());
    }
    // The snapshot block itself survives.
    assert!(storage.get_header(&chain_id, 5).unwrap().is_some());
    assert!(storage.get_body(&block_ids[4]).unwrap().is_some());
    // History is still recoverable from the snapshot.
    assert_eq!(
        storage.get_snapshot(&chain_id, 5).unwrap().unwrap().len(),
        5
    );
}
