//! Tests for the data layer: header signing, chain linkage, tamper detection.

use chains::crypto::hashing::blake3_hash;
use chains::crypto::keys::generate_signing_key;
use chains::models::{Body, Chain, Header};
use ed25519_dalek::SigningKey;

/// A named field mutation, used to tamper with headers one field at a time.
type Mutation = (&'static str, Box<dyn Fn(&mut Header)>);

fn make_header(signing_key: &SigningKey, sequence: u64, prev_hash: [u8; 32]) -> Header {
    let chain_id = [1u8; 32];
    let body = Body::new([0u8; 32], format!("payload {}", sequence).into_bytes());
    Header::new(
        chain_id,
        signing_key.verifying_key().to_bytes(),
        sequence,
        1_700_000_000,
        prev_hash,
        body.body_hash(),
        0,
        signing_key,
    )
}

#[test]
fn header_signs_and_verifies() {
    let key = generate_signing_key();
    let header = make_header(&key, 1, [0u8; 32]);
    header.verify().unwrap();
}

#[test]
fn header_tampered_fields_are_detected() {
    let key = generate_signing_key();

    // Every mutable field, tampered one at a time, must fail verification.
    let tampered: Vec<Mutation> = vec![
        ("sequence", Box::new(|h| h.sequence += 1)),
        ("timestamp", Box::new(|h| h.timestamp += 1)),
        ("ttl", Box::new(|h| h.ttl = 9999)),
        ("chain_id", Box::new(|h| h.chain_id = [9u8; 32])),
        ("prev_hash", Box::new(|h| h.prev_hash = [9u8; 32])),
        ("body_hash", Box::new(|h| h.body_hash = [9u8; 32])),
        ("block_id", Box::new(|h| h.block_id = [9u8; 32])),
    ];

    for (field, mutate) in tampered {
        let mut header = make_header(&key, 1, [0u8; 32]);
        mutate(&mut header);
        assert!(
            header.verify().is_err(),
            "tampered {} must fail verification",
            field
        );
    }
}

/// Recomputing the block_id after tampering must NOT be enough to forge a
/// header: the signature has to cover every field, not just a subset.
/// (Regression test — the signature originally covered only
/// prev_hash + body_hash + sequence.)
#[test]
fn header_tamper_with_recomputed_block_id_still_fails() {
    let key = generate_signing_key();

    let cases: Vec<Mutation> = vec![
        ("timestamp", Box::new(|h| h.timestamp += 3600)),
        ("ttl", Box::new(|h| h.ttl = 1)),
        ("chain_id", Box::new(|h| h.chain_id = [9u8; 32])),
    ];

    for (field, mutate) in cases {
        let mut header = make_header(&key, 1, [0u8; 32]);
        mutate(&mut header);
        // Attacker recomputes the content hash to cover their tracks.
        header.block_id = recomputed_block_id(&header);
        assert!(
            header.verify().is_err(),
            "forged {} with fixed-up block_id must still fail",
            field
        );
    }
}

/// Mirrors Header::serialized_without_id so tests can simulate an attacker
/// recomputing the block_id after tampering.
fn recomputed_block_id(h: &Header) -> [u8; 32] {
    blake3_hash(
        &bincode::serialize(&(
            h.chain_id,
            h.author_id,
            h.sequence,
            h.timestamp,
            h.prev_hash,
            h.body_hash,
            h.ttl,
            &h.signature,
        ))
        .unwrap(),
    )
}

#[test]
fn header_signed_by_someone_else_fails() {
    let key = generate_signing_key();
    let other = generate_signing_key();
    let mut header = make_header(&key, 1, [0u8; 32]);
    // Claim a different author without access to their private key.
    header.author_id = other.verifying_key().to_bytes();
    header.block_id = recomputed_block_id(&header);
    assert!(header.verify().is_err());
}

// ─── Chain integrity ───────────────────────────────────────────────────────

fn build_chain(len: usize) -> (Chain, SigningKey) {
    let key = generate_signing_key();
    let mut chain = Chain::new([1u8; 32]);
    for i in 0..len {
        chain = chain
            .append(format!("block {}", i).into_bytes(), 0, &key, None)
            .unwrap();
    }
    (chain, key)
}

#[test]
fn chain_append_links_blocks_and_validates() {
    let (chain, _) = build_chain(5);
    assert_eq!(chain.headers.len(), 5);
    assert_eq!(chain.headers[0].prev_hash, [0u8; 32]);
    for i in 1..5 {
        assert_eq!(chain.headers[i].prev_hash, chain.headers[i - 1].block_id);
    }
    chain.validate().unwrap();
}

#[test]
fn chain_empty_is_valid() {
    Chain::new([1u8; 32]).validate().unwrap();
}

#[test]
fn chain_broken_linkage_is_detected() {
    let (mut chain, _) = build_chain(5);
    chain.headers[2].prev_hash = [9u8; 32];
    assert!(chain.validate().is_err());
}

#[test]
fn chain_missing_body_is_detected() {
    let (mut chain, _) = build_chain(3);
    let victim = chain.headers[1].block_id;
    chain.bodies.remove(&victim);
    assert!(chain.validate().is_err());
}

#[test]
fn chain_swapped_body_is_detected() {
    let (mut chain, _) = build_chain(3);
    let victim = chain.headers[1].block_id;
    let mut forged = chain.bodies[&victim].clone();
    forged.ciphertext = b"forged payload".to_vec();
    chain.bodies.insert(victim, forged);
    assert!(chain.validate().is_err());
}

#[test]
fn chain_wrong_sequence_is_detected() {
    let (mut chain, _) = build_chain(3);
    chain.headers[1].sequence = 7;
    assert!(chain.validate().is_err());
}

#[test]
fn chain_foreign_chain_id_is_detected() {
    let (chain, _) = build_chain(2);
    let mut renamed = chain.clone();
    renamed.id = [2u8; 32]; // headers still claim chain [1u8; 32]
    assert!(renamed.validate().is_err());
}

// ─── Body encryption ───────────────────────────────────────────────────────

#[test]
fn body_plaintext_round_trip() {
    let body = Body::new([1u8; 32], b"clear data".to_vec());
    assert_eq!(body.encryption_algo, "none");
    assert_eq!(body.decrypt(&[0u8; 32]).unwrap(), b"clear data");
}

#[test]
fn body_encrypted_round_trip() {
    let key: [u8; 32] = rand::random();
    let body = Body::new_encrypted([1u8; 32], b"secret data", &key).unwrap();
    assert_eq!(body.encryption_algo, "XChaCha20-Poly1305");
    assert_ne!(body.ciphertext, b"secret data");
    assert_eq!(body.decrypt(&key).unwrap(), b"secret data");
}

#[test]
fn body_wrong_key_fails() {
    let key: [u8; 32] = rand::random();
    let wrong: [u8; 32] = rand::random();
    let body = Body::new_encrypted([1u8; 32], b"secret data", &key).unwrap();
    assert!(body.decrypt(&wrong).is_err());
}

#[test]
fn body_unsupported_algorithm_fails() {
    let mut body = Body::new([1u8; 32], b"data".to_vec());
    body.encryption_algo = "ROT13".to_string();
    assert!(body.decrypt(&[0u8; 32]).is_err());
}

#[test]
fn body_hash_is_over_ciphertext() {
    let key: [u8; 32] = rand::random();
    let body = Body::new_encrypted([1u8; 32], b"secret data", &key).unwrap();
    assert_eq!(body.body_hash(), blake3_hash(&body.ciphertext));
}
