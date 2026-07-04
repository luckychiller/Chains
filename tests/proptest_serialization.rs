//! Property-based tests: serialization round-trips and structural invariants
//! must hold for arbitrary inputs, not just hand-picked examples.

use chains::crypto::keys::generate_signing_key;
use chains::models::{Body, Chain, Header};
use chains::network::{SyncRequest, SyncResponse};
use proptest::collection::vec;
use proptest::prelude::*;

fn arb_header() -> impl Strategy<Value = Header> {
    (
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
        any::<u64>(),
        any::<u64>(),
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
        any::<u32>(),
        vec(any::<u8>(), 64),
    )
        .prop_map(
            |(
                block_id,
                chain_id,
                author_id,
                sequence,
                timestamp,
                prev_hash,
                body_hash,
                ttl,
                signature,
            )| Header {
                block_id,
                chain_id,
                author_id,
                sequence,
                timestamp,
                prev_hash,
                body_hash,
                ttl,
                signature,
            },
        )
}

fn arb_body() -> impl Strategy<Value = Body> {
    (
        any::<[u8; 32]>(),
        "[a-zA-Z0-9-]{0,32}",
        any::<[u8; 24]>(),
        vec(any::<u8>(), 0..512),
    )
        .prop_map(|(block_id, encryption_algo, nonce, ciphertext)| Body {
            block_id,
            encryption_algo,
            nonce,
            ciphertext,
        })
}

proptest! {
    #[test]
    fn header_bincode_round_trip(header in arb_header()) {
        let bytes = bincode::serialize(&header).unwrap();
        let decoded: Header = bincode::deserialize(&bytes).unwrap();
        prop_assert_eq!(header, decoded);
    }

    #[test]
    fn body_bincode_round_trip(body in arb_body()) {
        let bytes = bincode::serialize(&body).unwrap();
        let decoded: Body = bincode::deserialize(&bytes).unwrap();
        prop_assert_eq!(body, decoded);
    }

    #[test]
    fn sync_messages_round_trip(
        chain_id in any::<[u8; 32]>(),
        start in any::<u64>(),
        end in any::<u64>(),
    ) {
        let req = SyncRequest::GetHeaders { chain_id, start_seq: start, end_seq: end };
        let bytes = bincode::serialize(&req).unwrap();
        match bincode::deserialize::<SyncRequest>(&bytes).unwrap() {
            SyncRequest::GetHeaders { chain_id: c, start_seq: s, end_seq: e } => {
                prop_assert_eq!(c, chain_id);
                prop_assert_eq!(s, start);
                prop_assert_eq!(e, end);
            }
            _ => prop_assert!(false, "wrong variant"),
        }

        let resp = SyncResponse::LatestSequence { chain_id, sequence: end };
        let bytes = bincode::serialize(&resp).unwrap();
        match bincode::deserialize::<SyncResponse>(&bytes).unwrap() {
            SyncResponse::LatestSequence { chain_id: c, sequence: s } => {
                prop_assert_eq!(c, chain_id);
                prop_assert_eq!(s, end);
            }
            _ => prop_assert!(false, "wrong variant"),
        }
    }
}

proptest! {
    // Signing is comparatively slow; keep the case count modest.
    #![proptest_config(ProptestConfig::with_cases(16))]

    /// Any payloads appended in any order produce a chain that validates.
    #[test]
    fn appended_chains_always_validate(
        payloads in vec(vec(any::<u8>(), 0..256), 1..8),
        ttl in any::<u32>(),
    ) {
        let key = generate_signing_key();
        let mut chain = Chain::new([1u8; 32]);
        for payload in payloads {
            chain = chain.append(payload, ttl, &key, None).unwrap();
        }
        chain.validate().unwrap();
    }

    /// Encryption round-trips for arbitrary data and keys.
    #[test]
    fn body_encryption_round_trip(
        data in vec(any::<u8>(), 0..1024),
        key in any::<[u8; 32]>(),
    ) {
        let body = Body::new_encrypted([0u8; 32], &data, &key).unwrap();
        prop_assert_eq!(body.decrypt(&key).unwrap(), data);
    }

    /// A freshly signed header verifies for any field values.
    #[test]
    fn signed_headers_always_verify(
        chain_id in any::<[u8; 32]>(),
        sequence in any::<u64>(),
        timestamp in any::<u64>(),
        prev_hash in any::<[u8; 32]>(),
        body_hash in any::<[u8; 32]>(),
        ttl in any::<u32>(),
    ) {
        let key = generate_signing_key();
        let header = Header::new(
            chain_id,
            key.verifying_key().to_bytes(),
            sequence,
            timestamp,
            prev_hash,
            body_hash,
            ttl,
            &key,
        );
        prop_assert!(header.verify().is_ok());
    }
}
