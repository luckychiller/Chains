//! Tests for the encryption engine: X3DH, Double Ratchet, and Epoch Keys.

use chains::crypto::epoch::EpochManager;
use chains::crypto::ratchet::{
    generate_dh_keypair, x3dh_receive, x3dh_shared_secret, RatchetState,
};
use chains::models::Body;
use x25519_dalek::{PublicKey, StaticSecret};

fn keypair() -> (StaticSecret, PublicKey) {
    let sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let pk = PublicKey::from(&sk);
    (sk, pk)
}

/// Sets up a ratchet session pair the way a real handshake would:
/// Alice (initiator) knows Bob's signed prekey as his initial ratchet key.
fn ratchet_pair() -> (RatchetState, RatchetState) {
    let (alice_id_sk, alice_id_pk) = keypair();
    let (alice_eph_sk, alice_eph_pk) = keypair();
    let (bob_id_sk, bob_id_pk) = keypair();
    let (bob_spk_sk, bob_spk_pk) = keypair();

    let root_a = x3dh_shared_secret(&alice_id_sk, &alice_eph_sk, &bob_id_pk, &bob_spk_pk);
    let root_b = x3dh_receive(&bob_id_sk, &bob_spk_sk, &alice_id_pk, &alice_eph_pk);
    assert_eq!(root_a, root_b, "X3DH must agree on both sides");

    let (alice_dh_sk, alice_dh_pk) = generate_dh_keypair();
    let alice = RatchetState::new_receiver(root_a, alice_dh_sk, alice_dh_pk, bob_spk_pk.to_bytes());
    let bob = RatchetState::new_sender(root_b, bob_spk_sk.to_bytes(), bob_spk_pk.to_bytes());
    (alice, bob)
}

#[test]
fn x3dh_both_sides_derive_same_secret() {
    let (alice_id_sk, alice_id_pk) = keypair();
    let (alice_eph_sk, alice_eph_pk) = keypair();
    let (bob_id_sk, bob_id_pk) = keypair();
    let (bob_spk_sk, bob_spk_pk) = keypair();

    let sender = x3dh_shared_secret(&alice_id_sk, &alice_eph_sk, &bob_id_pk, &bob_spk_pk);
    let receiver = x3dh_receive(&bob_id_sk, &bob_spk_sk, &alice_id_pk, &alice_eph_pk);
    assert_eq!(sender, receiver);
}

#[test]
fn x3dh_different_parties_derive_different_secrets() {
    let (alice_id_sk, _) = keypair();
    let (alice_eph_sk, _) = keypair();
    let (_, bob_id_pk) = keypair();
    let (_, bob_spk_pk) = keypair();
    let (_, eve_id_pk) = keypair();

    let with_bob = x3dh_shared_secret(&alice_id_sk, &alice_eph_sk, &bob_id_pk, &bob_spk_pk);
    let with_eve = x3dh_shared_secret(&alice_id_sk, &alice_eph_sk, &eve_id_pk, &bob_spk_pk);
    assert_ne!(with_bob, with_eve);
}

#[test]
fn ratchet_single_message_round_trip() {
    let (mut alice, mut bob) = ratchet_pair();
    let msg = alice.encrypt_message(b"hello bob").unwrap();
    let plaintext = bob.decrypt_message(&msg).unwrap();
    assert_eq!(plaintext, b"hello bob");
}

#[test]
fn ratchet_sequential_messages_same_direction() {
    let (mut alice, mut bob) = ratchet_pair();
    for i in 0..10u32 {
        let text = format!("message {}", i);
        let msg = alice.encrypt_message(text.as_bytes()).unwrap();
        assert_eq!(bob.decrypt_message(&msg).unwrap(), text.as_bytes());
    }
}

#[test]
fn ratchet_ping_pong_multiple_round_trips() {
    let (mut alice, mut bob) = ratchet_pair();
    // Each full round-trip forces a DH ratchet step on both sides.
    for round in 0..5u32 {
        let a_text = format!("alice round {}", round);
        let msg = alice.encrypt_message(a_text.as_bytes()).unwrap();
        assert_eq!(bob.decrypt_message(&msg).unwrap(), a_text.as_bytes());

        let b_text = format!("bob round {}", round);
        let msg = bob.encrypt_message(b_text.as_bytes()).unwrap();
        assert_eq!(alice.decrypt_message(&msg).unwrap(), b_text.as_bytes());
    }
}

#[test]
fn ratchet_keys_change_every_message() {
    let (mut alice, mut bob) = ratchet_pair();
    let m1 = alice.encrypt_message(b"same plaintext").unwrap();
    let m2 = alice.encrypt_message(b"same plaintext").unwrap();
    assert_ne!(
        m1.ciphertext, m2.ciphertext,
        "identical plaintexts must never produce identical ciphertexts"
    );
    bob.decrypt_message(&m1).unwrap();
    bob.decrypt_message(&m2).unwrap();
}

#[test]
fn ratchet_tampered_ciphertext_is_rejected() {
    let (mut alice, mut bob) = ratchet_pair();
    let mut msg = alice.encrypt_message(b"secret").unwrap();
    msg.ciphertext[0] ^= 0xFF;
    assert!(bob.decrypt_message(&msg).is_err());
}

#[test]
fn ratchet_wrong_root_key_cannot_decrypt() {
    let (mut alice, _) = ratchet_pair();
    let (_, mut mallory) = ratchet_pair(); // different X3DH session, different root
    let msg = alice.encrypt_message(b"secret").unwrap();
    assert!(mallory.decrypt_message(&msg).is_err());
}

#[test]
fn ratchet_state_survives_serialization() {
    let (mut alice, mut bob) = ratchet_pair();
    let msg1 = alice.encrypt_message(b"before persist").unwrap();
    bob.decrypt_message(&msg1).unwrap();

    // Simulate a node restart: persist and reload both sessions.
    let alice_bytes = bincode::serialize(&alice).unwrap();
    let bob_bytes = bincode::serialize(&bob).unwrap();
    let mut alice: RatchetState = bincode::deserialize(&alice_bytes).unwrap();
    let mut bob: RatchetState = bincode::deserialize(&bob_bytes).unwrap();

    let msg2 = alice.encrypt_message(b"after persist").unwrap();
    assert_eq!(bob.decrypt_message(&msg2).unwrap(), b"after persist");
}

// ─── Epoch keys ────────────────────────────────────────────────────────────

#[test]
fn epoch_rotation_advances_epoch_and_changes_key() {
    let mut mgr = EpochManager::new();
    assert_eq!(mgr.current_epoch(), 1);
    let key1 = *mgr.current_key();

    let key2 = mgr.rotate();
    assert_eq!(mgr.current_epoch(), 2);
    assert_ne!(key1, key2);
    assert_eq!(*mgr.current_key(), key2);
    assert_eq!(mgr.key_count(), 2);
}

#[test]
fn epoch_key_distribution_round_trip() {
    let mgr = EpochManager::new();
    let subscriber_key: [u8; 32] = rand::random();

    let wrapped = mgr.encrypt_for_subscriber(&subscriber_key, 1).unwrap();
    let (epoch_key, epoch) = EpochManager::decrypt_epoch_key(&subscriber_key, &wrapped).unwrap();
    assert_eq!(epoch, 1);
    assert_eq!(epoch_key, *mgr.current_key());
}

#[test]
fn epoch_key_wrapped_for_someone_else_is_unreadable() {
    let mgr = EpochManager::new();
    let subscriber_key: [u8; 32] = rand::random();
    let eve_key: [u8; 32] = rand::random();

    let wrapped = mgr.encrypt_for_subscriber(&subscriber_key, 1).unwrap();
    assert!(EpochManager::decrypt_epoch_key(&eve_key, &wrapped).is_err());
}

#[test]
fn epoch_unknown_epoch_is_an_error() {
    let mgr = EpochManager::new();
    let subscriber_key: [u8; 32] = rand::random();
    assert!(mgr.encrypt_for_subscriber(&subscriber_key, 99).is_err());
}

#[test]
fn epoch_malformed_wrapped_key_is_an_error() {
    let my_key: [u8; 32] = rand::random();
    assert!(EpochManager::decrypt_epoch_key(&my_key, &[0u8; 8]).is_err());
}

#[test]
fn epoch_ban_list_tracks_users() {
    let mut mgr = EpochManager::new();
    let banned_user: [u8; 32] = rand::random();
    let good_user: [u8; 32] = rand::random();

    mgr.ban_user(&banned_user);
    assert!(mgr.is_banned(&banned_user));
    assert!(!mgr.is_banned(&good_user));
}

/// The whole point of epoch rotation: after a rotation, content encrypted
/// under the new epoch is static to anyone still holding the old key.
#[test]
fn epoch_rotation_locks_out_old_key_holders() {
    let mut mgr = EpochManager::new();
    let old_key = *mgr.current_key();
    let new_key = mgr.rotate();

    let block_id = [7u8; 32];
    let frame = Body::new_encrypted(block_id, b"video frame after ban", &new_key).unwrap();

    assert!(frame.decrypt(&old_key).is_err(), "old epoch key must fail");
    assert_eq!(frame.decrypt(&new_key).unwrap(), b"video frame after ban");
}
