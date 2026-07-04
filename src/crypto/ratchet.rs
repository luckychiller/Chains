use crate::models::ChainsResult;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

type HmacSha256 = Hmac<Sha256>;

const HMAC_KEY_DERIVE: &[u8] = b"chains-ratchet-derive";
const HMAC_KEY_MESSAGE: &[u8] = b"chains-ratchet-msg";
const HMAC_KEY_NEXT_CHAIN: &[u8] = b"chains-ratchet-next";

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC key length ok");
    mac.update(data);
    let result = mac.finalize();
    let code = result.into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&code);
    out
}

fn hkdf_derive(input_key: &[u8; 32], salt: &[u8]) -> ([u8; 32], [u8; 32]) {
    let prk = hmac_sha256(salt, input_key);
    let t1 = hmac_sha256(&prk, &[0x01]);
    let mut t2_input = Vec::with_capacity(33);
    t2_input.extend_from_slice(&t1);
    t2_input.push(0x02);
    let t2 = hmac_sha256(&prk, &t2_input);
    (t1, t2)
}

pub fn x3dh_shared_secret(
    our_identity: &StaticSecret,
    our_ephemeral: &StaticSecret,
    their_identity: &PublicKey,
    their_signed_prekey: &PublicKey,
) -> [u8; 32] {
    let dh1 = our_identity.diffie_hellman(their_signed_prekey);
    let dh2 = our_ephemeral.diffie_hellman(their_identity);
    let dh3 = our_ephemeral.diffie_hellman(their_signed_prekey);

    let mut input = Vec::with_capacity(96);
    input.extend_from_slice(dh1.as_bytes());
    input.extend_from_slice(dh2.as_bytes());
    input.extend_from_slice(dh3.as_bytes());

    blake3::hash(&input).into()
}

pub fn x3dh_receive(
    our_identity: &StaticSecret,
    our_signed_prekey: &StaticSecret,
    their_identity: &PublicKey,
    their_ephemeral: &PublicKey,
) -> [u8; 32] {
    let dh1 = our_signed_prekey.diffie_hellman(their_identity);
    let dh2 = our_identity.diffie_hellman(their_ephemeral);
    let dh3 = our_signed_prekey.diffie_hellman(their_ephemeral);

    let mut input = Vec::with_capacity(96);
    input.extend_from_slice(dh1.as_bytes());
    input.extend_from_slice(dh2.as_bytes());
    input.extend_from_slice(dh3.as_bytes());

    blake3::hash(&input).into()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CipherMessage {
    pub dh_public_key: [u8; 32],
    pub message_number: u32,
    pub previous_message_number: u32,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RatchetState {
    pub root_key: [u8; 32],
    pub send_chain_key: Option<[u8; 32]>,
    pub recv_chain_key: Option<[u8; 32]>,
    pub dh_private: [u8; 32],
    pub dh_public: [u8; 32],
    pub dh_remote: Option<[u8; 32]>,
    pub dh_remote_prev: Option<[u8; 32]>,
    pub message_count_send: u32,
    pub message_count_recv: u32,
    pub skipped_message_keys: Vec<(u32, [u8; 32])>,
}

impl RatchetState {
    pub fn new_sender(root_key: [u8; 32], dh_private: [u8; 32], dh_public: [u8; 32]) -> Self {
        RatchetState {
            root_key,
            send_chain_key: None,
            recv_chain_key: None,
            dh_private,
            dh_public,
            dh_remote: None,
            dh_remote_prev: None,
            message_count_send: 0,
            message_count_recv: 0,
            skipped_message_keys: Vec::new(),
        }
    }

    pub fn new_receiver(
        root_key: [u8; 32],
        dh_private: [u8; 32],
        dh_public: [u8; 32],
        dh_remote: [u8; 32],
    ) -> Self {
        RatchetState {
            root_key,
            send_chain_key: None,
            recv_chain_key: None,
            dh_private,
            dh_public,
            dh_remote: Some(dh_remote),
            dh_remote_prev: None,
            message_count_send: 0,
            message_count_recv: 0,
            skipped_message_keys: Vec::new(),
        }
    }

    pub fn encrypt_message(&mut self, plaintext: &[u8]) -> ChainsResult<CipherMessage> {
        let dh_public_bytes = self.dh_public;

        if self.send_chain_key.is_none() {
            if let Some(remote_bytes) = self.dh_remote {
                let sk = StaticSecret::from(self.dh_private);
                let remote = PublicKey::from(remote_bytes);
                let shared = sk.diffie_hellman(&remote);
                let (new_root, new_chain) = hkdf_derive(&self.root_key, shared.as_bytes());
                self.root_key = new_root;
                self.send_chain_key = Some(new_chain);
            } else {
                let new_key = hkdf_derive(&self.root_key, HMAC_KEY_DERIVE);
                self.root_key = new_key.0;
                self.send_chain_key = Some(new_key.1);
            }
        }

        let chain_key = self.send_chain_key.unwrap();
        let msg_key = hmac_sha256(&chain_key, HMAC_KEY_MESSAGE);
        let next_chain_key = hmac_sha256(&chain_key, HMAC_KEY_NEXT_CHAIN);
        self.send_chain_key = Some(next_chain_key);

        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let cipher = XChaCha20Poly1305::new_from_slice(&msg_key).expect("valid key");
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| format!("Ratchet encrypt failed: {}", e))?;

        let mut nonce_bytes = [0u8; 24];
        nonce_bytes.copy_from_slice(nonce.as_slice());

        let msg = CipherMessage {
            dh_public_key: dh_public_bytes,
            message_number: self.message_count_send,
            previous_message_number: self.message_count_recv,
            nonce: nonce_bytes,
            ciphertext,
        };

        self.message_count_send += 1;
        Ok(msg)
    }

    pub fn decrypt_message(&mut self, msg: &CipherMessage) -> ChainsResult<Vec<u8>> {
        self.try_skipped_message_keys(msg)?;

        let remote_pk = PublicKey::from(msg.dh_public_key);
        let needs_dh_ratchet = self.dh_remote != Some(msg.dh_public_key);

        if needs_dh_ratchet {
            self.dh_remote_prev = self.dh_remote.take();
            self.dh_remote = Some(msg.dh_public_key);

            if let Some(prev_remote) = &self.dh_remote_prev {
                if *prev_remote == msg.dh_public_key {
                    self.dh_remote_prev = None;
                }
            }

            let sk = StaticSecret::from(self.dh_private);
            let shared = sk.diffie_hellman(&remote_pk);
            let (new_root, new_recv_chain) = hkdf_derive(&self.root_key, shared.as_bytes());
            self.root_key = new_root;
            self.recv_chain_key = Some(new_recv_chain);

            let new_sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
            let new_pk = PublicKey::from(&new_sk);
            self.dh_private = new_sk.to_bytes();
            self.dh_public = new_pk.to_bytes();

            // A DH ratchet step replaces BOTH chains. Invalidate the send
            // chain so the next encrypt derives a fresh one from the new
            // keypair; keeping the old chain here desyncs the conversation
            // after the second round-trip.
            self.send_chain_key = None;
        }

        let chain_key = self
            .recv_chain_key
            .ok_or_else(|| "No receiving chain key available".to_string())?;

        let msg_key = hmac_sha256(&chain_key, HMAC_KEY_MESSAGE);
        let next_chain_key = hmac_sha256(&chain_key, HMAC_KEY_NEXT_CHAIN);
        self.recv_chain_key = Some(next_chain_key);

        let nonce = XNonce::from_slice(&msg.nonce);
        let cipher = XChaCha20Poly1305::new_from_slice(&msg_key).expect("valid key");
        let plaintext = cipher
            .decrypt(nonce, msg.ciphertext.as_slice())
            .map_err(|e| format!("Ratchet decrypt failed: {}", e))?;

        Ok(plaintext)
    }

    fn try_skipped_message_keys(&mut self, msg: &CipherMessage) -> ChainsResult<()> {
        let pos = self
            .skipped_message_keys
            .iter()
            .position(|(n, _)| *n == msg.message_number);
        if let Some(idx) = pos {
            let (_, _) = self.skipped_message_keys.swap_remove(idx);
        }
        Ok(())
    }
}

pub fn generate_dh_keypair() -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = PublicKey::from(&secret);
    (secret.to_bytes(), public.to_bytes())
}

pub fn generate_signed_prekey() -> ([u8; 32], [u8; 32]) {
    generate_dh_keypair()
}
