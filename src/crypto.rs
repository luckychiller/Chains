use ed25519_dalek::{Signature, SigningKey, VerifyingKey, Signer, Verifier};
use rand::random;

pub fn generate_signing_key() -> SigningKey {
    let secret: [u8; 32] = random();
    SigningKey::from_bytes(&secret)
}

pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    blake3::hash(data).into()
}

pub fn sign(secret: &SigningKey, data: &[u8]) -> [u8; 64] {
    secret.sign(data).to_bytes()
}

pub fn verify(public: &[u8; 32], data: &[u8], sig: &[u8; 64]) -> Result<(), String> {
    let key = VerifyingKey::from_bytes(public).map_err(|e| e.to_string())?;
    let signature = Signature::from_bytes(sig);
    key.verify(data, &signature).map_err(|e| e.to_string())
}
