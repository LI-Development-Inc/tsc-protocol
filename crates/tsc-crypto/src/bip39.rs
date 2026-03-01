//! BIP-39 mnemonic generation and SLIP-0010 key derivation.
//!
//! # Key hierarchy
//!
//! ```text
//! 24-word mnemonic
//!     └─► 512-byte master seed  (BIP-39 PBKDF2)
//!             └─► SLIP-0010 master node  (HMAC-SHA512)
//!                     ├─► K1  m/44'/7777'/0'/0'/0'  (active signing key)
//!                     └─► K2  m/44'/7777'/0'/0'/1'  (pre-rotation key)
//! ```
//!
//! # Zeroization note
//!
//! `ed25519-dalek 2.x` `SigningKey` implements `Zeroize` internally (via its
//! own `Drop`) but does **not** implement `DefaultIsZeroes`, so it cannot be
//! wrapped in `Zeroizing<SigningKey>`.  We therefore keep the raw 32-byte
//! scalar in `Zeroizing<[u8; 32]>` until the last possible moment and
//! construct the `SigningKey` only at the call site.  The scalar bytes are
//! zeroed when the `Zeroizing` wrapper is dropped; the `SigningKey` itself
//! zeroes on its own `Drop`.

use bip39::{Language, Mnemonic};
use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

use crate::CryptoError;

// ── SLIP-0010 constants ────────────────────────────────────────────────────

const SLIP10_ED25519_KEY: &[u8] = b"ed25519 seed";
const TSC_COIN_TYPE: u32 = 7777;
const HARDENED: u32 = 0x8000_0000;

// ── Public API ─────────────────────────────────────────────────────────────

/// Generates a fresh 24-word BIP-39 mnemonic and the 512-byte master seed.
///
/// Returns `(phrase, master_seed)`. The seed bytes are zeroed on drop.
pub fn generate_sovereign_entropy() -> (String, Zeroizing<Vec<u8>>) {
    let mnemonic = Mnemonic::generate_in(Language::English, 24)
        .expect("OS entropy unavailable — cannot generate mnemonic");
    let phrase = mnemonic.to_string();
    let seed = Zeroizing::new(mnemonic.to_seed("").to_vec());
    (phrase, seed)
}

/// Restores the 512-byte master seed from a BIP-39 mnemonic phrase.
///
/// Returns `Err` if the phrase is not valid BIP-39.
pub fn restore_from_phrase(phrase: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let mnemonic = Mnemonic::parse_in(Language::English, phrase)
        .map_err(|e| CryptoError::InvalidMnemonic(e.to_string()))?;
    Ok(Zeroizing::new(mnemonic.to_seed("").to_vec()))
}

/// Derives the active signing key K1 (`m/44'/7777'/0'/0'/0'`).
///
/// `SigningKey` zeroes its own memory on `Drop` (ed25519-dalek 2.x).
pub fn derive_active_key(master_seed: &[u8]) -> Result<SigningKey, CryptoError> {
    let scalar = slip10_derive(master_seed, &[
        44            | HARDENED,
        TSC_COIN_TYPE | HARDENED,
        0             | HARDENED,
        0             | HARDENED,
        0             | HARDENED,
    ])?;
    // scalar is Zeroizing<[u8; 32]> — zeroed when this scope ends
    Ok(SigningKey::from_bytes(&scalar))
}

/// Derives the pre-rotation key K2 (`m/44'/7777'/0'/0'/1'`).
///
/// Prefer [`prerotation_commitment`] when you only need the hash — it
/// zeroizes the K2 scalar immediately after hashing, without exposing the
/// `SigningKey` to the caller.
pub fn derive_prerotation_key(master_seed: &[u8]) -> Result<SigningKey, CryptoError> {
    let scalar = slip10_derive(master_seed, &[
        44            | HARDENED,
        TSC_COIN_TYPE | HARDENED,
        0             | HARDENED,
        0             | HARDENED,
        1             | HARDENED,
    ])?;
    Ok(SigningKey::from_bytes(&scalar))
}

/// Computes `BLAKE3(K2.verifying_key_bytes)` — the pre-rotation commitment
/// stored in the `n` field of the KERI Inception Event.
///
/// The K2 scalar (in `Zeroizing<[u8; 32]>`) is zeroed as soon as the hash
/// is computed; the `SigningKey` object is dropped immediately after.
pub fn prerotation_commitment(master_seed: &[u8]) -> Result<[u8; 32], CryptoError> {
    // scalar is zeroed when the block ends
    let scalar = slip10_derive(master_seed, &[
        44            | HARDENED,
        TSC_COIN_TYPE | HARDENED,
        0             | HARDENED,
        0             | HARDENED,
        1             | HARDENED,
    ])?;
    let k2 = SigningKey::from_bytes(&scalar);
    // scalar is dropped (and zeroed) here; k2's pubkey bytes are on the stack
    let pubkey_bytes = k2.verifying_key().to_bytes();
    // k2 is dropped (and zeroed via its own Drop impl) here
    Ok(*blake3::hash(&pubkey_bytes).as_bytes())
}

// ── SLIP-0010 internals ────────────────────────────────────────────────────

/// Derives a 32-byte Ed25519 private scalar following the SLIP-0010 path.
///
/// All `indices` MUST be hardened (>= `0x8000_0000`). Non-hardened
/// derivation is cryptographically invalid for Ed25519 and is rejected.
///
/// Returns `Zeroizing<[u8; 32]>` so the scalar is zeroed when dropped.
fn slip10_derive(master_seed: &[u8], indices: &[u32]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    // Step 1: master node = HMAC-SHA512("ed25519 seed", seed)
    let mut node: Zeroizing<[u8; 64]> = Zeroizing::new(hmac_sha512(SLIP10_ED25519_KEY, master_seed)?);

    // node[0..32] = private scalar (IL)
    // node[32..64] = chain code   (IR)
    for &index in indices {
        if index < HARDENED {
            return Err(CryptoError::KeyDerivation(
                "Non-hardened child derivation is not permitted for Ed25519".into(),
            ));
        }
        node = slip10_child(&node, index)?;
    }

    let mut scalar = Zeroizing::new([0u8; 32]);
    scalar.copy_from_slice(&node[..32]);
    // node is dropped and zeroed here
    Ok(scalar)
}

/// Computes one SLIP-0010 hardened child node.
///
/// ```text
/// HMAC-SHA512(key = chain_code, data = 0x00 || private_key || index_be)
/// ```
fn slip10_child(parent: &[u8; 64], index: u32) -> Result<Zeroizing<[u8; 64]>, CryptoError> {
    // data = 0x00 || IL[0..32] || index (big-endian u32) — 37 bytes total
    let mut data = Zeroizing::new([0u8; 37]);
    data[0] = 0x00;
    data[1..33].copy_from_slice(&parent[0..32]);   // private key
    data[33..37].copy_from_slice(&index.to_be_bytes());

    let chain_code = &parent[32..64];
    let result = hmac_sha512(chain_code, data.as_ref())?;
    // data is zeroed here
    Ok(Zeroizing::new(result))
}

/// Computes HMAC-SHA512(key, data) and returns the 64-byte result.
fn hmac_sha512(key: &[u8], data: &[u8]) -> Result<[u8; 64], CryptoError> {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;

    type HmacSha512 = Hmac<Sha512>;
    let mut mac = HmacSha512::new_from_slice(key)
        .map_err(|_| CryptoError::KeyDerivation("HMAC-SHA512: invalid key length".into()))?;
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    Ok(out)
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// All-`abandon` + `art` mnemonic: well-known BIP-39 test vector.
    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn restore_from_phrase_succeeds() {
        restore_from_phrase(TEST_MNEMONIC).expect("valid mnemonic must parse");
    }

    #[test]
    fn restore_from_phrase_rejects_invalid() {
        assert!(restore_from_phrase("not a valid mnemonic phrase at all bla bla").is_err());
    }

    #[test]
    fn active_key_is_deterministic() {
        let seed = restore_from_phrase(TEST_MNEMONIC).unwrap();
        let k1a = derive_active_key(&seed).unwrap();
        let k1b = derive_active_key(&seed).unwrap();
        assert_eq!(k1a.to_bytes(), k1b.to_bytes(), "same seed → same key");
    }

    #[test]
    fn active_and_prerotation_keys_differ() {
        let seed = restore_from_phrase(TEST_MNEMONIC).unwrap();
        let k1 = derive_active_key(&seed).unwrap();
        let k2 = derive_prerotation_key(&seed).unwrap();
        assert_ne!(k1.to_bytes(), k2.to_bytes(), "K1 and K2 must be distinct");
    }

    #[test]
    fn prerotation_commitment_is_nonzero() {
        let seed = restore_from_phrase(TEST_MNEMONIC).unwrap();
        let c = prerotation_commitment(&seed).unwrap();
        assert_ne!(c, [0u8; 32], "commitment must not be all-zero");
    }

    #[test]
    fn prerotation_commitment_is_deterministic() {
        let seed = restore_from_phrase(TEST_MNEMONIC).unwrap();
        let c1 = prerotation_commitment(&seed).unwrap();
        let c2 = prerotation_commitment(&seed).unwrap();
        assert_eq!(c1, c2);
    }
}
