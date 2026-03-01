#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! # tsc-crypto — Identity Domain (Root of Trust)
//!
//! No network socket access. No unsafe code. Every other TSC crate depends
//! on this one.
//!
//! ## Modules
//! - [`bip39`]  — BIP-39 mnemonic generation + SLIP-0010 key derivation
//! - [`keri`]   — KERI-lite event chain and verification engine
//! - [`vault`]  — Argon2id + ChaCha20-Poly1305 encrypted mnemonic vault

pub mod bip39;
pub mod keri;
pub mod vault;

use ed25519_dalek::SigningKey;
use zeroize::Zeroize;

// ── Shared error type ──────────────────────────────────────────────────────

/// Every error that can be returned by `tsc-crypto` operations.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// A BIP-39 mnemonic phrase was invalid.
    #[error("CRYPTO:INVALID_MNEMONIC: {0}")]
    InvalidMnemonic(String),

    /// SLIP-0010 or Argon2id key derivation failed.
    #[error("CRYPTO:KEY_DERIVATION: {0}")]
    KeyDerivation(String),

    /// AEAD encryption failed.
    #[error("CRYPTO:ENCRYPTION: {0}")]
    Encryption(String),

    /// AEAD authentication / decryption failed.
    #[error("CRYPTO:DECRYPTION: {0}")]
    Decryption(String),

    /// Vault file is present but structurally invalid or tampered.
    #[error("CRYPTO:VAULT_CORRUPTED: {0}")]
    VaultCorrupted(String),

    /// A KERI event signature failed verification.
    #[error("CRYPTO:SIGNATURE_INVALID: {0}")]
    SignatureInvalid(String),

    /// The Identifier Event Log has a structural or logical error.
    #[error("CRYPTO:INVALID_EVENT_LOG: {0}")]
    InvalidEventLog(String),

    /// Serialization or deserialization error.
    #[error("CRYPTO:SERIALIZATION: {0}")]
    Serialization(String),

    /// Filesystem or I/O error.
    #[error("CRYPTO:IO: {0}")]
    Io(String),
}

// ── Persona ────────────────────────────────────────────────────────────────

/// The runtime identity of a TSC node.
///
/// Always derived from a BIP-39 mnemonic via SLIP-0010.
/// MUST NOT be constructed from raw random bytes.
///
/// # Zeroization
///
/// We cannot `#[derive(ZeroizeOnDrop)]` because:
/// - `SigningKey` uses its own `Drop`-based zeroization (not `DefaultIsZeroes`)
/// - `Vec<KeyEvent>` does not implement `Zeroize`
///
/// We instead implement `Drop` manually: the `active_key` scalar is zeroed
/// via `SigningKey`'s own `Drop`, and `next_key_commitment` is zeroed
/// explicitly. The `event_log` and `ghost_id` contain only public data, so
/// zeroing them is not a security requirement.
pub struct Persona {
    /// Permanent GhostID: hex-encoded BLAKE3 hash of the Inception Event.
    /// Stable across all key rotations.
    pub ghost_id: String,

    /// Current Ed25519 signing key (K1).
    /// Zeroed automatically by `SigningKey`'s own `Drop` implementation.
    pub active_key: SigningKey,

    /// Pre-rotation commitment: `BLAKE3(K2.verifying_key_bytes)`.
    /// Stored in the `n` field of every KERI event. Must not be all-zero.
    pub next_key_commitment: [u8; 32],

    /// Ordered Identifier Event Log (public data; not zeroed on drop).
    pub event_log: Vec<keri::KeyEvent>,
}

impl Drop for Persona {
    fn drop(&mut self) {
        // next_key_commitment is sensitive — zero it explicitly.
        // active_key is zeroed by SigningKey's own Drop.
        self.next_key_commitment.zeroize();
    }
}

impl Persona {
    /// Derives a `Persona` from a BIP-39 master seed (the only valid constructor).
    ///
    /// Uses SLIP-0010 to derive K1 and K2, computes the pre-rotation
    /// commitment (`BLAKE3(K2.pub)`), and creates the signed KERI
    /// Inception Event.
    pub fn from_seed(master_seed: &[u8]) -> Result<Self, CryptoError> {
        let active_key  = bip39::derive_active_key(master_seed)?;
        let commitment  = bip39::prerotation_commitment(master_seed)?;

        let inception = keri::InceptionEvent::new(&active_key, commitment)?;
        let ghost_id  = hex::encode(inception.calculate_digest()?);

        Ok(Self {
            ghost_id,
            active_key,
            next_key_commitment: commitment,
            event_log: vec![keri::KeyEvent::Inception(inception)],
        })
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn persona_from_seed_is_deterministic() {
        let seed = bip39::restore_from_phrase(TEST_MNEMONIC).unwrap();
        let p1 = Persona::from_seed(&seed).unwrap();
        let p2 = Persona::from_seed(&seed).unwrap();
        assert_eq!(p1.ghost_id, p2.ghost_id, "same seed must produce same GhostID");
    }

    #[test]
    fn persona_ghost_id_nonempty() {
        let seed = bip39::restore_from_phrase(TEST_MNEMONIC).unwrap();
        let p = Persona::from_seed(&seed).unwrap();
        assert!(!p.ghost_id.is_empty());
    }

    #[test]
    fn persona_commitment_nonzero() {
        let seed = bip39::restore_from_phrase(TEST_MNEMONIC).unwrap();
        let p = Persona::from_seed(&seed).unwrap();
        assert_ne!(p.next_key_commitment, [0u8; 32]);
    }
}
