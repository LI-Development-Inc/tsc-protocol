#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! # tsc-crypto — Identity Domain (Root of Trust)
//!
//! No network access. No unsafe code. Every other TSC crate depends on this.
//!
//! ## Modules
//! - [`bip39`]  — BIP-39 mnemonic generation and SLIP-0010 key derivation
//! - [`keri`]   — KERI-lite event chain and verification engine
//! - [`vault`]  — Argon2id + ChaCha20-Poly1305 encrypted mnemonic vault
//! - [`iel`]    — Identifier Event Log persistence (append-only JSONL)

pub mod bip39;
pub mod iel;
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
///
/// # Rotation counter
///
/// `rotation` tracks how many key rotations have occurred.  At inception it
/// is `0`.  After the first `rotate()` it is `1`, and so on.  The active
/// SLIP-0010 derivation index is always `rotation`; the pre-rotation index
/// is `rotation + 1`.
///
/// # Zeroization
///
/// Manual `Drop`: `next_key_commitment` is zeroized explicitly; `active_key`
/// zeroes itself via `SigningKey`'s own `Drop`.
pub struct Persona {
    /// Permanent GhostID (BLAKE3 of InceptionEvent, hex). Stable forever.
    pub ghost_id: String,

    /// Current active signing key (K_N). Zeroed by `SigningKey::drop()`.
    pub active_key: SigningKey,

    /// Pre-rotation commitment `BLAKE3(K_(N+1).pub)`. Zeroed in `drop()`.
    pub next_key_commitment: [u8; 32],

    /// Number of rotations performed (0 = just after inception).
    pub rotation: u32,

    /// Ordered Identifier Event Log. Contains public data only.
    pub event_log: Vec<keri::KeyEvent>,
}

impl Drop for Persona {
    fn drop(&mut self) {
        self.next_key_commitment.zeroize();
    }
}

impl Persona {
    /// Derives a `Persona` from a BIP-39 master seed (the only valid constructor).
    pub fn from_seed(master_seed: &[u8]) -> Result<Self, CryptoError> {
        let active_key = bip39::derive_active_key(master_seed)?;
        let commitment = bip39::prerotation_commitment(master_seed)?;
        let inception  = keri::InceptionEvent::new(&active_key, commitment)?;
        let ghost_id   = hex::encode(inception.calculate_digest()?);

        Ok(Self {
            ghost_id,
            active_key,
            next_key_commitment: commitment,
            rotation: 0,
            event_log: vec![keri::KeyEvent::Inception(inception)],
        })
    }

    /// Performs one key rotation in-place.
    ///
    /// Derives the new active key (K_(N+1)) and the next pre-rotation key
    /// (K_(N+2)) from `master_seed`.  Builds and dual-signs a `RotationEvent`,
    /// appends it to the in-memory IEL, and updates `active_key`,
    /// `next_key_commitment`, and `rotation`.
    ///
    /// The caller is responsible for persisting the IEL after this returns.
    pub fn rotate(&mut self, master_seed: &[u8]) -> Result<&keri::RotationEvent, CryptoError> {
        let next_rotation = self.rotation + 1;

        // Derive the new active key (former pre-rotation key, index N+1)
        let new_active = bip39::derive_key_at_index(master_seed, next_rotation)?;

        // Derive the new pre-rotation key (index N+2) and compute its commitment
        let new_prerot_commitment = bip39::commitment_at_index(master_seed, next_rotation + 1)?;

        // Hash of the last event in the log
        let prev_event  = self.event_log.last()
            .ok_or_else(|| CryptoError::InvalidEventLog("Empty event log".into()))?;
        let prev_digest = prev_event.digest()?;
        let seq         = prev_event.seq() + 1;

        let deriv_path = format!("m/44'/7777'/0'/0/{}'", next_rotation);

        let rot = keri::RotationEvent::new(
            &self.active_key,
            &new_active,
            new_prerot_commitment,
            prev_digest,
            seq,
            &self.ghost_id,
            &deriv_path,
        )?;

        // Commit the rotation
        self.event_log.push(keri::KeyEvent::Rotation(rot));
        self.active_key         = new_active;
        self.next_key_commitment = new_prerot_commitment;
        self.rotation           = next_rotation;

        // Return reference to the rotation event we just appended
        match self.event_log.last() {
            Some(keri::KeyEvent::Rotation(r)) => Ok(r),
            _ => unreachable!(),
        }
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
        assert_eq!(p1.ghost_id, p2.ghost_id);
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

    #[test]
    fn persona_rotate_updates_fields() {
        let seed       = bip39::restore_from_phrase(TEST_MNEMONIC).unwrap();
        let mut p      = Persona::from_seed(&seed).unwrap();
        let ghost_before = p.ghost_id.clone();
        let key_before   = p.active_key.verifying_key().to_bytes();

        p.rotate(&seed).unwrap();

        // GhostID must NOT change
        assert_eq!(p.ghost_id, ghost_before, "GhostID must be stable across rotation");
        // Active key MUST change
        assert_ne!(p.active_key.verifying_key().to_bytes(), key_before);
        // Rotation counter incremented
        assert_eq!(p.rotation, 1);
        // IEL now has 2 events
        assert_eq!(p.event_log.len(), 2);
    }

    #[test]
    fn persona_rotate_log_verifies() {
        let seed  = bip39::restore_from_phrase(TEST_MNEMONIC).unwrap();
        let mut p = Persona::from_seed(&seed).unwrap();
        p.rotate(&seed).unwrap();
        // The full IEL must verify cleanly
        keri::verify_event_log(&p.event_log).expect("rotated IEL must verify");
    }

    #[test]
    fn persona_double_rotate_verifies() {
        let seed  = bip39::restore_from_phrase(TEST_MNEMONIC).unwrap();
        let mut p = Persona::from_seed(&seed).unwrap();
        p.rotate(&seed).unwrap();
        p.rotate(&seed).unwrap();
        assert_eq!(p.rotation, 2);
        keri::verify_event_log(&p.event_log).expect("double-rotated IEL must verify");
    }
}
