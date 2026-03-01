#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! # TSC Crypto
//! The Identity Domain (Root of Trust) for the Standalone Complex.

pub mod bip39;
pub mod keri;
pub mod vault;

/// The core Identity type representing a TSC Persona.
pub struct Persona {
    /// Cryptographic identifier: BLAKE3 hash of the Inception Event.
    pub ghost_id: String,
    /// The current Ed25519 signing key.
    pub active_key: ed25519_dalek::SigningKey,
    /// The BLAKE3 hash commitment to the *next* key.
    pub next_key_commitment: [u8; 32],
    /// The Identifier Event Log (IEL).
    pub event_log: Vec<crate::keri::KeyEvent>,
}

impl Persona {
    /// Initializes a Persona with a KERI Inception Event.
    pub fn new_with_history(active_key: ed25519_dalek::SigningKey, next_key_commitment: [u8; 32]) -> Self {
        let inception = crate::keri::InceptionEvent::new(&active_key, next_key_commitment);
        // Calculate the GhostID from the Inception Event hash
        let ghost_id = inception.calculate_digest().to_hex().to_string();
        
        Self {
            ghost_id,
            active_key,
            next_key_commitment,
            event_log: vec![crate::keri::KeyEvent::Inception(inception)],
        }
    }
}