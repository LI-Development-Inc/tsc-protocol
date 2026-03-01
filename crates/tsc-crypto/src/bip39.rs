//! BIP-39 Mnemonic and Seed derivation logic.

use bip39::{Mnemonic, Language};
use crate::Persona;
use ed25519_dalek::SigningKey;

/// Generates a new 24-word mnemonic and the resulting master seed.
pub fn generate_sovereign_entropy() -> (String, Vec<u8>) {
    let mnemonic = Mnemonic::generate_in(Language::English, 24).expect("Entropy failure");
    let phrase = mnemonic.to_string();
    let seed = mnemonic.to_seed(""); 
    (phrase, seed.to_vec())
}

/// Derives the Genesis Persona from the Master Seed bytes.
pub fn derive_genesis_persona(seed: &[u8]) -> Persona {
    let mut key_material = [0u8; 32];
    key_material.copy_from_slice(&seed[0..32]);
    
    let active_key = SigningKey::from_bytes(&key_material);
    let next_key_commitment = [0u8; 32]; 

    // FIX: Call the correct constructor
    Persona::new_with_history(active_key, next_key_commitment)
}