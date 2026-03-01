//! Vault: Secure entropy generation and storage.
//!
//! This module provides functions for generating and managing cryptographic keys 
//! and mnemonics, as well as deriving storage keys ($K_s$) based on the user's 
//! Persona and hardware identifiers.
//!
//! The vault ensures that critical data is never exposed outside of this 
//! module's secure boundaries.

use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use crate::Persona;
use bip39::{Mnemonic, Language};
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, aead::Aead};
use rand::rngs::ThreadRng;
use rand::RngExt;
use std::fs::File;
use std::io::{Write, Read};

/// Probes the system for a unique hardware identifier.
/// 
/// On Linux, this attempts to read the DMI product_uuid. If unavailable, 
/// it returns a fallback identifier for development purposes.
pub fn get_hardware_uuid() -> String {
    std::fs::read_to_string("/sys/class/dmi/id/product_uuid")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "FALLBACK_STATIC_ID_DO_NOT_USE_IN_PROD".to_string())
}

/// Derives the $K_s$ (Storage Key) from the Persona and Hardware UUID.
///
/// Uses Argon2id to produce a 256-bit key suitable for AES-GCM encryption.
pub fn derive_storage_key(persona: &Persona, hw_uuid: &str) -> Vec<u8> {
    let salt = SaltString::from_b64("TSCVaultSaltV001").expect("Invalid Salt");
    let argon2 = Argon2::default();
    
    // Combine Ghost ID and Hardware UUID as the KDF input
    let input = format!("{}{}", persona.ghost_id, hw_uuid);
    
    let password_hash = argon2
        .hash_password(input.as_bytes(), &salt)
        .expect("KDF failure");

    password_hash.hash.expect("Hash output missing").as_bytes().to_vec()
}

/// Generates a new 24-word BIP-39 mnemonic.
///
/// Returns a result containing a vector of 24 English words.
pub fn generate_mnemonic() -> Result<Vec<String>, String> {
    let mnemonic = Mnemonic::generate_in(Language::English, 24)
        .map_err(|e| format!("Mnemonic generation failed: {}", e))?;
    
    let words: Vec<String> = mnemonic
        .words()
        .map(|word: &str| word.to_string())
        .collect();
        
    Ok(words)
}

/// Encrypts the mnemonic and saves it to a local vault file.
///
/// This method generates a random 96-bit nonce for every encryption event.
/// The nonce is prepended to the ciphertext in the output file.
/// Encrypts the mnemonic and saves it to a local vault file.
pub fn lock_vault(words: Vec<String>, storage_key: &[u8]) -> Result<(), String> {
    let phrase = words.join(" ");
    
    let key = Key::<Aes256Gcm>::from_slice(&storage_key[..32]);
    let cipher = Aes256Gcm::new(key);
    
    let mut nonce_bytes = [0u8; 12];
    
    // ThreadRng::default() is valid, and .fill() is now provided by RngExt
    let mut rng = ThreadRng::default();
    rng.fill(&mut nonce_bytes);
    
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, phrase.as_bytes())
        .map_err(|e| format!("Encryption failure: {}", e))?;

    let mut file = File::create("/tmp/tsc_vault.bin")
        .map_err(|e| format!("File creation failed: {}", e))?;
    
    // Header: Nonce (12 bytes) + Ciphertext
    file.write_all(&nonce_bytes).map_err(|e| e.to_string())?;
    file.write_all(&ciphertext).map_err(|e| e.to_string())?;

    Ok(())
}

/// Decrypts the vault using the provided storage key.
///
/// Reads the 12-byte nonce from the file header before attempting decryption.
pub fn unlock_vault(storage_key: &[u8]) -> Result<Vec<String>, String> {
    let mut file = File::open("/tmp/tsc_vault.bin")
        .map_err(|e| format!("Vault not found: {}", e))?;
    
    let mut data = Vec::new();
    file.read_to_end(&mut data).map_err(|e| e.to_string())?;

    if data.len() < 12 {
        return Err("Vault file corrupted: missing nonce header".into());
    }

    // Extract Nonce (first 12 bytes) and Ciphertext (remaining)
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let key = Key::<Aes256Gcm>::from_slice(&storage_key[..32]);
    let cipher = Aes256Gcm::new(key);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failure (Unauthorized Access?): {}", e))?;

    let phrase = String::from_utf8(plaintext).map_err(|e| e.to_string())?;
    Ok(phrase.split_whitespace().map(|s| s.to_string()).collect())
}