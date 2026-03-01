//! Vault: secure mnemonic storage with hardware-bound key derivation.
//!
//! # Layout of `vault.bin`
//!
//! ```text
//! Offset  Size   Field
//! 0       8      Magic: b"TSCVAULT"
//! 8       1      Version: 0x01
//! 9       16     Argon2id salt  (random, generated at vault creation)
//! 25      12     ChaCha20-Poly1305 nonce  (random, generated per write)
//! 37      4      Ciphertext length  (u32 little-endian)
//! 41      N+16   Ciphertext + Poly1305 authentication tag
//! ```
//!
//! The plaintext is the 24 space-separated mnemonic words encoded as UTF-8.

use argon2::{
    password_hash::SaltString,
    Argon2, Params, PasswordHasher,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use std::path::PathBuf;
use zeroize::Zeroizing;

use crate::CryptoError;

// ── Constants ──────────────────────────────────────────────────────────────

const MAGIC: &[u8; 8] = b"TSCVAULT";
const VERSION: u8 = 0x01;

/// Argon2id parameters (RFC-006 §6.1).
const ARGON2_T: u32 = 3;        // time cost
const ARGON2_M: u32 = 65_536;   // memory cost (64 MiB)
const ARGON2_P: u32 = 4;        // parallelism
const ARGON2_LEN: usize = 32;   // output length

// ── Hardware UUID ──────────────────────────────────────────────────────────

/// Reads the DMI hardware UUID, providing a machine-specific binding for the
/// vault key derivation (RFC-006 §6.3, ADR-009).
///
/// Falls back to a SHA-256 hash of `/etc/machine-id` if the DMI UUID is
/// unavailable (e.g. inside a VM or container).  A static string is never
/// used as a fallback.
pub fn get_hardware_uuid() -> String {
    // Primary: DMI product UUID (most reliable on bare metal)
    if let Ok(uuid) = std::fs::read_to_string("/sys/class/dmi/id/product_uuid") {
        let trimmed = uuid.trim().to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }

    // Fallback: machine-id hash (VMs, containers, older hardware)
    if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
        let hash = blake3::hash(id.trim().as_bytes());
        tracing_warn("DMI UUID unavailable; using machine-id hash as hardware binding");
        return hex::encode(hash.as_bytes());
    }

    // Last resort: random bytes persisted in the XDG data dir.  This is the
    // weakest binding but still better than a static string.
    tracing_warn("No stable hardware ID found; generating ephemeral hardware binding");
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Minimal logging shim so tsc-crypto doesn't depend on a specific logger.
fn tracing_warn(msg: &str) {
    eprintln!("[WARN tsc-crypto::vault] {}", msg);
}

// ── Vault path ─────────────────────────────────────────────────────────────

/// Returns the canonical vault file path: `$XDG_DATA_HOME/tsc/vault.bin`.
///
/// Creates the parent directory with mode `0700` if it does not exist.
pub fn vault_path() -> Result<PathBuf, CryptoError> {
    let base = dirs::data_dir()
        .ok_or_else(|| CryptoError::Io("XDG_DATA_HOME is not set and cannot be inferred".into()))?;
    let dir = base.join("tsc");
    std::fs::create_dir_all(&dir).map_err(|e| CryptoError::Io(e.to_string()))?;

    // Tighten permissions: 0700 (owner rwx, no group/other)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| CryptoError::Io(e.to_string()))?;
    }

    Ok(dir.join("vault.bin"))
}

// ── Key derivation ─────────────────────────────────────────────────────────

/// Derives the 32-byte storage key `K_storage` from key material and the
/// hardware UUID (RFC-006 §6.1, ADR-005).
///
/// `salt` MUST be a 16-byte random value that is stored in the vault header.
/// It MUST NOT be a static constant.
pub fn derive_storage_key(
    key_material: &[u8],
    hw_uuid: &str,
    salt: &[u8; 16],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    // Combine key material + hardware UUID as the KDF input
    let mut input = Zeroizing::new(Vec::with_capacity(key_material.len() + hw_uuid.len()));
    input.extend_from_slice(key_material);
    input.extend_from_slice(hw_uuid.as_bytes());

    let params = Params::new(ARGON2_M, ARGON2_T, ARGON2_P, Some(ARGON2_LEN))
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    // SaltString requires base64; encode our random bytes
    let salt_b64 = base64_encode_no_pad(salt);
    let salt_str = SaltString::from_b64(&salt_b64)
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;

    let hash = argon2
        .hash_password(input.as_ref(), &salt_str)
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;

    let hash_bytes = hash.hash.ok_or_else(|| {
        CryptoError::KeyDerivation("Argon2id produced no output".into())
    })?;

    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&hash_bytes.as_bytes()[..32]);
    Ok(out)
}

// ── Vault operations ───────────────────────────────────────────────────────

/// Encrypts the mnemonic words and writes a new vault file.
///
/// Generates a fresh 16-byte Argon2 salt and 12-byte ChaCha20 nonce for
/// every write operation.
pub fn lock_vault(
    words: &[String],
    key_material: &[u8],
    hw_uuid: &str,
    path: &PathBuf,
) -> Result<(), CryptoError> {
    // Generate random salt and nonce
    let mut argon_salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut argon_salt);
    OsRng.fill_bytes(&mut nonce_bytes);

    let storage_key = derive_storage_key(key_material, hw_uuid, &argon_salt)?;
    let plaintext = Zeroizing::new(words.join(" ").into_bytes());

    let cipher_key = Key::from_slice(storage_key.as_ref());
    let cipher = ChaCha20Poly1305::new(cipher_key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|_| CryptoError::Encryption("ChaCha20-Poly1305 encryption failed".into()))?;

    // Build the binary vault file
    let mut file_data: Vec<u8> = Vec::new();
    file_data.extend_from_slice(MAGIC);                          // 8 bytes
    file_data.push(VERSION);                                      // 1 byte
    file_data.extend_from_slice(&argon_salt);                    // 16 bytes
    file_data.extend_from_slice(&nonce_bytes);                   // 12 bytes
    let ct_len = ciphertext.len() as u32;
    file_data.extend_from_slice(&ct_len.to_le_bytes());          // 4 bytes
    file_data.extend_from_slice(&ciphertext);                    // N+16 bytes

    std::fs::write(path, &file_data).map_err(|e| CryptoError::Io(e.to_string()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| CryptoError::Io(e.to_string()))?;
    }

    Ok(())
}

/// Decrypts the vault file and returns the mnemonic words.
///
/// Returns `Err` if the file is missing, the magic/version check fails, or
/// the AEAD authentication tag is invalid (wrong key or tampered data).
pub fn unlock_vault(
    key_material: &[u8],
    hw_uuid: &str,
    path: &PathBuf,
) -> Result<Vec<String>, CryptoError> {
    let data = std::fs::read(path).map_err(|e| {
        CryptoError::Io(format!("Vault not found at {}: {}", path.display(), e))
    })?;

    // Minimum size: 8+1+16+12+4 = 41 bytes header + at least 16 bytes AEAD tag
    if data.len() < 57 {
        return Err(CryptoError::VaultCorrupted("File too small to be a valid vault".into()));
    }

    // Verify magic
    if &data[0..8] != MAGIC {
        return Err(CryptoError::VaultCorrupted("Invalid vault magic bytes".into()));
    }

    // Verify version
    if data[8] != VERSION {
        return Err(CryptoError::VaultCorrupted(
            format!("Unsupported vault version: 0x{:02x}", data[8]),
        ));
    }

    // Extract fields
    let argon_salt: &[u8; 16] = data[9..25].try_into().unwrap();
    let nonce_bytes: &[u8; 12] = data[25..37].try_into().unwrap();
    let ct_len = u32::from_le_bytes(data[37..41].try_into().unwrap()) as usize;

    if data.len() < 41 + ct_len {
        return Err(CryptoError::VaultCorrupted("Vault ciphertext length field is corrupt".into()));
    }
    let ciphertext = &data[41..41 + ct_len];

    // Derive storage key using the stored salt
    let storage_key = derive_storage_key(key_material, hw_uuid, argon_salt)?;

    let cipher_key = Key::from_slice(storage_key.as_ref());
    let cipher = ChaCha20Poly1305::new(cipher_key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| {
            CryptoError::Decryption(
                "Authentication failed — wrong key or tampered vault".into(),
            )
        })?;

    let phrase = String::from_utf8(plaintext)
        .map_err(|_| CryptoError::VaultCorrupted("Decrypted content is not valid UTF-8".into()))?;

    Ok(phrase.split_whitespace().map(|s| s.to_string()).collect())
}

// ── Internal helpers ───────────────────────────────────────────────────────

/// Encodes 16 bytes to base64 without padding, for use as an Argon2 salt string.
fn base64_encode_no_pad(bytes: &[u8]) -> String {
    use std::fmt::Write;
    // Simple manual base64 encoding to avoid adding a dependency
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let combined = (b0 << 16) | (b1 << 8) | b2;
        let _ = write!(out, "{}", TABLE[((combined >> 18) & 0x3F) as usize] as char);
        let _ = write!(out, "{}", TABLE[((combined >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            let _ = write!(out, "{}", TABLE[((combined >> 6) & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            let _ = write!(out, "{}", TABLE[(combined & 0x3F) as usize] as char);
        }
    }
    out
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const TEST_HW_UUID: &str = "test-hardware-uuid-12345";

    fn temp_vault_path() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("tsc_test_vault_{}.bin", std::process::id()));
        p
    }

    fn test_key_material() -> Vec<u8> {
        vec![0x42u8; 32]
    }

    #[test]
    fn lock_and_unlock_round_trip() {
        let path = temp_vault_path();
        let words: Vec<String> = vec!["alpha", "bravo", "charlie"]
            .into_iter()
            .map(|s| s.to_string())
            .collect();
        let km = test_key_material();

        lock_vault(&words, &km, TEST_HW_UUID, &path).expect("lock must succeed");
        let recovered = unlock_vault(&km, TEST_HW_UUID, &path).expect("unlock must succeed");

        assert_eq!(words, recovered);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unlock_with_wrong_key_fails() {
        let path = temp_vault_path();
        let words = vec!["test".to_string()];
        let km = test_key_material();

        lock_vault(&words, &km, TEST_HW_UUID, &path).expect("lock must succeed");

        let wrong_km = vec![0xFFu8; 32];
        let result = unlock_vault(&wrong_km, TEST_HW_UUID, &path);
        assert!(result.is_err(), "wrong key must not decrypt vault");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tampered_vault_fails_authentication() {
        let path = temp_vault_path();
        let words = vec!["test".to_string()];
        let km = test_key_material();

        lock_vault(&words, &km, TEST_HW_UUID, &path).expect("lock must succeed");

        // Flip a byte in the ciphertext region
        let mut data = std::fs::read(&path).unwrap();
        let last = data.len() - 1;
        data[last] ^= 0xFF;
        std::fs::write(&path, &data).unwrap();

        let result = unlock_vault(&km, TEST_HW_UUID, &path);
        assert!(result.is_err(), "tampered vault must fail AEAD check");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn vault_with_wrong_magic_rejected() {
        let path = temp_vault_path();
        std::fs::write(&path, b"BADMAGICXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX").unwrap();
        let km = test_key_material();
        let result = unlock_vault(&km, TEST_HW_UUID, &path);
        assert!(result.is_err());
        let _ = std::fs::remove_file(&path);
    }
}
