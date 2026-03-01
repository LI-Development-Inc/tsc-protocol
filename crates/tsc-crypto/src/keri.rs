//! KERI-lite state machine for verifiable key succession (RFC-002).
//!
//! # Event chain
//!
//! ```text
//! IXN (s=0) ──signed-by-K1──► ROT (s=1) ──signed-by-K1+K2──► ROT (s=2) ──► …
//! ```
//!
//! The GhostID is the BLAKE3 hash of the Inception Event and never changes,
//! even through key rotations.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::CryptoError;

// ── Inception Event ────────────────────────────────────────────────────────

/// The genesis event that anchors a GhostID to the network (RFC-002 §2.3).
///
/// `d` and `i` are self-referential: computed with `d=""`, then inserted.
/// `sig` is an Ed25519 signature by K1 over the event with `sig=""`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InceptionEvent {
    /// Protocol version. Always `"TSC2.0"`.
    pub v: String,
    /// Event type tag. Always `"ixn"`.
    pub t: String,
    /// Self-referential BLAKE3 digest (with `d=""` and `sig=""` during hash).
    pub d: String,
    /// GhostID — equal to `d`.
    pub i: String,
    /// Sequence number. Always `0` for inception.
    pub s: u64,
    /// Key threshold. Always `1` in TSC v1.
    pub kt: u8,
    /// Active public keys (base64url, no padding). Length == `kt`.
    pub k: Vec<String>,
    /// Pre-rotation commitment: `BLAKE3(K2.verifying_key_bytes)`, hex-encoded.
    pub n: String,
    /// SLIP-0010 derivation path used for K1.
    pub di: String,
    /// Ed25519 signature by K1 (with `sig=""` during signing).
    pub sig: String,
}

impl InceptionEvent {
    /// Creates and self-signs a new Inception Event.
    ///
    /// Rejects `next_commitment == [0u8; 32]` (RFC-002 §2.3).
    pub fn new(active_key: &SigningKey, next_commitment: [u8; 32]) -> Result<Self, CryptoError> {
        if next_commitment == [0u8; 32] {
            return Err(CryptoError::KeyDerivation(
                "Pre-rotation commitment must not be all-zero (RFC-002 §2.3)".into(),
            ));
        }

        let pubkey_b64 = base64url(active_key.verifying_key().as_bytes());
        let commitment_hex = hex::encode(next_commitment);

        // Build skeleton with placeholders for d, i, sig
        let mut event = Self {
            v:   "TSC2.0".into(),
            t:   "ixn".into(),
            d:   String::new(),
            i:   String::new(),
            s:   0,
            kt:  1,
            k:   vec![pubkey_b64],
            n:   commitment_hex,
            di:  "m/44'/7777'/0'/0'/0'".into(),
            sig: String::new(),
        };

        // Step 1: d = BLAKE3(canonical_json with d="" i="" sig="")
        let digest = event.calculate_digest()?;
        event.d = hex::encode(digest);
        event.i = event.d.clone();

        // Step 2: sign with d and i set, sig still ""
        let msg = canonical_json(&event)?;
        let signature: Signature = active_key.sign(&msg);
        event.sig = hex::encode(signature.to_bytes());

        Ok(event)
    }

    /// Verifies the self-signature on this event.
    pub fn verify_signature(&self) -> Result<(), CryptoError> {
        let vk = parse_verifying_key(&self.k[0])?;
        let sig = parse_signature(&self.sig)?;

        let mut tmp = self.clone();
        tmp.sig = String::new();
        let msg = canonical_json(&tmp)?;

        vk.verify_strict(&msg, &sig)
            .map_err(|e| CryptoError::SignatureInvalid(e.to_string()))
    }

    /// BLAKE3 digest of this event (used as GhostID and as `d` field value).
    ///
    /// Computed with `d=""`, `i=""`, and `sig=""`.
    pub fn calculate_digest(&self) -> Result<[u8; 32], CryptoError> {
        let mut tmp = self.clone();
        tmp.d   = String::new();
        tmp.i   = String::new();
        tmp.sig = String::new();
        let bytes = canonical_json(&tmp)?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }
}

// ── Rotation Event ─────────────────────────────────────────────────────────

/// A key rotation event (RFC-002 §2.4).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RotationEvent {
    /// Protocol version.
    pub v: String,
    /// Event type tag. Always `"rot"`.
    pub t: String,
    /// BLAKE3 digest of this event.
    pub d: String,
    /// GhostID (unchanged through rotations).
    pub i: String,
    /// Sequence number (`previous.s + 1`).
    pub s: u64,
    /// BLAKE3 hash of the previous event.
    pub p: String,
    /// New active public key (base64url).
    pub k: Vec<String>,
    /// Pre-rotation commitment to the next-next key.
    pub n: String,
    /// Signature by the outgoing (old) key.
    pub sig_prev: String,
    /// Signature by the incoming (new) key.
    pub sig_new: String,
}

// ── Event log ──────────────────────────────────────────────────────────────

/// Every valid lifecycle event in the Identifier Event Log (IEL).
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t")]
pub enum KeyEvent {
    /// Genesis event.
    #[serde(rename = "ixn")]
    Inception(InceptionEvent),
    /// Key rotation.
    #[serde(rename = "rot")]
    Rotation(RotationEvent),
}

// ── Verification engine ────────────────────────────────────────────────────

/// Verifies an entire IEL from inception through all rotations.
///
/// Returns the current `VerifyingKey` if the chain is valid.
pub fn verify_event_log(log: &[KeyEvent]) -> Result<VerifyingKey, CryptoError> {
    if log.is_empty() {
        return Err(CryptoError::InvalidEventLog("Event log is empty".into()));
    }

    // First event must be an inception
    let ixn = match &log[0] {
        KeyEvent::Inception(e) => e,
        KeyEvent::Rotation(_) => {
            return Err(CryptoError::InvalidEventLog(
                "First event must be an Inception Event".into(),
            ))
        }
    };

    ixn.verify_signature()?;

    let mut current_key = parse_verifying_key(&ixn.k[0])?;
    let mut current_commitment = hex::decode(&ixn.n)
        .map_err(|_| CryptoError::InvalidEventLog("Cannot decode inception commitment".into()))?;
    let mut prev_digest = ixn.calculate_digest()?;
    let ghost_id = hex::encode(prev_digest);

    for (i, event) in log[1..].iter().enumerate() {
        match event {
            KeyEvent::Rotation(rot) => {
                verify_rotation(
                    rot,
                    &ghost_id,
                    (i + 1) as u64,
                    &prev_digest,
                    &current_key,
                    &current_commitment,
                )?;

                // Advance state to the new key
                current_key = parse_verifying_key(&rot.k[0])?;
                current_commitment = hex::decode(&rot.n).unwrap_or_default();

                // Compute this rotation's digest for the next iteration
                let mut tmp = rot.clone();
                tmp.d        = String::new();
                tmp.sig_prev = String::new();
                tmp.sig_new  = String::new();
                prev_digest = *blake3::hash(&canonical_json(&tmp)?).as_bytes();
            }
            KeyEvent::Inception(_) => {
                return Err(CryptoError::InvalidEventLog(
                    "Inception event found after position 0".into(),
                ));
            }
        }
    }

    Ok(current_key)
}

fn verify_rotation(
    rot: &RotationEvent,
    ghost_id: &str,
    expected_seq: u64,
    prev_digest: &[u8; 32],
    prev_key: &VerifyingKey,
    prev_commitment: &[u8],
) -> Result<(), CryptoError> {

    // Rule 1: sequence number
    if rot.s != expected_seq {
        return Err(CryptoError::InvalidEventLog(format!(
            "ROT: expected seq {}, got {}", expected_seq, rot.s
        )));
    }
    // Rule 2: GhostID unchanged
    if rot.i != ghost_id {
        return Err(CryptoError::InvalidEventLog(
            "ROT: GhostID changed across rotation".into(),
        ));
    }
    // Rule 3: previous event hash
    if rot.p != hex::encode(prev_digest) {
        return Err(CryptoError::InvalidEventLog(
            "ROT: previous event hash mismatch".into(),
        ));
    }
    // Rule 4: new key matches previous commitment
    let new_vk = parse_verifying_key(&rot.k[0])?;
    let new_commitment = blake3::hash(new_vk.as_bytes());
    if new_commitment.as_bytes().as_ref() != prev_commitment {
        return Err(CryptoError::InvalidEventLog(
            "ROT: new key does not match pre-rotation commitment".into(),
        ));
    }
    // Rule 5 & 6: both signatures over the same message (without sig fields)
    let mut tmp = rot.clone();
    tmp.sig_prev = String::new();
    tmp.sig_new  = String::new();
    let msg = canonical_json(&tmp)?;

    let sig_prev = parse_signature(&rot.sig_prev)
        .map_err(|_| CryptoError::SignatureInvalid("ROT: bad sig_prev".into()))?;
    prev_key.verify_strict(&msg, &sig_prev)
        .map_err(|e| CryptoError::SignatureInvalid(format!("ROT: sig_prev invalid: {}", e)))?;

    let sig_new = parse_signature(&rot.sig_new)
        .map_err(|_| CryptoError::SignatureInvalid("ROT: bad sig_new".into()))?;
    new_vk.verify_strict(&msg, &sig_new)
        .map_err(|e| CryptoError::SignatureInvalid(format!("ROT: sig_new invalid: {}", e)))?;

    Ok(())
}

// ── Internal helpers ───────────────────────────────────────────────────────

/// Serializes to canonical JSON bytes.
/// Field order follows struct declaration order — keep fields alphabetical
/// within each struct for canonical determinism.
fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, CryptoError> {
    serde_json::to_vec(value).map_err(|e| CryptoError::Serialization(e.to_string()))
}

fn parse_verifying_key(b64: &str) -> Result<VerifyingKey, CryptoError> {
    let bytes = base64url_decode(b64)
        .map_err(|_| CryptoError::SignatureInvalid("Cannot base64url-decode public key".into()))?;
    let arr: [u8; 32] = bytes.try_into()
        .map_err(|_| CryptoError::SignatureInvalid("Public key must be 32 bytes".into()))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| CryptoError::SignatureInvalid(e.to_string()))
}

fn parse_signature(hex_str: &str) -> Result<Signature, CryptoError> {
    let bytes = hex::decode(hex_str)
        .map_err(|_| CryptoError::SignatureInvalid("Cannot hex-decode signature".into()))?;
    let arr: [u8; 64] = bytes.try_into()
        .map_err(|_| CryptoError::SignatureInvalid("Signature must be 64 bytes".into()))?;
    Ok(Signature::from_bytes(&arr))
}

fn base64url(bytes: &[u8]) -> String {
    const T: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[((n >> 18) & 0x3F) as usize] as char);
        out.push(T[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 { out.push(T[((n >> 6) & 0x3F) as usize] as char); }
        if chunk.len() > 2 { out.push(T[(n & 0x3F) as usize] as char); }
    }
    out
}

fn base64url_decode(s: &str) -> Result<Vec<u8>, ()> {
    const TABLE: [i8; 128] = {
        let mut t = [-1i8; 128];
        let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut i = 0usize;
        while i < 64 { t[chars[i] as usize] = i as i8; i += 1; }
        t
    };
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < b.len() {
        let a = *TABLE.get(b[i] as usize).unwrap_or(&-1);
        let bv = *TABLE.get(b[i+1] as usize).unwrap_or(&-1);
        if a < 0 || bv < 0 { return Err(()); }
        out.push((a as u8) << 2 | (bv as u8) >> 4);
        if i + 2 < b.len() {
            let c = *TABLE.get(b[i+2] as usize).unwrap_or(&-1);
            if c < 0 { return Err(()); }
            out.push((bv as u8) << 4 | (c as u8) >> 2);
            if i + 3 < b.len() {
                let d = *TABLE.get(b[i+3] as usize).unwrap_or(&-1);
                if d < 0 { return Err(()); }
                out.push((c as u8) << 6 | d as u8);
                i += 4;
            } else { i += 3; }
        } else { i += 2; }
    }
    Ok(out)
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn fresh_key() -> SigningKey { SigningKey::generate(&mut OsRng) }
    fn commitment(k: &SigningKey) -> [u8; 32] {
        *blake3::hash(k.verifying_key().as_bytes()).as_bytes()
    }

    #[test]
    fn inception_signature_verifies() {
        let k1 = fresh_key();
        let k2 = fresh_key();
        let ixn = InceptionEvent::new(&k1, commitment(&k2)).unwrap();
        ixn.verify_signature().expect("must verify");
    }

    #[test]
    fn inception_d_equals_i() {
        let k1 = fresh_key();
        let ixn = InceptionEvent::new(&k1, commitment(&fresh_key())).unwrap();
        assert_eq!(ixn.d, ixn.i);
        assert!(!ixn.d.is_empty());
    }

    #[test]
    fn inception_rejects_zero_commitment() {
        let k1 = fresh_key();
        assert!(InceptionEvent::new(&k1, [0u8; 32]).is_err());
    }

    #[test]
    fn single_event_log_verifies() {
        let k1 = fresh_key();
        let ixn = InceptionEvent::new(&k1, commitment(&fresh_key())).unwrap();
        verify_event_log(&[KeyEvent::Inception(ixn)]).expect("must verify");
    }
}
