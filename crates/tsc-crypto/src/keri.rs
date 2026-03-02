//! KERI-lite state machine for verifiable key succession (RFC-002).
//!
//! # Event chain
//!
//! ```text
//! IXN (s=0) ──K1──► ROT (s=1) ──K1+K2──► ROT (s=2) ──K2+K3──► …
//! ```
//!
//! The GhostID equals `BLAKE3(InceptionEvent)` and never changes through
//! any number of rotations.
//!
//! # Rotation index
//!
//! SLIP-0010 derivation path for rotation N:
//! ```text
//!   active_key  = m/44'/7777'/0'/0'/<N>'
//!   prerot_key  = m/44'/7777'/0'/0'/<N+1>'
//! ```
//! So inception uses N=0 (K1=index 0, K2=index 1).
//! First rotation advances to N=1 (new K1=index 1, new K2=index 2), etc.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::CryptoError;

// ── Inception Event ────────────────────────────────────────────────────────

/// The genesis event. Self-referential: GhostID = BLAKE3(this event).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InceptionEvent {
    /// Protocol version string. Always `"TSC2.0"`.
    pub v: String,
    /// Event type tag. Always `"ixn"`.
    pub t: String,
    /// Self-referential BLAKE3 digest (hex). Computed with `d=""`/`sig=""`.
    pub d: String,
    /// GhostID — identical to `d`.
    pub i: String,
    /// Sequence number. Always `0`.
    pub s: u64,
    /// Key threshold. Always `1` in TSC v1.
    pub kt: u8,
    /// Active public key(s), base64url-encoded without padding.
    pub k: Vec<String>,
    /// Pre-rotation commitment: hex(`BLAKE3(K2.verifying_key_bytes)`).
    pub n: String,
    /// SLIP-0010 derivation path used for the active key.
    pub di: String,
    /// Ed25519 signature by K1. Computed with `sig=""`.
    pub sig: String,
}

impl InceptionEvent {
    /// Creates and self-signs a new Inception Event.
    ///
    /// Rejects `next_commitment == [0u8;32]` (RFC-002 §2.3).
    pub fn new(
        active_key:       &SigningKey,
        next_commitment:  [u8; 32],
    ) -> Result<Self, CryptoError> {
        if next_commitment == [0u8; 32] {
            return Err(CryptoError::KeyDerivation(
                "Pre-rotation commitment must not be all-zero (RFC-002 §2.3)".into(),
            ));
        }

        let mut event = Self {
            v:   "TSC2.0".into(),
            t:   "ixn".into(),
            d:   String::new(),
            i:   String::new(),
            s:   0,
            kt:  1,
            k:   vec![base64url(active_key.verifying_key().as_bytes())],
            n:   hex::encode(next_commitment),
            di:  "m/44'/7777'/0'/0'/0'".into(),
            sig: String::new(),
        };

        // d = BLAKE3(event with d="" i="" sig="")
        let digest = event.calculate_digest()?;
        event.d = hex::encode(digest);
        event.i = event.d.clone();

        // sig = Ed25519(event with sig="")
        let msg: Signature = active_key.sign(&canonical_json(&event)?);
        event.sig = hex::encode(msg.to_bytes());

        Ok(event)
    }

    /// Verifies the Ed25519 self-signature.
    pub fn verify_signature(&self) -> Result<(), CryptoError> {
        let vk  = parse_verifying_key(&self.k[0])?;
        let sig = parse_signature(&self.sig)?;
        let mut tmp = self.clone();
        tmp.sig = String::new();
        vk.verify_strict(&canonical_json(&tmp)?, &sig)
            .map_err(|e| CryptoError::SignatureInvalid(e.to_string()))
    }

    /// BLAKE3 of the event with `d`, `i`, `sig` set to `""`.
    pub fn calculate_digest(&self) -> Result<[u8; 32], CryptoError> {
        let mut tmp = self.clone();
        tmp.d   = String::new();
        tmp.i   = String::new();
        tmp.sig = String::new();
        Ok(*blake3::hash(&canonical_json(&tmp)?).as_bytes())
    }
}

// ── Rotation Event ─────────────────────────────────────────────────────────

/// A key rotation event (RFC-002 §2.4).
///
/// Dual-signed: both the outgoing key (`sig_prev`) and the incoming key
/// (`sig_new`) sign the same canonical message.  This proves:
/// - the outgoing key holder authorised the rotation
/// - the incoming key holder controls the private key being installed
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RotationEvent {
    /// Protocol version. Always `"TSC2.0"`.
    pub v: String,
    /// Event type tag. Always `"rot"`.
    pub t: String,
    /// BLAKE3 digest of this event. Computed with `d=""`/`sig_prev=""`/`sig_new=""`.
    pub d: String,
    /// GhostID — unchanged through all rotations.
    pub i: String,
    /// Sequence number: always `prev.s + 1`.
    pub s: u64,
    /// Hex-encoded BLAKE3 digest of the previous event.
    pub p: String,
    /// New active public key, base64url-encoded.
    pub k: Vec<String>,
    /// Pre-rotation commitment for the next-next key.
    pub n: String,
    /// SLIP-0010 derivation path of the new active key.
    pub di: String,
    /// Signature by the outgoing (old) active key.
    pub sig_prev: String,
    /// Signature by the incoming (new) active key.
    pub sig_new: String,
}

impl RotationEvent {
    /// Creates and dual-signs a Rotation Event.
    ///
    /// Parameters:
    /// - `prev_key`       — the current active signing key (being rotated away from)
    /// - `new_key`        — the new active signing key (K_N+1, formerly the pre-rotation key)
    /// - `next_commitment`— BLAKE3(K_N+2.verifying_key), the next pre-rotation commitment
    /// - `prev_digest`    — BLAKE3 digest of the previous event in the IEL
    /// - `seq`            — sequence number (prev.s + 1)
    /// - `ghost_id`       — stable GhostID (unchanged)
    /// - `deriv_path`     — SLIP-0010 path string for `new_key` (e.g. `"m/44'/7777'/0'/0'/1'"`)
    pub fn new(
        prev_key:        &SigningKey,
        new_key:         &SigningKey,
        next_commitment: [u8; 32],
        prev_digest:     [u8; 32],
        seq:             u64,
        ghost_id:        &str,
        deriv_path:      &str,
    ) -> Result<Self, CryptoError> {
        if next_commitment == [0u8; 32] {
            return Err(CryptoError::KeyDerivation(
                "Next pre-rotation commitment must not be all-zero".into(),
            ));
        }

        let mut event = Self {
            v:        "TSC2.0".into(),
            t:        "rot".into(),
            d:        String::new(),
            i:        ghost_id.to_string(),
            s:        seq,
            p:        hex::encode(prev_digest),
            k:        vec![base64url(new_key.verifying_key().as_bytes())],
            n:        hex::encode(next_commitment),
            di:       deriv_path.to_string(),
            sig_prev: String::new(),
            sig_new:  String::new(),
        };

        // d = BLAKE3(event with d="" sig_prev="" sig_new="")
        let digest = event.calculate_digest()?;
        event.d = hex::encode(digest);

        // Both keys sign the same canonical message (with d set, sigs still "")
        let msg = canonical_json(&event)?;
        event.sig_prev = hex::encode(prev_key.sign(&msg).to_bytes());
        event.sig_new  = hex::encode(new_key.sign(&msg).to_bytes());

        Ok(event)
    }

    /// BLAKE3 of the event with `d`, `sig_prev`, `sig_new` set to `""`.
    pub fn calculate_digest(&self) -> Result<[u8; 32], CryptoError> {
        let mut tmp = self.clone();
        tmp.d        = String::new();
        tmp.sig_prev = String::new();
        tmp.sig_new  = String::new();
        Ok(*blake3::hash(&canonical_json(&tmp)?).as_bytes())
    }
}

// ── Event log ──────────────────────────────────────────────────────────────

/// A single entry in the Identifier Event Log.
///
/// Uses `#[serde(untagged)]` because each inner struct already carries a
/// `t` field (`"ixn"` or `"rot"`) that acts as the natural discriminant.
/// Using `#[serde(tag = "t")]` would inject a second `"t"` key into the
/// serialized JSON — a duplicate that breaks both serialization and the
/// KERI canonical hash.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum KeyEvent {
    /// Genesis event (sequence 0).
    Inception(InceptionEvent),
    /// Key rotation (sequence ≥ 1).
    Rotation(RotationEvent),
}

impl KeyEvent {
    /// The sequence number of this event.
    pub fn seq(&self) -> u64 {
        match self {
            KeyEvent::Inception(e) => e.s,
            KeyEvent::Rotation(e)  => e.s,
        }
    }

    /// The BLAKE3 digest of this event.
    pub fn digest(&self) -> Result<[u8; 32], CryptoError> {
        match self {
            KeyEvent::Inception(e) => e.calculate_digest(),
            KeyEvent::Rotation(e)  => e.calculate_digest(),
        }
    }
}

// ── Verification engine ────────────────────────────────────────────────────

/// Verifies an entire IEL from inception through all rotations.
///
/// Returns the current `VerifyingKey` on success.
pub fn verify_event_log(log: &[KeyEvent]) -> Result<VerifyingKey, CryptoError> {
    if log.is_empty() {
        return Err(CryptoError::InvalidEventLog("Event log is empty".into()));
    }

    let ixn = match &log[0] {
        KeyEvent::Inception(e) => e,
        KeyEvent::Rotation(_)  => return Err(CryptoError::InvalidEventLog(
            "First event must be Inception".into(),
        )),
    };

    ixn.verify_signature()?;

    let mut current_key        = parse_verifying_key(&ixn.k[0])?;
    let mut current_commitment = hex::decode(&ixn.n).map_err(|_|
        CryptoError::InvalidEventLog("Bad inception commitment encoding".into()))?;
    let mut prev_digest        = ixn.calculate_digest()?;
    let ghost_id               = hex::encode(prev_digest);

    for (i, event) in log[1..].iter().enumerate() {
        match event {
            KeyEvent::Inception(_) => return Err(CryptoError::InvalidEventLog(
                "Inception event found after position 0".into(),
            )),
            KeyEvent::Rotation(rot) => {
                verify_rotation(
                    rot,
                    &ghost_id,
                    (i + 1) as u64,
                    &prev_digest,
                    &current_key,
                    &current_commitment,
                )?;
                current_key        = parse_verifying_key(&rot.k[0])?;
                current_commitment = hex::decode(&rot.n).unwrap_or_default();
                prev_digest        = rot.calculate_digest()?;
            }
        }
    }

    Ok(current_key)
}

fn verify_rotation(
    rot:              &RotationEvent,
    ghost_id:         &str,
    expected_seq:     u64,
    prev_digest:      &[u8; 32],
    prev_key:         &VerifyingKey,
    prev_commitment:  &[u8],
) -> Result<(), CryptoError> {
    // 1. Sequence
    if rot.s != expected_seq {
        return Err(CryptoError::InvalidEventLog(format!(
            "ROT: expected seq {}, got {}", expected_seq, rot.s
        )));
    }
    // 2. GhostID unchanged
    if rot.i != ghost_id {
        return Err(CryptoError::InvalidEventLog(
            "ROT: GhostID changed across rotation".into(),
        ));
    }
    // 3. Previous event hash
    if rot.p != hex::encode(prev_digest) {
        return Err(CryptoError::InvalidEventLog(
            "ROT: previous event hash mismatch".into(),
        ));
    }
    // 4. New key matches previous commitment
    let new_vk = parse_verifying_key(&rot.k[0])?;
    if blake3::hash(new_vk.as_bytes()).as_bytes().as_ref() != prev_commitment {
        return Err(CryptoError::InvalidEventLog(
            "ROT: new key does not match pre-rotation commitment".into(),
        ));
    }
    // 5 & 6. Both signatures over canonical message (d set, sigs zeroed)
    let msg = {
        let mut tmp  = rot.clone();
        tmp.sig_prev = String::new();
        tmp.sig_new  = String::new();
        canonical_json(&tmp)?
    };

    let sig_prev = parse_signature(&rot.sig_prev)
        .map_err(|_| CryptoError::SignatureInvalid("ROT: cannot parse sig_prev".into()))?;
    prev_key.verify_strict(&msg, &sig_prev)
        .map_err(|e| CryptoError::SignatureInvalid(format!("ROT sig_prev: {}", e)))?;

    let sig_new = parse_signature(&rot.sig_new)
        .map_err(|_| CryptoError::SignatureInvalid("ROT: cannot parse sig_new".into()))?;
    new_vk.verify_strict(&msg, &sig_new)
        .map_err(|e| CryptoError::SignatureInvalid(format!("ROT sig_new: {}", e)))?;

    Ok(())
}

// ── Internal helpers ───────────────────────────────────────────────────────

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, CryptoError> {
    serde_json::to_vec(value).map_err(|e| CryptoError::Serialization(e.to_string()))
}

fn parse_verifying_key(b64: &str) -> Result<VerifyingKey, CryptoError> {
    let bytes = base64url_decode(b64)
        .map_err(|_| CryptoError::SignatureInvalid("Bad base64url public key".into()))?;
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
        let n  = (b0 << 16) | (b1 << 8) | b2;
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
        let a  = *TABLE.get(b[i]   as usize).unwrap_or(&-1);
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
    fn inception_self_signs() {
        let k1 = fresh_key();
        let ixn = InceptionEvent::new(&k1, commitment(&fresh_key())).unwrap();
        ixn.verify_signature().unwrap();
    }

    #[test]
    fn inception_d_equals_i_and_nonempty() {
        let k1  = fresh_key();
        let ixn = InceptionEvent::new(&k1, commitment(&fresh_key())).unwrap();
        assert_eq!(ixn.d, ixn.i);
        assert!(!ixn.d.is_empty());
    }

    #[test]
    fn inception_rejects_zero_commitment() {
        assert!(InceptionEvent::new(&fresh_key(), [0u8; 32]).is_err());
    }

    #[test]
    fn single_event_log_verifies() {
        let k1  = fresh_key();
        let ixn = InceptionEvent::new(&k1, commitment(&fresh_key())).unwrap();
        verify_event_log(&[KeyEvent::Inception(ixn)]).unwrap();
    }

    #[test]
    fn rotation_chain_ixn_rot_verifies() {
        // K1 = active at inception, K2 = pre-rotation at inception
        let k1 = fresh_key();
        let k2 = fresh_key();
        let k3 = fresh_key();

        let ixn = InceptionEvent::new(&k1, commitment(&k2)).unwrap();
        let ghost_id    = hex::encode(ixn.calculate_digest().unwrap());
        let ixn_digest  = ixn.calculate_digest().unwrap();

        // Rotation: old=K1, new=K2, next_commitment=BLAKE3(K3.pub)
        let rot = RotationEvent::new(
            &k1, &k2,
            commitment(&k3),
            ixn_digest,
            1,
            &ghost_id,
            "m/44'/7777'/0'/0'/1'",
        ).unwrap();

        let log = vec![
            KeyEvent::Inception(ixn),
            KeyEvent::Rotation(rot),
        ];

        let current_vk = verify_event_log(&log).unwrap();
        // After one rotation, current key is K2
        assert_eq!(current_vk.as_bytes(), k2.verifying_key().as_bytes());
    }

    #[test]
    fn rotation_ghost_id_unchanged() {
        let k1 = fresh_key();
        let k2 = fresh_key();
        let k3 = fresh_key();

        let ixn        = InceptionEvent::new(&k1, commitment(&k2)).unwrap();
        let ghost_id   = ixn.i.clone();
        let ixn_digest = ixn.calculate_digest().unwrap();

        let rot = RotationEvent::new(
            &k1, &k2, commitment(&k3),
            ixn_digest, 1, &ghost_id,
            "m/44'/7777'/0'/0'/1'",
        ).unwrap();

        // GhostID in the rotation event must equal the inception GhostID
        assert_eq!(rot.i, ghost_id);
    }

    #[test]
    fn rotation_wrong_commitment_rejected() {
        let k1  = fresh_key();
        let k2  = fresh_key();
        let k3  = fresh_key();
        // Use k3 as commitment but try to install k2 as new key (mismatch)
        let ixn = InceptionEvent::new(&k1, commitment(&k3)).unwrap();
        let digest  = ixn.calculate_digest().unwrap();
        let gid     = ixn.i.clone();

        let rot = RotationEvent::new(
            &k1, &k2, commitment(&k3), digest, 1, &gid,
            "m/44'/7777'/0'/0'/1'",
        ).unwrap();

        let log = vec![KeyEvent::Inception(ixn), KeyEvent::Rotation(rot)];
        // k2.pub hashes to a different value than commitment(&k3) stored in IXN.n
        assert!(verify_event_log(&log).is_err());
    }

    #[test]
    fn double_rotation_verifies() {
        let k1 = fresh_key();
        let k2 = fresh_key();
        let k3 = fresh_key();
        let k4 = fresh_key();

        let ixn        = InceptionEvent::new(&k1, commitment(&k2)).unwrap();
        let gid        = ixn.i.clone();
        let d0         = ixn.calculate_digest().unwrap();

        let rot1 = RotationEvent::new(
            &k1, &k2, commitment(&k3), d0, 1, &gid,
            "m/44'/7777'/0'/0'/1'",
        ).unwrap();
        let d1 = rot1.calculate_digest().unwrap();

        let rot2 = RotationEvent::new(
            &k2, &k3, commitment(&k4), d1, 2, &gid,
            "m/44'/7777'/0'/0'/2'",
        ).unwrap();

        let log = vec![
            KeyEvent::Inception(ixn),
            KeyEvent::Rotation(rot1),
            KeyEvent::Rotation(rot2),
        ];

        let vk = verify_event_log(&log).unwrap();
        assert_eq!(vk.as_bytes(), k3.verifying_key().as_bytes());
    }
}
