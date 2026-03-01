//! KERI-lite state machine for verifiable key rotation.

use serde::{Deserialize, Serialize};


/// The initial event that anchors a GhostID to the network.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InceptionEvent {
    /// Version string (e.g., "TSC1.0").
    pub v: String,
    /// Event type: "ixn" for inception.
    pub t: String,
    /// The initial public key (Hex).
    pub i: String,
    /// Sequence number (always 0 for inception).
    pub s: u64,
    /// BLAKE3 Hash commitment to the next key.
    pub n: String,
    /// Derivation path info.
    pub di: String,
}

impl InceptionEvent {
    /// Creates a new KERI Inception Event from a signing key and a future commitment.
    /// 
    /// This anchors the Ghost's identity by declaring the initial public key
    /// and pre-committing to the next key in the rotation chain.
    pub fn new(active_key: &ed25519_dalek::SigningKey, next_commitment: [u8; 32]) -> Self {
        Self {
            v: "TSC1.0".to_string(),
            t: "ixn".to_string(),
            i: hex::encode(active_key.verifying_key().as_bytes()),
            s: 0,
            n: hex::encode(next_commitment),
            di: "m/44'/0'/0'/0/0".to_string(),
        }
    }

    /// Generates the BLAKE3 cryptographic digest of the Inception Event.
    /// 
    /// This digest serves as the basis for the Autonomic Identifier (AID) 
    /// or GhostID, making the identity self-addressable and immutable.
    pub fn calculate_digest(&self) -> blake3::Hash {
        let serialized = serde_json::to_vec(self).expect("Serialization failed");
        blake3::hash(&serialized)
    }
}

/// Valid identity lifecycle events.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t")]
pub enum KeyEvent {
    /// Genesis event of an identity.
    #[serde(rename = "ixn")]
    Inception(InceptionEvent),
    /// Migration to a new key-pair.
    #[serde(rename = "rot")]
    Rotation(RotationEvent),
}

/// Event for migrating identity to a new cryptographic key.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RotationEvent {
    /// Version string.
    pub v: String,
    /// Hash of this event.
    pub d: String,
    /// Sequence number.
    pub s: u64,
    /// Hash of the previous event.
    pub p: String,
    /// The newly activated public key.
    pub k: String,
    /// Commitment to the next future key.
    pub n: String,
    /// Signature over the old key.
    pub sig_old: String,
    /// Signatures for the new key.
    pub sig_new: String,
}