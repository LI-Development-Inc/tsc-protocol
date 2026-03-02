//! Ghost Service Protocol (GSP) framing and types (RFC-001).
//!
//! # Handshake flow
//!
//! ```text
//! Initiator                          Responder
//!    │── HELLO (GhostID + VK + sig) ──►│
//!    │◄──── HELLO (responder's) ────────│
//! ```
//!
//! Both sides send a `GspHello` inside a `Control` frame immediately after
//! the QUIC connection is established.  Each side verifies the other's
//! signature before exchanging any `Data` frames.

use serde::{Deserialize, Serialize};
use tsc_crypto::keri::InceptionEvent;

/// GSP Message Types: Control, Data, Migration, and Chaff.
#[repr(u8)]
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgType {
    /// Management frames (HELLO handshake, KERI sync, keepalives).
    Control = 0x01,
    /// Encapsulated Ghost-to-Ghost application traffic.
    Data = 0x02,
    /// Ghost migration events.
    Migration = 0x03,
    /// Traffic morphing padding — silently discarded by receivers (RFC-001 §1.6).
    Chaff = 0xFF,
}

/// GSP HELLO frame payload — sent by both sides on connection establishment.
///
/// The receiver verifies that:
/// 1. `inception.verify_signature()` passes
/// 2. `BLAKE3(inception)` == `ghost_id`
/// 3. The QUIC peer address matches a known DHT record (Phase 2.2)
#[derive(Serialize, Deserialize, Debug)]
pub struct GspHello {
    /// The sender's GhostID (hex BLAKE3 of the InceptionEvent).
    pub ghost_id: String,
    /// The sender's KERI Inception Event. Verifier recomputes `BLAKE3(ixn)`
    /// and checks it equals `ghost_id`.
    pub inception: InceptionEvent,
}

/// Verification response after a handshake attempt.
#[derive(Serialize, Deserialize, Debug)]
pub enum HandshakeResult {
    /// Handshake successful; identity verified.
    Success,
    /// Verification failed (GhostID mismatch or invalid signature).
    Failed(String),
}

/// A length-prefixed GSP frame for transport over a QUIC stream.
///
/// Wire layout:
/// ```text
/// ┌──────────────┬──────────┬─────────────────┐
/// │  length: u32 │  type:u8 │  payload: [u8]  │
/// └──────────────┴──────────┴─────────────────┘
/// ```
#[derive(Serialize, Deserialize, Debug)]
pub struct GspFrame {
    /// Byte length of `payload`.
    pub length: u32,
    /// Frame classification.
    pub msg_type: MsgType,
    /// Raw payload bytes (bincode-encoded for `Control`, opaque for `Data`).
    pub payload: Vec<u8>,
}

impl GspFrame {
    /// Wraps a payload in a GSP frame.
    pub fn new(msg_type: MsgType, payload: Vec<u8>) -> Self {
        Self {
            length: payload.len() as u32,
            msg_type,
            payload,
        }
    }

    /// Serializes the frame to bytes for transmission over a QUIC stream.
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("GspFrame serialization failure")
    }

    /// Deserializes a frame from received bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok()
    }
}

// ── HELLO helpers ─────────────────────────────────────────────────────────

/// Encodes a `GspHello` into a `Control` frame, ready to send.
pub fn encode_hello(hello: &GspHello) -> Vec<u8> {
    let payload = bincode::serialize(hello).expect("GspHello serialize");
    GspFrame::new(MsgType::Control, payload).to_bytes()
}

/// Decodes a `GspHello` from the payload of a `Control` frame.
///
/// Returns `None` if the frame is not a `Control` frame or deserialisation
/// fails.
pub fn decode_hello(frame_bytes: &[u8]) -> Option<GspHello> {
    let frame = GspFrame::from_bytes(frame_bytes)?;
    if frame.msg_type != MsgType::Control {
        return None;
    }
    bincode::deserialize(&frame.payload).ok()
}

/// Verifies a received `GspHello`:
/// 1. IXN signature must be valid.
/// 2. `BLAKE3(ixn_with_placeholders)` must equal `hello.ghost_id`.
///
/// Returns `Ok(ghost_id)` on success, `Err(reason)` on failure.
pub fn verify_hello(hello: &GspHello) -> Result<String, String> {
    // 1. Verify the Ed25519 self-signature on the inception event
    hello.inception.verify_signature()
        .map_err(|e| format!("KERI:BAD_SIGNATURE: {}", e))?;

    // 2. Recompute the GhostID and compare
    let digest = hello.inception.calculate_digest()
        .map_err(|e| format!("KERI:DIGEST_ERROR: {}", e))?;
    let computed_id = hex::encode(digest);

    if computed_id != hello.ghost_id {
        return Err(format!(
            "KERI:ID_MISMATCH: claimed {} but inception hashes to {}",
            &hello.ghost_id[..16], &computed_id[..16],
        ));
    }

    Ok(hello.ghost_id.clone())
}
