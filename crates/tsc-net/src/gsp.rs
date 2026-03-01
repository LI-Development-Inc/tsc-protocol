//! Ghost Service Protocol (GSP) framing and types.
//! Defines the wire format for GSP messages, including framing and serialization logic.

use serde::{Deserialize, Serialize};
use bincode; 
use tsc_crypto::keri::InceptionEvent;

/// GSP Message Types: Control, Data, and Migration.
#[repr(u8)]
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum MsgType {
    /// Management tasks (Handshakes, KERI sync).
    Control = 0x01,
    /// Encapsulated Ghost-to-Ghost traffic.
    Data = 0x02,
    /// Ghost migration events.
    Migration = 0x03,
}

/// The initial handshake message for GSP peers.
#[derive(Serialize, Deserialize, Debug)]
pub struct GspHandshake {
    /// The sender's KERI Inception Event for verification.
    pub inception: InceptionEvent,
    /// A random challenge to prevent replay attacks.
    pub challenge: [u8; 32],
}

/// Verification response after a handshake attempt.
#[derive(Serialize, Deserialize, Debug)]
pub enum HandshakeResult {
    /// Handshake successful; identity verified.
    Success,
    /// Verification failed (GhostID mismatch or invalid signature).
    Failed(String),
}

/// A length-prefixed packet frame for transport over QUIC.
#[derive(Serialize, Deserialize, Debug)]
pub struct GspFrame {
    /// Size of the payload in bytes (Big Endian).
    pub length: u32,
    /// The type of message being transmitted.
    pub msg_type: MsgType,
    /// The raw message content.
    pub payload: Vec<u8>,
}

impl GspFrame {
    /// Encodes a payload into a GSP frame using bincode.
    pub fn new(msg_type: MsgType, payload: Vec<u8>) -> Self {
        Self {
            length: payload.len() as u32,
            msg_type,
            payload,
        }
    }

    /// Serializes the frame into bytes for transmission.
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("GSP serialization failure")
    }
}