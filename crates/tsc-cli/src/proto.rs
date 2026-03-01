//! Protocol definitions for structured IPC communication between the Shell and TSC Daemon.
//! This module defines the command and response schemas used in the Unix Domain Socket communication.
//! The `GhostCommand` enum represents the various control commands that the CLI can send to the Shell,
//! while the `GhostResponse` enum encapsulates the structured responses that the Shell can return,
//! including success messages, errors, and critical data like the mnemonic words.

use serde::{Deserialize, Serialize};

/// Structured commands for the Shell.
#[derive(Serialize, Deserialize, Debug)]
pub enum GhostCommand {
    /// Check Shell health.
    Ping,
    /// Initialize a new Sovereign Identity.
    InitIdentity,
    /// Check the status of the local vault and identity.
    Status,
    /// Attempt to connect to a peer using their GhostID.
    Connect(String),
    /// Send an encrypted string to a resolved GhostID.
    SendMessage { target_id: String, content: String },
}

/// Structured responses from the Shell.
#[derive(Serialize, Deserialize, Debug)]
pub enum GhostResponse {
    /// Generic success message.
    Ok(String),
    /// The 24-word Mnemonic.
    Mnemonic(Vec<String>),
    /// Standardized error message.
    Err(String),
    /// Confirmation of a decrypted identity.
    IdentityFound(String),
    /// Response for a successful connection attempt.
    LinkEstablished(String),
    /// Confirmation the data entered the QUIC egress queue.
    MessageSent(String),
}