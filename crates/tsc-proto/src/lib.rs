#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! # tsc-proto
//!
//! Shared IPC protocol types for the Standalone Complex.
//!
//! Both `tscd` and `tsc-cli` depend on this crate. Neither may define their
//! own copies of [`GhostCommand`] or [`GhostResponse`]. This guarantees that
//! the serialization format stays in sync across the daemon/CLI boundary.

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Wire protocol version. Both sides MUST agree before exchanging commands.
pub const PROTO_VERSION: u32 = 1;

// ─────────────────────────────────────────────────────────────
// Commands  (CLI → tscd)
// ─────────────────────────────────────────────────────────────

/// Every control command the CLI (or any IPC client) can send to `tscd`.
#[derive(Serialize, Deserialize, Debug)]
pub enum GhostCommand {
    /// Heartbeat / liveness check.
    Ping,

    /// Create a new sovereign identity.
    ///
    /// Generates BIP-39 entropy, derives keys via SLIP-0010, writes the vault,
    /// and returns the 24-word mnemonic so the user can back it up.
    InitIdentity,

    /// Restore an identity from an existing mnemonic phrase.
    RecoverIdentity {
        /// Space-separated 24-word BIP-39 mnemonic.
        mnemonic: String,
    },

    /// Return current daemon status.
    Status,

    /// Resolve a GhostID to a network address via the DHT.
    Resolve {
        /// The target GhostID (hex-encoded BLAKE3 digest).
        ghost_id: String,
    },

    /// Establish a GSP connection to a peer.
    Connect {
        /// The target GhostID.
        ghost_id: String,
    },

    /// Send an encrypted message to a connected peer.
    SendMessage {
        /// The target GhostID.
        target_id: String,
        /// Plaintext content (encrypted in transit over QUIC/GSP).
        content: String,
    },

    /// Spawn a new Ghost-Box from an OCI image hash.
    SpawnGhost {
        /// BLAKE3 hash of the OCI image to run.
        image_hash: String,
        /// Optional vault ID for persistent storage. `None` = ephemeral Ghost.
        vault_id: Option<String>,
    },

    /// List all currently running Ghost processes.
    ListGhosts,

    /// Terminate a running Ghost by its GhostID.
    StopGhost {
        /// The GhostID of the running instance to stop.
        ghost_id: String,
    },

    /// Rotate the active signing key (KERI Rotation Event).
    ///
    /// The mnemonic is read on the CLI side (from `TSC_MNEMONIC` or prompt)
    /// and passed to the daemon only for the duration of this call.
    /// The daemon never stores the mnemonic.
    RotateKey {
        /// The BIP-39 mnemonic phrase authorizing this rotation.
        mnemonic: String,
    },

    /// Connect directly to a peer by IP:port, bypassing DHT resolution.
    ///
    /// Used for cross-internet testing before bootstrap nodes are configured.
    /// The remote peer's GhostID is returned after the KERI HELLO handshake.
    ///
    /// Example: `tsc-cli connect-direct 1.2.3.4:9090`
    ConnectDirect {
        /// Socket address of the remote peer, e.g. `"1.2.3.4:9090"`.
        addr: String,
    },

    /// Send a message to a peer by IP:port, bypassing DHT resolution.
    ///
    /// Performs a fresh QUIC + GSP HELLO per call (no persistent connection pool yet).
    /// Useful for Phase 2.1/2.2 cross-node validation before bootstrap nodes exist.
    ///
    /// Example: `tsc-cli send-direct 1.2.3.4:9090 "hello from local"`
    SendDirect {
        /// Socket address of the remote peer, e.g. `"1.2.3.4:9090"`.
        addr: String,
        /// Message content to deliver.
        content: String,
    },
}

// ─────────────────────────────────────────────────────────────
// Responses  (tscd → CLI)
// ─────────────────────────────────────────────────────────────

/// Every response `tscd` can return to an IPC client.
#[derive(Serialize, Deserialize, Debug)]
pub enum GhostResponse {
    /// Generic success with a human-readable message.
    Ok(String),

    /// Structured error. Format: `"MODULE:CODE: description"`.
    Err(String),

    /// 24-word mnemonic, returned after [`GhostCommand::InitIdentity`].
    ///
    /// **Security:** The caller MUST display these words to the user and
    /// then immediately drop them. They MUST NOT be persisted in any log.
    Mnemonic(Vec<String>),

    /// Full daemon status snapshot.
    Status(DaemonStatus),

    /// A resolved network address for a GhostID.
    Resolved {
        /// The queried GhostID.
        ghost_id: String,
        /// Resolved socket address, e.g. `"1.2.3.4:9090"`.
        addr: String,
    },

    /// GSP link established to a remote peer.
    LinkEstablished {
        /// The remote peer's GhostID.
        remote_id: String,
        /// The address the connection was made to.
        addr: String,
    },

    /// GSP direct link established (ConnectDirect — no DHT lookup).
    ///
    /// Returns the KERI-verified GhostID of the remote peer, learned during HELLO.
    DirectLinkEstablished {
        /// KERI-verified GhostID of the remote peer (from their HELLO frame).
        /// Will be `"unverified"` if the peer is in ephemeral mode.
        remote_id: String,
        /// The address that was dialled.
        addr: String,
    },

    /// Message successfully handed to the GSP egress queue.
    MessageSent {
        /// The target GhostID the message was sent to.
        target_id: String,
    },

    /// A Ghost-Box was spawned successfully.
    GhostSpawned {
        /// Host PID of the container leader process.
        pid: u32,
        /// Virtual IPv6 address assigned inside the Ghost namespace.
        virtual_ip: String,
    },

    /// Snapshot of all running Ghosts.
    GhostList(Vec<GhostInfo>),

    /// A Ghost was cleanly terminated.
    GhostStopped {
        /// The GhostID that was stopped.
        ghost_id: String,
    },

    /// Key rotation completed. The GhostID is unchanged; the signing key is new.
    KeyRotated {
        /// The new Ed25519 public key, hex-encoded.
        new_public_key: String,
    },
}

// ─────────────────────────────────────────────────────────────
// Supporting types
// ─────────────────────────────────────────────────────────────

/// A snapshot of the daemon's current state.
#[derive(Serialize, Deserialize, Debug)]
pub struct DaemonStatus {
    /// The persistent GhostID for this node (or `"ephemeral:<id>"` if no vault).
    pub ghost_id: String,
    /// Current vault state.
    pub vault_state: VaultState,
    /// Number of connected peers in the DHT swarm.
    pub peer_count: usize,
    /// Number of active Ghost-Box processes.
    pub active_ghosts: usize,
    /// Seconds since `tscd` started.
    pub uptime_secs: u64,
}

/// The current state of the identity vault.
#[derive(Serialize, Deserialize, Debug)]
pub enum VaultState {
    /// Vault is open and the persistent identity is active.
    Unlocked,
    /// Vault file exists but the daemon cannot open it (wrong key / corrupted).
    Locked,
    /// No vault on disk; running with a session-only ephemeral identity.
    Ephemeral,
}

/// A summary of a single running Ghost-Box.
#[derive(Serialize, Deserialize, Debug)]
pub struct GhostInfo {
    /// The GhostID of this Ghost instance.
    pub ghost_id: String,
    /// Host-side PID of the container leader.
    pub pid: u32,
    /// Virtual IPv6 address assigned to this Ghost.
    pub virtual_ip: String,
    /// Human-readable status string.
    pub status: String,
    /// Seconds this Ghost has been running.
    pub uptime_secs: u64,
}

// ─────────────────────────────────────────────────────────────
// IPC Framing helpers  (RFC-003 §3.1)
// ─────────────────────────────────────────────────────────────
//
// Every message is prefixed with a little-endian u32 that gives the byte
// length of the bincode payload.  This prevents partial-read bugs when the
// kernel delivers the data in multiple TCP/UDS segments.
//
//   [ payload_length: u32 (LE) ][ bincode payload: N bytes ]

/// Write a single framed, bincode-serialized message to any async writer.
///
/// The frame format is a 4-byte little-endian length prefix followed by the
/// `bincode`-encoded payload.
pub async fn write_framed<W, T>(writer: &mut W, value: &T) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let payload = bincode::serialize(value).map_err(FrameError::Serialize)?;
    let len = payload.len() as u32;
    writer.write_all(&len.to_le_bytes()).await.map_err(FrameError::Io)?;
    writer.write_all(&payload).await.map_err(FrameError::Io)?;
    Ok(())
}

/// Read a single framed message from any async reader and deserialize it.
///
/// Returns `None` if the stream was closed cleanly (zero bytes read on the
/// length prefix).  Returns `Err` on any I/O or deserialization failure.
pub async fn read_framed<R, T>(reader: &mut R) -> Result<Option<T>, FrameError>
where
    R: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(FrameError::Io(e)),
    }

    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 65_536 {
        return Err(FrameError::FrameTooLarge(len));
    }

    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await.map_err(FrameError::Io)?;
    let value = bincode::deserialize(&payload).map_err(FrameError::Deserialize)?;
    Ok(Some(value))
}

/// Errors that can occur during IPC framing.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// An underlying I/O error on the socket.
    #[error("IPC I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Bincode serialization failed.
    #[error("IPC serialize error: {0}")]
    Serialize(bincode::Error),

    /// Bincode deserialization failed.
    #[error("IPC deserialize error: {0}")]
    Deserialize(bincode::Error),

    /// The peer sent a frame larger than the 64 KiB maximum.
    #[error("IPC frame too large: {0} bytes (max 65536)")]
    FrameTooLarge(usize),
}
