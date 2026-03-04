//! IPC server over Unix Domain Sockets (RFC-003).
//!
//! ## Framing
//! Every message is prefixed with a 4-byte little-endian length (tsc-proto).
//!
//! ## Authentication
//! `SO_PEERCRED` — caller UID must match daemon owner or be root.
//!
//! ## Live identity reload
//! `InitIdentity` and `RecoverIdentity` write a new vault and then update
//! the shared [`DaemonState`] so subsequent `status` calls reflect the new
//! identity without restarting the daemon.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::unistd::Uid;
use std::os::unix::io::AsFd;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixListener;
use tokio::sync::RwLock;

use tsc_net::dht::GhostDiscovery;
use tsc_net::{NetStack, ReannounceRequest};
use tsc_proto::{
    read_framed, write_framed, DaemonStatus, GhostCommand, GhostResponse, VaultState,
};

// ── Shared daemon state ────────────────────────────────────────────────────

/// What the daemon knows about the vault at boot time.
pub enum BootVaultState {
    /// Vault was unlocked; contains the 32-byte key material.
    Unlocked([u8; 32]),
    /// No vault file existed or mnemonic was not supplied.
    Ephemeral,
}

/// Mutable identity state, shared between the IPC handler tasks.
///
/// Wrapped in `Arc<RwLock<_>>` so `InitIdentity` can update it while
/// concurrent `status` reads continue without blocking.
pub struct IdentityState {
    /// Current GhostID string (persistent or `"ephemeral:<short>"`).
    pub ghost_id: String,
    /// Whether a valid vault is loaded.
    pub vault_ok: bool,
}

/// All state the IPC server needs, shared via `Arc`.
pub struct DaemonState {
    /// Mutable identity (GhostID, vault status).
    pub identity: RwLock<IdentityState>,
    /// Absolute path of the vault file.
    pub vault_path: PathBuf,
    /// Hardware UUID used for vault KDF binding.
    pub hw_uuid: String,
    /// Wall-clock start time for uptime calculation.
    pub started: Instant,
}

impl DaemonState {
    /// Constructs the initial shared state.
    pub fn new(
        ghost_id:    String,
        vault_state: BootVaultState,
        vault_path:  PathBuf,
        hw_uuid:     String,
    ) -> Self {
        let vault_ok = matches!(vault_state, BootVaultState::Unlocked(_));
        Self {
            identity: RwLock::new(IdentityState { ghost_id, vault_ok }),
            vault_path,
            hw_uuid,
            started: Instant::now(),
        }
    }
}

// ── IPC server ─────────────────────────────────────────────────────────────

/// Listens on a Unix Domain Socket and dispatches `GhostCommand`s.
pub struct IpcServer {
    /// Path of the Unix Domain Socket to bind.
    pub socket_path: String,
    /// Shared daemon state (identity, vault path, hw_uuid).
    pub state: Arc<DaemonState>,
    /// Network stack — needed so InitIdentity can update local_id and reannounce.
    pub net_stack: Arc<NetStack>,
}

impl IpcServer {
    /// Runs the accept loop.
    pub async fn start(
        self,
        discovery: Arc<GhostDiscovery>,
    ) -> tokio::io::Result<()> {
        let _ = std::fs::remove_file(&self.socket_path);
        let listener = UnixListener::bind(&self.socket_path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                &self.socket_path,
                std::fs::Permissions::from_mode(0o600),
            )?;
        }

        println!("[*] IPC: Listening on {}", self.socket_path);

        loop {
            let (stream, _) = listener.accept().await?;

            // Peer credential check
            if let Ok(creds) = getsockopt(&stream.as_fd(), PeerCredentials) {
                let uid = Uid::from_raw(creds.uid());
                if uid != Uid::current() && !uid.is_root() {
                    eprintln!("[!] IPC: Rejected UID {}", creds.uid());
                    continue;
                }
            }

            let disc_c  = Arc::clone(&discovery);
            let state_c = Arc::clone(&self.state);
            let ns_c    = Arc::clone(&self.net_stack);

            tokio::spawn(async move {
                handle_connection(stream, disc_c, state_c, ns_c).await;
            });
        }
    }
}

// ── Connection handler ─────────────────────────────────────────────────────

async fn handle_connection(
    mut stream: tokio::net::UnixStream,
    discovery:  Arc<GhostDiscovery>,
    state:      Arc<DaemonState>,
    net_stack:  Arc<NetStack>,
) {
    let (mut reader, mut writer) = stream.split();

    let cmd = match read_framed::<_, GhostCommand>(&mut reader).await {
        Ok(Some(c)) => c,
        Ok(None)    => return,
        Err(e) => {
            eprintln!("[!] IPC: frame read error: {}", e);
            return;
        }
    };

    let response = dispatch(cmd, &discovery, &state, &net_stack).await;

    if let Err(e) = write_framed(&mut writer, &response).await {
        eprintln!("[!] IPC: frame write error: {}", e);
    }
    let _ = writer.shutdown().await;
}

// ── Command dispatch ───────────────────────────────────────────────────────

async fn dispatch(
    cmd:       GhostCommand,
    discovery: &Arc<GhostDiscovery>,
    state:     &Arc<DaemonState>,
    net_stack: &Arc<NetStack>,
) -> GhostResponse {
    match cmd {

        // ── Ping ─────────────────────────────────────────────────────────
        GhostCommand::Ping => GhostResponse::Ok("TSC_PULSE_OK".into()),

        // ── Status ───────────────────────────────────────────────────────
        GhostCommand::Status => {
            let id    = state.identity.read().await;
            let vault = if id.ghost_id.starts_with("ephemeral") {
                VaultState::Ephemeral
            } else if id.vault_ok {
                VaultState::Unlocked
            } else {
                VaultState::Locked
            };
            GhostResponse::Status(DaemonStatus {
                ghost_id:     id.ghost_id.clone(),
                vault_state:  vault,
                peer_count:   0,    // TODO(Phase 2.2): wire to libp2p swarm peer count
                active_ghosts: 0,   // TODO(Phase 3.1): wire to GhostHandle registry
                uptime_secs:  state.started.elapsed().as_secs(),
            })
        }

        // ── Init Identity ────────────────────────────────────────────────
        GhostCommand::InitIdentity => {
            let hw_uuid = &state.hw_uuid;

            // 1. Generate fresh entropy and derive persona
            let (phrase, master_seed) = tsc_crypto::bip39::generate_sovereign_entropy();
            let words: Vec<String> = phrase.split_whitespace()
                .map(|s| s.to_string()).collect();

            let persona = match tsc_crypto::Persona::from_seed(&master_seed) {
                Ok(p)  => p,
                Err(e) => return GhostResponse::Err(e.to_string()),
            };
            let k1 = match tsc_crypto::bip39::derive_active_key(&master_seed) {
                Ok(k)  => k,
                Err(e) => return GhostResponse::Err(e.to_string()),
            };

            // 2. Write vault
            if let Err(e) = tsc_crypto::vault::lock_vault(
                &words, &k1.to_bytes(), hw_uuid, &state.vault_path,
            ) {
                return GhostResponse::Err(e.to_string());
            }

            // 2b. Persist the inception IEL (overwrites any previous IEL)
            if let Err(e) = tsc_crypto::iel::save_iel(&persona.event_log) {
                // Non-fatal: log the error but continue — rotate-key will
                // reconstruct from seed if the IEL is missing.
                eprintln!("[WARN] IEL write failed after init: {}", e);
            }

            // 3. Update live daemon state and DHT identity
            {
                let mut id = state.identity.write().await;
                id.ghost_id = persona.ghost_id.clone();
                id.vault_ok = true;
            }
            // Update the NetStack's local_id and local_ixn for HELLO handshake
            *net_stack.local_id.write().await  = persona.ghost_id.clone();
            *net_stack.local_ixn.write().await = Some(
                match &persona.event_log[0] {
                    tsc_crypto::keri::KeyEvent::Inception(ixn) => ixn.clone(),
                    _ => unreachable!(),
                }
            );
            // Encode the local address and store in the local Kademlia store immediately
            if let Ok(addr) = net_stack.endpoint.local_addr() {
                let real_addr = if addr.ip().is_unspecified() {
                    std::net::SocketAddr::new("127.0.0.1".parse().unwrap(), addr.port())
                } else { addr };
                let value = discovery.encode_coordinate(real_addr);
                let _ = net_stack.reannounce_tx().send(ReannounceRequest {
                    ghost_id: persona.ghost_id.clone(),
                    value,
                }).await;
            }

            println!("[+] IPC: Identity created: {}", persona.ghost_id);
            GhostResponse::Mnemonic(words)
        }

        // ── Recover Identity ─────────────────────────────────────────────
        GhostCommand::RecoverIdentity { mnemonic } => {
            let hw_uuid = &state.hw_uuid;

            let master_seed = match tsc_crypto::bip39::restore_from_phrase(&mnemonic) {
                Ok(s)  => s,
                Err(e) => return GhostResponse::Err(e.to_string()),
            };
            let k1 = match tsc_crypto::bip39::derive_active_key(&master_seed) {
                Ok(k)  => k,
                Err(e) => return GhostResponse::Err(e.to_string()),
            };
            let words: Vec<String> = mnemonic.split_whitespace()
                .map(|s| s.to_string()).collect();

            if let Err(e) = tsc_crypto::vault::lock_vault(
                &words, &k1.to_bytes(), hw_uuid, &state.vault_path,
            ) {
                return GhostResponse::Err(e.to_string());
            }

            // Update live state and DHT identity
            if let Ok(persona) = tsc_crypto::Persona::from_seed(&master_seed) {
                // Persist fresh inception IEL (discards any prior rotation history —
                // recovery intentionally resets to rotation 0)
                if let Err(e) = tsc_crypto::iel::save_iel(&persona.event_log) {
                    eprintln!("[WARN] IEL write failed after recover: {}", e);
                }
                {
                    let mut id = state.identity.write().await;
                    id.ghost_id = persona.ghost_id.clone();
                    id.vault_ok = true;
                }
                *net_stack.local_id.write().await  = persona.ghost_id.clone();
                *net_stack.local_ixn.write().await = Some(
                    match &persona.event_log[0] {
                        tsc_crypto::keri::KeyEvent::Inception(ixn) => ixn.clone(),
                        _ => unreachable!(),
                    }
                );
                if let Ok(addr) = net_stack.endpoint.local_addr() {
                    let real_addr = if addr.ip().is_unspecified() {
                        std::net::SocketAddr::new("127.0.0.1".parse().unwrap(), addr.port())
                    } else { addr };
                    let value = discovery.encode_coordinate(real_addr);
                    let _ = net_stack.reannounce_tx().send(ReannounceRequest {
                        ghost_id: persona.ghost_id.clone(),
                        value,
                    }).await;
                }
            }

            GhostResponse::Ok(
                "IDENTITY:RECOVERED: Vault written and identity reloaded.".into(),
            )
        }

        // ── Resolve ──────────────────────────────────────────────────────
        GhostCommand::Resolve { ghost_id } => {
            match net_stack.resolve_ghost(ghost_id.clone(), discovery).await {
                Some(addr) => GhostResponse::Resolved {
                    ghost_id,
                    addr: addr.to_string(),
                },
                None => GhostResponse::Err(
                    "NET:NOT_FOUND: GhostID not found in DHT".into(),
                ),
            }
        }

        // ── Connect ──────────────────────────────────────────────────────
        GhostCommand::Connect { ghost_id } => {
            match net_stack.resolve_ghost(ghost_id.clone(), discovery).await {
                Some(addr) => GhostResponse::LinkEstablished {
                    remote_id: ghost_id,
                    addr:      addr.to_string(),
                },
                None => GhostResponse::Err(
                    "NET:NOT_FOUND: GhostID not found or offline".into(),
                ),
            }
        }

        // ── Send Message ─────────────────────────────────────────────────
        GhostCommand::SendMessage { target_id, content } => {
            let addr = match net_stack.resolve_ghost(target_id.clone(), discovery).await {
                Some(a) => a,
                None    => return GhostResponse::Err(
                    "NET:NOT_FOUND: Target Ghost offline or unreachable".into(),
                ),
            };
            match net_stack.connect(addr).await {
                Ok(conn) => match conn.open_ghost_stream().await {
                    Ok(mut send) => {
                        // Wrap content in a Data frame for protocol-aware ingress
                        let frame = tsc_net::gsp::GspFrame::new(
                            tsc_net::gsp::MsgType::Data,
                            content.into_bytes(),
                        );
                        let _ = send.write_all(&frame.to_bytes()).await;
                        let _ = send.finish().await;
                        GhostResponse::MessageSent { target_id }
                    }
                    Err(e) => GhostResponse::Err(
                        format!("NET:STREAM: {}", e),
                    ),
                },
                Err(e) => GhostResponse::Err(
                    format!("NET:CONNECT: {}", e),
                ),
            }
        }

        // ── Connect Direct (bypass DHT — Phase 2.1 cross-node testing) ──────
        //
        // Dials a peer by explicit IP:port rather than DHT lookup.
        // Performs the full GSP HELLO handshake and returns the KERI-verified
        // GhostID learned from the peer's inception event.
        //
        // Usage: tsc-cli connect-direct <ip>:<port>
        GhostCommand::ConnectDirect { addr } => {
            let sock_addr: std::net::SocketAddr = match addr.parse() {
                Ok(a)  => a,
                Err(_) => return GhostResponse::Err(
                    format!("NET:BAD_ADDR: '{}' is not a valid IP:port", addr)
                ),
            };
            match net_stack.connect(sock_addr).await {
                Ok(conn) => GhostResponse::DirectLinkEstablished {
                    remote_id: conn.remote_ghost_id,
                    addr,
                },
                Err(e) => GhostResponse::Err(format!("NET:CONNECT_DIRECT: {}", e)),
            }
        }

        // ── Send Direct (bypass DHT — Phase 2.1 cross-node testing) ─────────
        //
        // Opens a fresh QUIC connection to IP:port, performs GSP HELLO,
        // then sends a Data frame.  No connection pool; each call is independent.
        //
        // Usage: tsc-cli send-direct <ip>:<port> "<message>"
        GhostCommand::SendDirect { addr, content } => {
            let sock_addr: std::net::SocketAddr = match addr.parse() {
                Ok(a)  => a,
                Err(_) => return GhostResponse::Err(
                    format!("NET:BAD_ADDR: '{}' is not a valid IP:port", addr)
                ),
            };
            match net_stack.connect(sock_addr).await {
                Ok(conn) => match conn.open_ghost_stream().await {
                    Ok(mut send) => {
                        let frame = tsc_net::gsp::GspFrame::new(
                            tsc_net::gsp::MsgType::Data,
                            content.into_bytes(),
                        );
                        let _ = send.write_all(&frame.to_bytes()).await;
                        let _ = send.finish().await;
                        GhostResponse::Ok(format!(
                            "DIRECT: Message delivered to {} (peer: {})",
                            addr, &conn.remote_ghost_id[..16.min(conn.remote_ghost_id.len())]
                        ))
                    }
                    Err(e) => GhostResponse::Err(format!("NET:STREAM: {}", e)),
                },
                Err(e) => GhostResponse::Err(format!("NET:CONNECT_DIRECT: {}", e)),
            }
        }

        // ── Ghost lifecycle (Phase 3 — stubs) ────────────────────────────
        GhostCommand::SpawnGhost { image_hash, .. } => GhostResponse::Err(
            format!("RUNTIME:NOT_IMPL: SpawnGhost({}) — Phase 3 pending", image_hash),
        ),
        GhostCommand::ListGhosts => GhostResponse::GhostList(vec![]),
        GhostCommand::StopGhost { ghost_id } => GhostResponse::Err(
            format!("RUNTIME:NOT_IMPL: StopGhost({}) — Phase 3 pending", ghost_id),
        ),
        GhostCommand::RotateKey { mnemonic } => {
            // mnemonic arrived from tsc-cli (read from TSC_MNEMONIC on client side).
            // Validate and derive seed immediately; mnemonic is dropped at end of scope.
            let master_seed = match tsc_crypto::bip39::restore_from_phrase(mnemonic.trim()) {
                Ok(s)  => s,
                Err(e) => return GhostResponse::Err(format!("IDENTITY:ROTATE: {}", e)),
            };

            // 2. Load the existing IEL or build from vault
            let mut log = match tsc_crypto::iel::load_iel() {
                Ok(l) if !l.is_empty() => l,
                _ => {
                    // IEL file missing — reconstruct from seed (inception only)
                    match tsc_crypto::Persona::from_seed(&master_seed) {
                        Ok(p) => p.event_log.clone(),
                        Err(e) => return GhostResponse::Err(format!("IDENTITY:ROTATE: {}", e)),
                    }
                }
            };

            // 3. Determine current rotation count from IEL length
            let rotation = (log.len() as u32).saturating_sub(1);
            let next_rotation = rotation + 1;

            // 4. Derive new active key (K_{N+1}) and commitment BLAKE3(K_{N+2})
            let new_active = match tsc_crypto::bip39::derive_key_at_index(&master_seed, next_rotation) {
                Ok(k)  => k,
                Err(e) => return GhostResponse::Err(format!("IDENTITY:ROTATE: {}", e)),
            };
            let new_commitment = match tsc_crypto::bip39::commitment_at_index(&master_seed, next_rotation + 1) {
                Ok(c)  => c,
                Err(e) => return GhostResponse::Err(format!("IDENTITY:ROTATE: {}", e)),
            };

            // 5. Get prev_digest and ghost_id from tip of IEL
            let prev_event = match log.last() {
                Some(e) => e,
                None    => return GhostResponse::Err("IDENTITY:ROTATE: IEL is empty".into()),
            };
            let prev_digest = match prev_event.digest() {
                Ok(d)  => d,
                Err(e) => return GhostResponse::Err(format!("IDENTITY:ROTATE: {}", e)),
            };
            let seq = prev_event.seq() + 1;

            // ghost_id is always the inception GhostID
            let ghost_id = state.identity.read().await.ghost_id.clone();
            // If still ephemeral, can't rotate
            if ghost_id.starts_with("ephemeral") {
                return GhostResponse::Err(
                    "IDENTITY:ROTATE: Cannot rotate an ephemeral identity. Run 'init' first.".into(),
                );
            }

            // We need the current active key to sign sig_prev.
            // Re-derive it from the seed at the current rotation index.
            let current_active = match tsc_crypto::bip39::derive_key_at_index(&master_seed, rotation) {
                Ok(k)  => k,
                Err(e) => return GhostResponse::Err(format!("IDENTITY:ROTATE: {}", e)),
            };

            let deriv_path = format!("m/44'/7777'/0'/0/{}'", next_rotation);
            let rot_event = match tsc_crypto::keri::RotationEvent::new(
                &current_active,
                &new_active,
                new_commitment,
                prev_digest,
                seq,
                &ghost_id,
                &deriv_path,
            ) {
                Ok(r)  => r,
                Err(e) => return GhostResponse::Err(format!("IDENTITY:ROTATE: {}", e)),
            };

            // 6. Append to IEL in memory and persist
            let new_event = tsc_crypto::keri::KeyEvent::Rotation(rot_event);
            log.push(new_event.clone());

            if let Err(e) = tsc_crypto::iel::append_event(&new_event) {
                return GhostResponse::Err(format!("IDENTITY:ROTATE: IEL write failed: {}", e));
            }

            // 7. Update vault key_material with new K_{N+1} bytes
            let words: Vec<String> = mnemonic.trim().split_whitespace()
                .map(|s| s.to_string()).collect();
            if let Err(e) = tsc_crypto::vault::lock_vault(
                &words,
                &new_active.to_bytes(),
                &state.hw_uuid,
                &state.vault_path,
            ) {
                return GhostResponse::Err(format!("IDENTITY:ROTATE: vault rewrite failed: {}", e));
            }

            // 8. Update NetStack local_id and reannounce (GhostID unchanged)
            // The GhostID is stable — no need to update net_stack.local_id.
            // But we do reannounce to refresh the DHT record.
            if let Ok(addr) = net_stack.endpoint.local_addr() {
                let real_addr = if addr.ip().is_unspecified() {
                    std::net::SocketAddr::new("127.0.0.1".parse().unwrap(), addr.port())
                } else { addr };
                let value = discovery.encode_coordinate(real_addr);
                let _ = net_stack.reannounce_tx().send(tsc_net::ReannounceRequest {
                    ghost_id: ghost_id.clone(),
                    value,
                }).await;
            }

            println!("[+] IPC: Key rotated. Rotation #{}, GhostID unchanged: {}", next_rotation, &ghost_id[..16]);
            let new_pubkey_hex = hex::encode(new_active.verifying_key().to_bytes());
            GhostResponse::KeyRotated {
                new_public_key: new_pubkey_hex,
            }
        }
    }
}
