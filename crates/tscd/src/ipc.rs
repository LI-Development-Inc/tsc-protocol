//! IPC server over Unix Domain Sockets (RFC-003).
//!
//! Authentication: `SO_PEERCRED` — caller UID must match the daemon owner or be root.
//! Framing: u32 little-endian length prefix (from `tsc_proto::read_framed` / `write_framed`).
//! Types: `GhostCommand` / `GhostResponse` from `tsc-proto` (RFC-011, ADR-007).

use std::sync::Arc;
use tokio::net::UnixListener;
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::unistd::Uid;
use std::os::unix::io::AsFd;

use tsc_net::dht::GhostDiscovery;
use tsc_net::NetStack;
use tsc_proto::{
    read_framed, write_framed, DaemonStatus, GhostCommand, GhostResponse, VaultState,
};

/// The IPC server that handles CLI → daemon commands.
pub struct IpcServer {
    /// Filesystem path for the Unix Domain Socket.
    pub socket_path: String,
    /// The resolved Persona (None in ephemeral mode).
    pub persona: Option<tsc_crypto::Persona>,
}

impl IpcServer {
    /// Starts the IPC listener loop.
    pub async fn start(
        self,
        net: Arc<NetStack>,
        discovery: Arc<GhostDiscovery>,
    ) -> tokio::io::Result<()> {
        // Clean up stale socket from a previous run
        let _ = std::fs::remove_file(&self.socket_path);
        let listener = UnixListener::bind(&self.socket_path)?;

        // Tighten socket permissions to owner-only
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                &self.socket_path,
                std::fs::Permissions::from_mode(0o600),
            )?;
        }

        println!("[*] IPC: Listening on {}", self.socket_path);

        let start_time = std::time::Instant::now();
        // The ghost_id for status responses
        let ghost_id = self
            .persona
            .as_ref()
            .map(|p| p.ghost_id.clone())
            .unwrap_or_else(|| "ephemeral".to_string());

        loop {
            let (stream, _) = listener.accept().await?;

            // ── Peer credential check (RFC-003 §3.1) ──────────────────────
            if let Ok(creds) = getsockopt(&stream.as_fd(), PeerCredentials) {
                let caller_uid = Uid::from_raw(creds.uid());
                if caller_uid != Uid::current() && !caller_uid.is_root() {
                    eprintln!("[!] IPC: Rejected connection from UID {}", creds.uid());
                    continue;
                }
            }

            let net_stack   = Arc::clone(&net);
            let disc_stack  = Arc::clone(&discovery);
            let ghost_id_c  = ghost_id.clone();
            let uptime_fn   = start_time;

            tokio::spawn(async move {
                handle_connection(stream, net_stack, disc_stack, ghost_id_c, uptime_fn).await;
            });
        }
    }
}

/// Handles a single accepted IPC connection.
async fn handle_connection(
    mut stream: tokio::net::UnixStream,
    net: Arc<NetStack>,
    discovery: Arc<GhostDiscovery>,
    ghost_id: String,
    started: std::time::Instant,
) {
    use tokio::io::AsyncWriteExt;

    // Split into reader/writer so we can hold them simultaneously
    let (mut reader, mut writer) = stream.split();

    let cmd = match read_framed::<_, GhostCommand>(&mut reader).await {
        Ok(Some(c)) => c,
        Ok(None) => return, // clean EOF
        Err(e) => {
            eprintln!("[!] IPC: Frame read error: {}", e);
            return;
        }
    };

    let response = dispatch_command(cmd, &net, &discovery, &ghost_id, started).await;

    if let Err(e) = write_framed(&mut writer, &response).await {
        eprintln!("[!] IPC: Frame write error: {}", e);
    }
    let _ = writer.shutdown().await;
}

/// Routes a `GhostCommand` to the appropriate handler and returns a `GhostResponse`.
async fn dispatch_command(
    cmd: GhostCommand,
    net: &Arc<NetStack>,
    discovery: &Arc<GhostDiscovery>,
    ghost_id: &str,
    started: std::time::Instant,
) -> GhostResponse {
    match cmd {
        // ── Ping ───────────────────────────────────────────────────────────
        GhostCommand::Ping => GhostResponse::Ok("TSC_PULSE_OK".into()),

        // ── Status ─────────────────────────────────────────────────────────
        GhostCommand::Status => {
            GhostResponse::Status(DaemonStatus {
                ghost_id: ghost_id.to_string(),
                vault_state: if ghost_id.starts_with("ephemeral") {
                    VaultState::Ephemeral
                } else {
                    VaultState::Unlocked
                },
                peer_count: 0,    // TODO: query libp2p swarm peer count
                active_ghosts: 0, // TODO: query runtime Ghost registry
                uptime_secs: started.elapsed().as_secs(),
            })
        }

        // ── Init Identity ──────────────────────────────────────────────────
        GhostCommand::InitIdentity => {
            let hw_uuid = tsc_crypto::vault::get_hardware_uuid();
            let vault_path = match tsc_crypto::vault::vault_path() {
                Ok(p) => p,
                Err(e) => return GhostResponse::Err(format!("{}", e)),
            };

            // Generate entropy and derive seed
            let (phrase, master_seed) = tsc_crypto::bip39::generate_sovereign_entropy();
            let words: Vec<String> = phrase.split_whitespace().map(|s| s.to_string()).collect();

            // Derive persona to get K1 for the vault KDF
            let persona = match tsc_crypto::Persona::from_seed(&master_seed) {
                Ok(p) => p,
                Err(e) => return GhostResponse::Err(format!("{}", e)),
            };

            let k1 = match tsc_crypto::bip39::derive_active_key(&master_seed) {
                Ok(k) => k,
                Err(e) => return GhostResponse::Err(format!("{}", e)),
            };
            let key_material = k1.to_bytes();

            // Lock vault
            if let Err(e) = tsc_crypto::vault::lock_vault(&words, &key_material, &hw_uuid, &vault_path) {
                return GhostResponse::Err(format!("{}", e));
            }

            println!("[+] IPC: New Identity Created: {}", persona.ghost_id);
            GhostResponse::Mnemonic(words)
        }

        // ── Recover Identity ───────────────────────────────────────────────
        GhostCommand::RecoverIdentity { mnemonic } => {
            let hw_uuid = tsc_crypto::vault::get_hardware_uuid();
            let vault_path = match tsc_crypto::vault::vault_path() {
                Ok(p) => p,
                Err(e) => return GhostResponse::Err(format!("{}", e)),
            };

            let master_seed = match tsc_crypto::bip39::restore_from_phrase(&mnemonic) {
                Ok(s) => s,
                Err(e) => return GhostResponse::Err(format!("{}", e)),
            };

            let words: Vec<String> = mnemonic.split_whitespace().map(|s| s.to_string()).collect();
            let k1 = match tsc_crypto::bip39::derive_active_key(&master_seed) {
                Ok(k) => k,
                Err(e) => return GhostResponse::Err(format!("{}", e)),
            };

            if let Err(e) = tsc_crypto::vault::lock_vault(&words, &k1.to_bytes(), &hw_uuid, &vault_path) {
                return GhostResponse::Err(format!("{}", e));
            }
            GhostResponse::Ok("IDENTITY:RECOVERED: Vault written. Restart tscd to load the new identity.".into())
        }

        // ── Resolve ────────────────────────────────────────────────────────
        GhostCommand::Resolve { ghost_id: target_id } => {
            match net.resolve_ghost(target_id.clone(), discovery).await {
                Some(addr) => GhostResponse::Resolved {
                    ghost_id: target_id,
                    addr: addr.to_string(),
                },
                None => GhostResponse::Err(
                    "NET:NOT_FOUND: GhostID not found in DHT".into(),
                ),
            }
        }

        // ── Connect ────────────────────────────────────────────────────────
        GhostCommand::Connect { ghost_id: target_id } => {
            match net.resolve_ghost(target_id.clone(), discovery).await {
                Some(addr) => GhostResponse::LinkEstablished {
                    remote_id: target_id,
                    addr: addr.to_string(),
                },
                None => GhostResponse::Err(
                    "NET:NOT_FOUND: GhostID not found in DHT or offline".into(),
                ),
            }
        }

        // ── SendMessage ────────────────────────────────────────────────────
        GhostCommand::SendMessage { target_id, content } => {

            let addr = match net.resolve_ghost(target_id.clone(), discovery).await {
                Some(a) => a,
                None => {
                    return GhostResponse::Err(
                        "NET:NOT_FOUND: Target Ghost offline or unreachable".into(),
                    )
                }
            };

            match net.connect(addr).await {
                Ok(conn) => match conn.open_ghost_stream().await {
                    Ok(mut send) => {
                        let _ = send.write_all(content.as_bytes()).await;
                        let _ = send.finish().await;
                        GhostResponse::MessageSent { target_id }
                    }
                    Err(e) => GhostResponse::Err(
                        format!("NET:STREAM_OPEN: Failed to open data stream: {}", e),
                    ),
                },
                Err(e) => GhostResponse::Err(
                    format!("NET:CONNECT: GSP handshake failed: {}", e),
                ),
            }
        }

        // ── Ghost lifecycle (Phase 3) ──────────────────────────────────────
        GhostCommand::SpawnGhost { image_hash, vault_id: _ } => {
            GhostResponse::Err(format!(
                "RUNTIME:NOT_IMPL: SpawnGhost({}) — Phase 3 work pending",
                image_hash
            ))
        }
        GhostCommand::ListGhosts => {
            GhostResponse::GhostList(vec![])
        }
        GhostCommand::StopGhost { ghost_id } => {
            GhostResponse::Err(format!(
                "RUNTIME:NOT_IMPL: StopGhost({}) — Phase 3 work pending",
                ghost_id
            ))
        }
        GhostCommand::RotateKey => {
            GhostResponse::Err("IDENTITY:NOT_IMPL: RotateKey — Phase 1.1 work pending".into())
        }
    }
}
