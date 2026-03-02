#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! # TSCD — The Shell (TSC Daemon)
//!
//! ## Boot sequence (RFC-010)
//!
//! 1. Probe vault → load identity (or enter ephemeral mode)
//! 2. Initialise NetStack (creates QUIC endpoint + lookup channel)
//! 3. Start parallel tasks:
//!    - GSP listener
//!    - DHT discovery loop  (owns the lookup receiver)
//!    - IPC server          (uses Arc<DaemonState> for live identity)

pub mod ipc;

use std::net::SocketAddr;
use std::sync::Arc;

use tsc_net::dht::GhostDiscovery;
use tsc_net::NetStack;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("--- Standalone Complex (TSCD) v0.1.0 Initializing ---");

    // ── Step 1: Identity resolution ───────────────────────────────────────
    let hw_uuid    = tsc_crypto::vault::get_hardware_uuid();
    let vault_path = tsc_crypto::vault::vault_path()
        .map_err(|e| format!("TSCD:VAULT_PATH: {}", e))?;

    let (ghost_id, dht_key, vault_state, boot_ixn) = if vault_path.exists() {
        let mnemonic = std::env::var("TSC_MNEMONIC").unwrap_or_default();
        if mnemonic.trim().is_empty() {
            eprintln!("[!] Vault found at {} but TSC_MNEMONIC is not set.", vault_path.display());
            eprintln!("[!] Set TSC_MNEMONIC=\"word1 ... word24\" to unlock.");
            eprintln!("[!] Falling back to ephemeral mode.");
            ephemeral_boot()
        } else {
            match load_from_mnemonic(mnemonic.trim(), &hw_uuid, &vault_path) {
                Ok(r) => { println!("[+] Identity loaded. GhostID: {}", r.0); r }
                Err(e) => {
                    eprintln!("[!] Vault unlock failed: {}. Ephemeral mode.", e);
                    ephemeral_boot()
                }
            }
        }
    } else {
        println!("[!] No vault found — ephemeral mode.");
        println!("[!] Run 'tsc-cli init' to create a persistent identity.");
        ephemeral_boot()
    };

    // ── Step 2: Shared daemon state ───────────────────────────────────────
    let state = Arc::new(ipc::DaemonState::new(
        ghost_id.clone(),
        vault_state,
        vault_path.clone(),
        hw_uuid.clone(),
    ));

    // ── Step 3: Network stack ─────────────────────────────────────────────
    let listen_addr: SocketAddr = "0.0.0.0:9090".parse()?;
    let (net_stack, lookup_rx, reannounce_rx) = NetStack::new(ghost_id.clone(), listen_addr)
        .await
        .map_err(|e| format!("TSCD:NET_INIT: {}", e))?;
    let net_stack  = Arc::new(net_stack);
    // Set the inception event for GSP HELLO handshake (None in ephemeral mode)
    if let Some(ixn) = boot_ixn {
        *net_stack.local_ixn.write().await = Some(ixn);
    }
    let discovery  = Arc::new(GhostDiscovery::new(ghost_id.clone(), dht_key));

    let socket_path = ipc_socket_path();
    let ipc_server  = ipc::IpcServer {
        socket_path,
        state:      Arc::clone(&state),
        net_stack:  Arc::clone(&net_stack),
    };

    println!("[+] Standalone Complex Online.  GhostID: {}", ghost_id);

    // ── Step 4: Parallel tasks ────────────────────────────────────────────
    let net_listen  = Arc::clone(&net_stack);
    let net_disc    = Arc::clone(&net_stack);
    let disc_clone  = Arc::clone(&discovery);
    let disc_ipc    = Arc::clone(&discovery);

    tokio::select! {
        _ = net_listen.listen() => {
            println!("[!] GSP Listener exited.");
        },
        r = net_disc.run_discovery((*disc_clone).clone(), lookup_rx, reannounce_rx) => {
            if let Err(e) = r { println!("[!] DHT Discovery error: {}", e); }
        },
        r = ipc_server.start(disc_ipc) => {
            if let Err(e) = r { println!("[!] IPC error: {:?}", e); }
        },
    }

    Ok(())
}

// ── Boot helpers ──────────────────────────────────────────────────────────

/// Loads identity from a mnemonic phrase and verifies against the vault.
fn load_from_mnemonic(
    mnemonic: &str,
    hw_uuid:  &str,
    vault_path: &std::path::PathBuf,
) -> Result<(String, [u8; 32], ipc::BootVaultState, Option<tsc_crypto::keri::InceptionEvent>), String> {
    let seed = tsc_crypto::bip39::restore_from_phrase(mnemonic)
        .map_err(|e| e.to_string())?;
    let k1   = tsc_crypto::bip39::derive_active_key(&seed)
        .map_err(|e| e.to_string())?;
    let km   = k1.to_bytes();

    // Verify mnemonic matches vault
    tsc_crypto::vault::unlock_vault(&km, hw_uuid, vault_path)
        .map_err(|e| e.to_string())?;

    // Load IEL from disk
    let iel = tsc_crypto::iel::load_iel().unwrap_or_default();
    let persona = if !iel.is_empty() {
        match tsc_crypto::keri::verify_event_log(&iel) {
            Ok(_) => {
                let mut p = tsc_crypto::Persona::from_seed(&seed)
                    .map_err(|e| e.to_string())?;
                p.rotation  = (iel.len() as u32).saturating_sub(1);
                p.event_log = iel;
                p
            }
            Err(e) => {
                eprintln!("[WARN] IEL verification failed ({}); using inception only", e);
                tsc_crypto::Persona::from_seed(&seed).map_err(|e| e.to_string())?
            }
        }
    } else {
        tsc_crypto::Persona::from_seed(&seed).map_err(|e| e.to_string())?
    };

    // Extract the inception event for the GSP HELLO handshake
    let inception = match &persona.event_log[0] {
        tsc_crypto::keri::KeyEvent::Inception(ixn) => ixn.clone(),
        _ => unreachable!(),
    };

    let ghost_id = persona.ghost_id.clone();
    let dht_key  = derive_dht_key(&km, &ghost_id)?;

    Ok((ghost_id, dht_key, ipc::BootVaultState::Unlocked(km), Some(inception)))
}

/// Returns an ephemeral (session-only) identity.
///
/// Returns `None` for the `InceptionEvent` — ephemeral nodes skip the GSP
/// HELLO handshake and are labelled `"unverified"` by peers.
fn ephemeral_boot() -> (String, [u8; 32], ipc::BootVaultState, Option<tsc_crypto::keri::InceptionEvent>) {
    use rand::rngs::OsRng;
    let sk  = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let cmt = *blake3::hash(b"ephemeral-commitment").as_bytes();
    let ixn = tsc_crypto::keri::InceptionEvent::new(&sk, cmt)
        .expect("ephemeral inception cannot fail");
    let ghost_id = format!(
        "ephemeral:{}",
        &hex::encode(ixn.calculate_digest().unwrap())[..16]
    );
    (ghost_id, [0u8; 32], ipc::BootVaultState::Ephemeral, None)
}

/// Derives a separate DHT coordinate encryption key (must not reuse vault KM).
fn derive_dht_key(key_material: &[u8], ghost_id: &str) -> Result<[u8; 32], String> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(Some(b"tsc-dht-coord-v1"), key_material);
    let mut k = [0u8; 32];
    hk.expand(ghost_id.as_bytes(), &mut k)
        .map_err(|_| "HKDF expand failed".to_string())?;
    Ok(k)
}

/// XDG-aware IPC socket path.
fn ipc_socket_path() -> String {
    if let Some(d) = dirs::runtime_dir() {
        let dir = d.join("tsc");
        let _ = std::fs::create_dir_all(&dir);
        return dir.join("tscd.sock").to_string_lossy().into_owned();
    }
    eprintln!("[WARN] XDG_RUNTIME_DIR not set; using /tmp/tscd.sock");
    "/tmp/tscd.sock".to_string()
}
