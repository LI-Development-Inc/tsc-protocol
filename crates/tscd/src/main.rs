#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! # TSCD — The Shell (TSC Daemon)
//!
//! Entry point for the privileged daemon that owns the network socket,
//! IPC interface, and Ghost lifecycle.
//!
//! ## Boot sequence (RFC-010)
//!
//! 1. Probe vault → load identity (or enter ephemeral mode)
//! 2. Initialize NetStack with the resolved GhostID
//! 3. Start parallel tasks: GSP listener · DHT discovery · IPC server

pub mod ipc;

use std::net::SocketAddr;
use std::sync::Arc;

use tsc_net::dht::GhostDiscovery;
use tsc_net::NetStack;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("--- Standalone Complex (TSCD) v0.1.0 Initializing ---");

    // ── Step 1: Identity resolution (RFC-010) ─────────────────────────────
    let hw_uuid = tsc_crypto::vault::get_hardware_uuid();
    let vault_path = tsc_crypto::vault::vault_path()
        .map_err(|e| format!("TSCD:VAULT_PATH: {}", e))?;

    // Resolve identity: vault-backed (persistent) or ephemeral.
    let (ghost_id, dht_key, persona_opt) = if vault_path.exists() {
        // Prompt for mnemonic.  In production this would come from a secure
        // input channel; for now we read from the TSC_MNEMONIC env var or
        // print a clear error.
        let mnemonic = std::env::var("TSC_MNEMONIC").unwrap_or_default();
        if mnemonic.trim().is_empty() {
            eprintln!("[!] Vault found at {} but TSC_MNEMONIC is not set.", vault_path.display());
            eprintln!("[!] Set TSC_MNEMONIC=\"word1 ... word24\" to unlock the vault.");
            eprintln!("[!] Falling back to ephemeral mode.");
            ephemeral_identity()
        } else {
            match load_identity_from_mnemonic(mnemonic.trim(), &hw_uuid, &vault_path) {
                Ok(result) => {
                    println!("[+] Identity Loaded. GhostID: {}", result.0);
                    result
                }
                Err(e) => {
                    eprintln!("[!] Vault unlock failed: {}. Entering ephemeral mode.", e);
                    ephemeral_identity()
                }
            }
        }
    } else {
        println!("[!] No vault found. Running in ephemeral mode.");
        println!("[!] Run 'tsc-cli init' to create a persistent sovereign identity.");
        ephemeral_identity()
    };

    // ── Step 2: Initialize shared stacks ──────────────────────────────────
    let addr: SocketAddr = "0.0.0.0:9090"
        .parse()
        .map_err(|e| format!("TSCD:ADDR_PARSE: {:?}", e))?;

    let net_stack = Arc::new(
        NetStack::new(ghost_id.clone(), addr)
            .await
            .map_err(|e| format!("TSCD:NET_INIT: {}", e))?,
    );

    let discovery = Arc::new(GhostDiscovery::new(ghost_id.clone(), dht_key));

    // Resolve the XDG runtime socket path
    let socket_path = ipc_socket_path();

    let ipc_server = crate::ipc::IpcServer {
        socket_path,
        persona: persona_opt,
    };

    println!("[+] Standalone Complex Online.  GhostID: {}", ghost_id);

    // ── Step 3: Parallel execution ─────────────────────────────────────────
    let net_for_disc = Arc::clone(&net_stack);
    let disc_clone   = Arc::clone(&discovery);
    let net_for_ipc  = Arc::clone(&net_stack);
    let disc_for_ipc = Arc::clone(&discovery);

    tokio::select! {
        _ = net_stack.listen() => {
            println!("[!] GSP Listener exited.");
        },
        result = net_for_disc.run_discovery((*disc_clone).clone()) => {
            if let Err(e) = result {
                println!("[!] DHT Discovery error: {}", e);
            }
        },
        result = ipc_server.start(net_for_ipc, disc_for_ipc) => {
            if let Err(e) = result {
                println!("[!] IPC Server error: {:?}", e);
            }
        },
    }

    Ok(())
}

// ── Boot helpers ───────────────────────────────────────────────────────────

/// Loads an identity from the mnemonic, verifying it against the vault.
///
/// Returns `(ghost_id, dht_key, Some(persona))`.
fn load_identity_from_mnemonic(
    mnemonic: &str,
    hw_uuid: &str,
    vault_path: &std::path::PathBuf,
) -> Result<(String, [u8; 32], Option<tsc_crypto::Persona>), String> {
    // 1. Derive the master seed from the mnemonic
    let master_seed = tsc_crypto::bip39::restore_from_phrase(mnemonic)
        .map_err(|e| format!("{}", e))?;

    // 2. Derive K1 to get the key material for the vault KDF
    let k1 = tsc_crypto::bip39::derive_active_key(&master_seed)
        .map_err(|e| format!("{}", e))?;
    let key_material = k1.to_bytes();

    // 3. Unlock vault to verify the mnemonic is correct
    tsc_crypto::vault::unlock_vault(&key_material, hw_uuid, vault_path)
        .map_err(|e| format!("{}", e))?;

    // 4. Build the Persona from the seed
    let persona = tsc_crypto::Persona::from_seed(&master_seed)
        .map_err(|e| format!("{}", e))?;

    let ghost_id = persona.ghost_id.clone();

    // 5. Derive a separate DHT coordinate key (must not reuse vault key)
    let dht_key = derive_dht_key(&key_material, &ghost_id)?;

    Ok((ghost_id, dht_key, Some(persona)))
}

/// Creates an ephemeral identity (no vault, session-only GhostID).
fn ephemeral_identity() -> (String, [u8; 32], Option<tsc_crypto::Persona>) {
    use rand::rngs::OsRng;
    let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
    // For ephemeral mode we use a dummy commitment — the identity is not
    // persistent so KERI rotation is not meaningful here.
    let dummy_commitment = *blake3::hash(b"ephemeral-commitment").as_bytes();
    let inception = tsc_crypto::keri::InceptionEvent::new(&signing_key, dummy_commitment)
        .expect("ephemeral inception must not fail");
    let ghost_id = format!(
        "ephemeral:{}",
        &hex::encode(inception.calculate_digest().unwrap())[..16]
    );
    (ghost_id, [0u8; 32], None)
}

/// Derives the DHT coordinate encryption key using HKDF-SHA256.
///
/// This key is intentionally distinct from the vault storage key (ADR-011,
/// Technical Specs §2.5).
fn derive_dht_key(key_material: &[u8], ghost_id: &str) -> Result<[u8; 32], String> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(Some(b"tsc-dht-coord-v1"), key_material);
    let mut dht_key = [0u8; 32];
    hk.expand(ghost_id.as_bytes(), &mut dht_key)
        .map_err(|_| "HKDF expand failed for DHT key".to_string())?;
    Ok(dht_key)
}

/// Returns the IPC Unix Domain Socket path.
///
/// Prefers `$XDG_RUNTIME_DIR/tsc/tscd.sock`; falls back to `/tmp/tscd.sock`
/// only if XDG_RUNTIME_DIR is unavailable.
fn ipc_socket_path() -> String {
    if let Some(runtime_dir) = dirs::runtime_dir() {
        let dir = runtime_dir.join("tsc");
        let _ = std::fs::create_dir_all(&dir);
        return dir.join("tscd.sock").to_string_lossy().into_owned();
    }
    // Fallback — not recommended for production
    eprintln!("[WARN] XDG_RUNTIME_DIR not set; using /tmp/tscd.sock");
    "/tmp/tscd.sock".to_string()
}
