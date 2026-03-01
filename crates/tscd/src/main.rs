#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! # TSCD (The Shell)
pub mod ipc;

use tsc_net::NetStack;
use tsc_net::dht::GhostDiscovery;
use std::net::SocketAddr;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("--- Standalone Complex (TSCD) v2.0 Initializing ---");

    // 1. Identity & Vault Setup
    let hw_uuid = tsc_crypto::vault::get_hardware_uuid();
    
    // NOTE: In a production flow, we would load the existing signing key from the vault.
    // For now, we maintain the persona for boot-strapping.
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let persona = tsc_crypto::Persona::new_with_history(signing_key, [0u8; 32]);
    let ks_vec = tsc_crypto::vault::derive_storage_key(&persona, &hw_uuid);
    let ks: [u8; 32] = ks_vec.try_into().expect("Key must be 32 bytes");

    let (ghost_identity, storage_key) = match tsc_crypto::vault::unlock_vault(&ks) {
        Ok(_) => {
            println!("[+] Vault Verified. GhostID: {}", persona.ghost_id);
            (persona.ghost_id.clone(), ks)
        },
        Err(_) => {
            // Updated to display the Ephemeral ID consistently with your logs
            println!("[!] Warning: Vault Locked. Using Ephemeral ID: {}", persona.ghost_id);
            (persona.ghost_id.clone(), [0u8; 32])
        }
    };

    // 2. Initialize Shared Stacks
    let addr: SocketAddr = "0.0.0.0:9090".parse().map_err(|e| format!("Addr Parse Error: {:?}", e))?;
    
    // The '?' now works because main returns Send + Sync
    let net_stack = Arc::new(NetStack::new(ghost_identity.clone(), addr).await?);
    let discovery = Arc::new(GhostDiscovery::new(ghost_identity, storage_key));
    
    let ipc_server = crate::ipc::IpcServer {
        socket_path: "/tmp/tscd.sock".to_string(),
    };

    println!("[+] Standalone Complex Online.");

    // 3. Parallel Execution
    let net_for_discovery = Arc::clone(&net_stack);
    let disc_for_discovery = Arc::clone(&discovery);
    
    let net_for_ipc = Arc::clone(&net_stack);
    let disc_for_ipc = Arc::clone(&discovery);

    

    tokio::select! {
        _ = net_stack.listen() => println!("[!] GSP Listener exited."),
        _ = net_for_discovery.run_discovery((*disc_for_discovery).clone()) => {
            println!("[!] DHT Discovery exited.");
        },
        // Passing the clones to the IPC server for resolution and messaging
        res = ipc_server.start(net_for_ipc, disc_for_ipc) => {
            if let Err(e) = res {
                println!("[!] IPC Server Error: {:?}", e);
            }
        },
    }

    Ok(())
}