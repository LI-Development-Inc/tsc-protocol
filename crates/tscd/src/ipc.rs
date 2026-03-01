//! IPC communication over Unix Domain Sockets with Peer Authentication.
//!
//! This module implements the TSCD Shell's primary control interface, allowing
//! the CLI or WASM-based frontends to interact with the daemon securely.

use tokio::net::UnixListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::unistd::Uid; 
use std::os::unix::io::AsFd;
use serde::{Serialize, Deserialize};
use std::sync::Arc;

// Internal TSC imports
use tsc_net::NetStack; // Fix: Import NetStack
use tsc_net::dht::GhostDiscovery; // Fix: Import GhostDiscovery

/// Structured commands for the Shell.
#[derive(Serialize, Deserialize, Debug)]
pub enum GhostCommand {
    /// Check Shell health (Heartbeat).
    Ping,
    /// Initialize a new Sovereign Identity and generate a root mnemonic.
    InitIdentity,
    /// Check the status of the local vault and verify identity integrity.   
    Status,
    /// Connect to a Ghost by its ID, triggering DHT resolution and network connection.
    Connect(String), 
    /// Send an encrypted string to a resolved GhostID.
    SendMessage {
        /// The target GhostID to send the message to.
        target_id: String, 
        /// The plaintext content to be encrypted and sent.
        content: String },
}

/// Structured responses from the Shell.
#[derive(Serialize, Deserialize, Debug)]
pub enum GhostResponse {
    /// Generic success message.
    Ok(String),
    /// The 24-word Mnemonic generated during initialization.
    Mnemonic(Vec<String>),
    /// Standardized error message.
    Err(String),
    /// Success response confirming the identity is verified and locked.
    IdentityFound(String),
    /// Response confirming a successful connection to a Ghost.
    LinkEstablished(String),
    /// Confirmation that a message was sent to the target Ghost.
    MessageSent(String),
}

/// The IPC server responsible for handling local control commands via Unix Domain Sockets.
pub struct IpcServer {
    /// The filesystem path where the Unix Domain Socket will be created.
    pub socket_path: String,
}
/// The IPC server implementation.
impl IpcServer {
    /// Starts the IPC server, listening for incoming commands and responding accordingly.
    pub async fn start(
        &self, 
        net: Arc<NetStack>, 
        discovery: Arc<GhostDiscovery>
    ) -> tokio::io::Result<()> {
        let _ = std::fs::remove_file(&self.socket_path);
        let listener = UnixListener::bind(&self.socket_path)?;
        
        loop {
            let (mut stream, _) = listener.accept().await?;
            
            if let Ok(creds) = getsockopt(&stream.as_fd(), PeerCredentials) {
                if Uid::from_raw(creds.uid()) != Uid::current() && !Uid::from_raw(creds.uid()).is_root() {
                    continue; 
                }
            }
            
            let net_stack = Arc::clone(&net);
            let disc_stack = Arc::clone(&discovery);

            tokio::spawn(async move {
                let mut buffer = [0u8; 1024];
                if let Ok(n) = stream.read(&mut buffer).await {
                    if n == 0 { return; }
                    
                    let cmd: GhostCommand = bincode::deserialize(&buffer[..n]).unwrap_or(GhostCommand::Ping);
                    
                    let response = match cmd {
                        GhostCommand::Ping => GhostResponse::Ok("TSC_PULSE_OK".into()),
                        GhostCommand::Connect(target_id) => {
                            match net_stack.resolve_ghost(target_id.clone(), &disc_stack).await {
                                Some(addr) => GhostResponse::LinkEstablished(
                                    format!("Ghost {} resolved to {}", target_id, addr)
                                ),
                                None => GhostResponse::Err("GhostID not found in DHT".into()),
                            }
                        },
                        GhostCommand::InitIdentity => {
                            match tsc_crypto::vault::generate_mnemonic() {
                                Ok(words) => {
                                    // 1. Generate the actual persona from the seed
                                    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
                                    let persona = tsc_crypto::Persona::new_with_history(signing_key, [0u8; 32]);
                                    
                                    // 2. Lock it in the vault
                                    let hw_uuid = tsc_crypto::vault::get_hardware_uuid();
                                    let ks = tsc_crypto::vault::derive_storage_key(&persona, &hw_uuid);
                                    
                                    if let Ok(_) = tsc_crypto::vault::lock_vault(words.clone(), &ks) {
                                        // 3. SUCCESS: Send the words back to the CLI
                                        println!("[+] IPC: New Identity Created: {}", persona.ghost_id);
                                        GhostResponse::Mnemonic(words)
                                    } else {
                                        GhostResponse::Err("Vault Lock Failed".into())
                                    }
                                },
                                Err(e) => GhostResponse::Err(format!("Entropy Error: {}", e)),
                            }
                        },
                        GhostCommand::Status => {
                            let hw_uuid = tsc_crypto::vault::get_hardware_uuid();
                            GhostResponse::IdentityFound(format!("Hardware UUID: {}", hw_uuid))
                        }
                        GhostCommand::SendMessage { target_id, content } => {
                            // 1. Resolve the address
                            if let Some(addr) = net_stack.resolve_ghost(target_id.clone(), &disc_stack).await {
                                // 2. Establish GSP Connection
                                match net_stack.connect(addr).await {
                                    Ok(conn) => {
                                        // 3. Open a stream and write the content
                                        if let Ok(mut stream) = conn.open_ghost_stream().await {
                                            let _ = stream.write_all(content.as_bytes()).await;
                                            let _ = stream.finish().await; // Close the stream cleanly
                                            GhostResponse::MessageSent(format!("Payload delivered to {}", target_id))
                                        } else {
                                            GhostResponse::Err("Failed to open data stream".into())
                                        }
                                    },
                                    Err(e) => GhostResponse::Err(format!("GSP Handshake Failed: {}", e)),
                                }
                            } else {
                                GhostResponse::Err("Target Ghost offline or unreachable".into())
                            }
                        },
                    };

                    if let Ok(resp_bytes) = bincode::serialize(&response) {
                        let _ = stream.write_all(&resp_bytes).await;
                        let _ = stream.shutdown().await;
                    }
                }
            });
        }
    }
}