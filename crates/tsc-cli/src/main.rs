//! TSC-CLI: Sovereign Controller for the Standalone Complex Shell.
mod proto;
use proto::{GhostCommand, GhostResponse};

use tokio::net::UnixStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let socket_path = "/tmp/tscd.sock";
    
    // 1. Updated Argument Parser
    let cmd = if args.len() > 1 {
        match args[1].as_str() {
            "init" => GhostCommand::InitIdentity,
            "status" => GhostCommand::Status,
            "connect" => {
                if args.len() > 2 {
                    GhostCommand::Connect(args[2].clone())
                } else {
                    println!("[!] Error: 'connect' requires a target GhostID.");
                    return Ok(());
                }
            },
            // NEW: Handle the 'send' command
            "send" => {
                if args.len() > 3 {
                    GhostCommand::SendMessage {
                        target_id: args[2].clone(),
                        content: args[3].clone(),
                    }
                } else {
                    println!("[!] Usage: ./tsc-cli send <GHOST_ID> \"<MESSAGE>\"");
                    return Ok(());
                }
            },
            _ => GhostCommand::Ping,
        }
    } else {
        GhostCommand::Ping 
    };

    // 2. Connection Logic
    let mut stream = UnixStream::connect(socket_path).await
        .map_err(|e| format!("[-] Connect Error: {}. Is tscd running?", e))?;

    // 3. Transmission
    let encoded = bincode::serialize(&cmd)?;
    stream.write_all(&encoded).await?;
    stream.shutdown().await?;

    // 4. Collect Response
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    
    let resp: GhostResponse = bincode::deserialize(&buf)
        .map_err(|e| format!("[-] Failed to decode Shell response: {}", e))?;

    // 5. Updated Response Handler
    match resp {
        GhostResponse::Ok(msg) => println!("[<] Shell Pulse: {}", msg),
        GhostResponse::IdentityFound(msg) => println!("[+] Success: {}", msg),
        GhostResponse::Mnemonic(words) => {
            println!("\n--- SOVEREIGN IDENTITY INITIALIZED ---");
            println!("CRITICAL: Write down these 24 words. They are your Master Seed.");
            println!("\n{}\n", words.join(" "));
            println!("--------------------------------------");
        },
        GhostResponse::LinkEstablished(peer_id) => {
            println!("[+] GSP Link Active: Successfully routed to Ghost {}", peer_id);
        },
        GhostResponse::MessageSent(details) => {
            println!("[+] Egress Success: {}", details);
        },
        GhostResponse::Err(e) => println!("[!] Shell Error: {}", e),
    }

    Ok(())
}