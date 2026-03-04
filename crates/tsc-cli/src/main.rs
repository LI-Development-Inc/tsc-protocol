//! TSC-CLI: Sovereign Controller for the Standalone Complex Shell.
//!
//! Connects to the `tscd` daemon via Unix Domain Socket and dispatches
//! commands using the shared `tsc-proto` IPC protocol (RFC-003, ADR-007).

use tokio::net::UnixStream;
use tsc_proto::{read_framed, write_framed, DaemonStatus, GhostCommand, GhostResponse, VaultState};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let cmd = parse_command(&args)?;
    let socket_path = resolve_socket_path();

    let mut stream = UnixStream::connect(&socket_path).await.map_err(|e| {
        format!(
            "CLI:CONNECT: Cannot reach tscd at '{}': {}. Is the daemon running?",
            socket_path, e
        )
    })?;

    write_framed(&mut stream, &cmd).await?;

    let response = read_framed::<_, GhostResponse>(&mut stream)
        .await?
        .ok_or("CLI:EOF: Daemon closed connection without responding")?;

    print_response(response);
    Ok(())
}

// ── Command parsing ────────────────────────────────────────────────────────

fn parse_command(args: &[String]) -> Result<GhostCommand, String> {
    if args.len() < 2 {
        return Ok(GhostCommand::Ping);
    }

    match args[1].as_str() {
        "ping"    => Ok(GhostCommand::Ping),
        "init"    => Ok(GhostCommand::InitIdentity),
        "status"  => Ok(GhostCommand::Status),

        "recover" => {
            if args.len() < 3 {
                Err("Usage: tsc-cli recover \"<24 mnemonic words>\"".into())
            } else {
                Ok(GhostCommand::RecoverIdentity {
                    mnemonic: args[2..].join(" "),
                })
            }
        }

        "resolve" => {
            if args.len() < 3 {
                Err("Usage: tsc-cli resolve <GHOST_ID>".into())
            } else {
                Ok(GhostCommand::Resolve { ghost_id: args[2].clone() })
            }
        }

        "connect" => {
            if args.len() < 3 {
                Err("Usage: tsc-cli connect <GHOST_ID>".into())
            } else {
                Ok(GhostCommand::Connect { ghost_id: args[2].clone() })
            }
        }

        "send" => {
            if args.len() < 4 {
                Err("Usage: tsc-cli send <GHOST_ID> \"<message>\"".into())
            } else {
                Ok(GhostCommand::SendMessage {
                    target_id: args[2].clone(),
                    content:   args[3..].join(" "),
                })
            }
        }

        "spawn" => {
            if args.len() < 3 {
                Err("Usage: tsc-cli spawn <IMAGE_HASH> [VAULT_ID]".into())
            } else {
                Ok(GhostCommand::SpawnGhost {
                    image_hash: args[2].clone(),
                    vault_id:   args.get(3).cloned(),
                })
            }
        }

        "list"   => Ok(GhostCommand::ListGhosts),

        "stop" => {
            if args.len() < 3 {
                Err("Usage: tsc-cli stop <GHOST_ID>".into())
            } else {
                Ok(GhostCommand::StopGhost { ghost_id: args[2].clone() })
            }
        }

        "rotate-key" => {
            // Read from env — never stored in daemon memory
            let mnemonic = std::env::var("TSC_MNEMONIC")
                .unwrap_or_default();
            if mnemonic.trim().is_empty() {
                return Err(
                    "Set TSC_MNEMONIC=\"word1 ... word24\" before running rotate-key".into()
                );
            }
            Ok(GhostCommand::RotateKey { mnemonic: mnemonic.trim().to_string() })
        }

        "connect-direct" => {
            if args.len() < 3 {
                Err("Usage: tsc-cli connect-direct <IP:PORT>".into())
            } else {
                Ok(GhostCommand::ConnectDirect { addr: args[2].clone() })
            }
        }

        "send-direct" => {
            if args.len() < 4 {
                Err("Usage: tsc-cli send-direct <IP:PORT> \"<message>\"".into())
            } else {
                Ok(GhostCommand::SendDirect {
                    addr:    args[2].clone(),
                    content: args[3..].join(" "),
                })
            }
        }

        "help" | "--help" | "-h" => {
            print_help();
            std::process::exit(0);
        }

        other => Err(format!(
            "CLI:UNKNOWN_CMD: '{}'. Run 'tsc-cli help' for usage.",
            other
        )),
    }
}

// ── Response printing ──────────────────────────────────────────────────────

fn print_response(resp: GhostResponse) {
    match resp {
        GhostResponse::Ok(msg) => println!("[+] {}", msg),

        GhostResponse::Err(e) => eprintln!("[!] Error: {}", e),

        GhostResponse::Mnemonic(words) => {
            println!();
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("  SOVEREIGN IDENTITY INITIALIZED");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!();
            println!("  CRITICAL: Write down these 24 words and store");
            println!("  them securely offline. This is your Master Seed.");
            println!("  If you lose it, your identity is unrecoverable.");
            println!();
            // Print in 4 columns of 6
            for (i, word) in words.iter().enumerate() {
                print!("  {:2}. {:<12}", i + 1, word);
                if (i + 1) % 4 == 0 { println!(); }
            }
            println!();
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        }

        GhostResponse::Status(s) => print_status(s),

        GhostResponse::Resolved { ghost_id, addr } => {
            println!("[+] Resolved: {} → {}", ghost_id, addr);
        }

        GhostResponse::LinkEstablished { remote_id, addr } => {
            println!("[+] GSP Link Active: {} @ {}", remote_id, addr);
        }

        GhostResponse::DirectLinkEstablished { remote_id, addr } => {
            println!("[+] GSP Direct Link: {} @ {}", remote_id, addr);
            if remote_id == "unverified" {
                eprintln!("[~] Peer is in ephemeral mode — no KERI verification performed.");
            }
        }

        GhostResponse::MessageSent { target_id } => {
            println!("[+] Message delivered to {}", target_id);
        }

        GhostResponse::GhostSpawned { pid, virtual_ip } => {
            println!("[+] Ghost running: PID={} IP={}", pid, virtual_ip);
        }

        GhostResponse::GhostList(ghosts) => {
            if ghosts.is_empty() {
                println!("[*] No Ghosts currently running.");
            } else {
                println!("{:<20} {:>8}  {:<24} {}", "GHOST_ID", "PID", "VIRTUAL_IP", "UPTIME");
                for g in ghosts {
                    println!(
                        "{:<20} {:>8}  {:<24} {}s",
                        &g.ghost_id[..20.min(g.ghost_id.len())],
                        g.pid,
                        g.virtual_ip,
                        g.uptime_secs
                    );
                }
            }
        }

        GhostResponse::GhostStopped { ghost_id } => {
            println!("[+] Ghost {} stopped.", ghost_id);
        }

        GhostResponse::KeyRotated { new_public_key } => {
            println!("[+] Key rotated. New public key: {}", new_public_key);
        }
    }
}

fn print_status(s: DaemonStatus) {
    let vault_str = match s.vault_state {
        VaultState::Unlocked  => "Unlocked ✓",
        VaultState::Locked    => "Locked ✗",
        VaultState::Ephemeral => "Ephemeral (no vault)",
    };
    println!();
    println!("  GhostID  : {}", s.ghost_id);
    println!("  Vault    : {}", vault_str);
    println!("  Peers    : {}", s.peer_count);
    println!("  Ghosts   : {}", s.active_ghosts);
    println!("  Uptime   : {}s", s.uptime_secs);
    println!();
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Resolves the daemon socket path.
///
/// Matches the resolution logic in `tscd/src/main.rs`.
fn resolve_socket_path() -> String {
    if let Some(runtime_dir) = dirs::runtime_dir() {
        let path = runtime_dir.join("tsc").join("tscd.sock");
        if path.exists() {
            return path.to_string_lossy().into_owned();
        }
    }
    "/tmp/tscd.sock".to_string()
}

fn print_help() {
    println!("tsc-cli — Standalone Complex Controller");
    println!();
    println!("USAGE:");
    println!("  tsc-cli <COMMAND> [ARGS]");
    println!();
    println!("IDENTITY");
    println!("  ping                            Heartbeat check");
    println!("  init                            Create a new sovereign identity");
    println!("  recover \"<mnemonic>\"            Restore identity from 24-word seed");
    println!("  status                          Show daemon status");
    println!("  rotate-key                      Rotate signing key (KERI) — needs TSC_MNEMONIC");
    println!();
    println!("NETWORKING (DHT-resolved)");
    println!("  resolve <GHOST_ID>              Resolve a GhostID to IP:port via DHT");
    println!("  connect <GHOST_ID>              Establish a GSP link via DHT");
    println!("  send    <GHOST_ID> <msg>        Send a message via DHT resolution");
    println!();
    println!("NETWORKING (direct IP — bypasses DHT)");
    println!("  connect-direct <IP:PORT>        GSP HELLO handshake to explicit address");
    println!("  send-direct    <IP:PORT> <msg>  Send a message to explicit address");
    println!();
    println!("GHOST RUNTIME (Phase 3 — stubs)");
    println!("  spawn <IMAGE_HASH> [VAULT]      Spawn a Ghost-Box");
    println!("  list                            List running Ghosts");
    println!("  stop  <GHOST_ID>                Stop a running Ghost");
    println!();
    println!("  help                            Show this message");
}
