#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! # TSC Network (The Pipe)
//! QUIC transport, GSP framing, DHT discovery, and traffic morphing.

/// Ghost Service Protocol (GSP) framing and types.
pub mod gsp;
/// DHT-based discovery for GhostID-to-IP mapping.
pub mod dht;
/// Traffic morphing and metadata defence (Chaffing).
pub mod morph;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use libp2p::{
    futures::StreamExt,
    kad::{self, store::RecordStore, QueryId},
    mdns,
    swarm::{NetworkBehaviour, SwarmEvent},
};
use quinn::{Connection, Endpoint, ServerConfig};
use tokio::io::AsyncWriteExt;
use tokio::sync::{oneshot, Mutex, RwLock};

/// Thread-safe result type.
type NetResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

// ── libp2p behaviour ──────────────────────────────────────────────────────

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "GhostEvent")]
struct GhostBehavior {
    /// Kademlia DHT for GhostID resolution and announcement.
    kad: kad::Behaviour<kad::store::MemoryStore>,
    /// mDNS for automatic local-network peer discovery.
    mdns: mdns::tokio::Behaviour,
}

#[allow(clippy::large_enum_variant)]
enum GhostEvent {
    /// Kademlia DHT events.
    Kad(kad::Event),
    /// mDNS discovery events.
    Mdns(mdns::Event),
}

impl From<kad::Event> for GhostEvent {
    fn from(e: kad::Event) -> Self { GhostEvent::Kad(e) }
}
impl From<mdns::Event> for GhostEvent {
    fn from(e: mdns::Event) -> Self { GhostEvent::Mdns(e) }
}

// ── Channel types ─────────────────────────────────────────────────────────

/// A one-shot reply channel for a DHT lookup result.
type PendingLookup = oneshot::Sender<Option<SocketAddr>>;

/// A request sent into the discovery loop to look up a GhostID.
pub struct LookupRequest {
    /// GhostID bytes to query.
    key: Vec<u8>,
    /// Where to send the result.
    reply: PendingLookup,
}

/// Sent into the discovery loop to trigger an immediate re-announcement.
/// Used after `init` creates a new persistent identity.
pub struct ReannounceRequest {
    /// The new GhostID to announce.
    pub ghost_id: String,
    /// Pre-encoded CoordinateBlob value.
    pub value: Vec<u8>,
}

// ── NetStack ──────────────────────────────────────────────────────────────

/// The main network stack: QUIC endpoint + DHT query dispatch.
pub struct NetStack {
    /// QUIC endpoint for GSP connections.
    pub endpoint: Endpoint,
    /// The current local GhostID (updated live when identity changes).
    pub local_id: Arc<RwLock<String>>,
    /// The local KERI Inception Event — sent in every GSP HELLO frame.
    /// `None` in ephemeral mode (no vault); HELLO is skipped for loopback
    /// self-connections in that case.
    pub local_ixn: Arc<RwLock<Option<tsc_crypto::keri::InceptionEvent>>>,
    /// Sender for DHT lookup requests into the discovery task.
    lookup_tx: tokio::sync::mpsc::Sender<LookupRequest>,
    /// Sender for re-announcement requests (e.g. after `init`).
    reannounce_tx: tokio::sync::mpsc::Sender<ReannounceRequest>,
    /// In-flight query map: QueryId → reply sender.
    pending: Arc<Mutex<HashMap<QueryId, PendingLookup>>>,
}

// ── TLS cert verifier (dev builds only, ADR-008) ──────────────────────────

#[cfg(feature = "dev")]
struct SkipServerVerification;

#[cfg(feature = "dev")]
impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

impl NetStack {
    /// Creates the QUIC endpoint and internal channels.
    ///
    /// Returns `(NetStack, lookup_rx, reannounce_rx)`.
    /// Pass both receivers to [`run_discovery`].
    pub async fn new(
        local_id:    String,
        addr:        SocketAddr,
    ) -> NetResult<(
        Self,
        tokio::sync::mpsc::Receiver<LookupRequest>,
        tokio::sync::mpsc::Receiver<ReannounceRequest>,
    )> {
        let (cert, key) = Self::generate_self_signed_cert()?;

        let mut server_config = ServerConfig::with_single_cert(vec![cert], key)
            .map_err(|e| format!("TLS config error: {:?}", e))?;
        Arc::get_mut(&mut server_config.transport)
            .unwrap()
            .max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()));

        let endpoint = Endpoint::server(server_config, addr)
            .map_err(|e| format!("QUIC endpoint error: {:?}", e))?;

        let (lookup_tx,     lookup_rx)     = tokio::sync::mpsc::channel(64);
        let (reannounce_tx, reannounce_rx) = tokio::sync::mpsc::channel(8);
        let pending   = Arc::new(Mutex::new(HashMap::new()));
        let local_id  = Arc::new(RwLock::new(local_id));
        let local_ixn = Arc::new(RwLock::new(None));

        Ok((
            Self { endpoint, local_id, local_ixn, lookup_tx, reannounce_tx, pending },
            lookup_rx,
            reannounce_rx,
        ))
    }

    /// Returns a clone of the re-announce sender so callers (e.g. `ipc.rs`)
    /// can trigger an immediate DHT announcement after identity changes.
    pub fn reannounce_tx(&self) -> tokio::sync::mpsc::Sender<ReannounceRequest> {
        self.reannounce_tx.clone()
    }

    /// Accepts incoming QUIC connections.
    ///
    /// For each connection, the first QUIC stream is expected to carry
    /// the peer's `GspHello` Control frame.  The local HELLO is sent back
    /// on the same stream before accepting application `Data` frames.
    ///
    /// If no `local_ixn` is set (ephemeral mode) the HELLO exchange is
    /// skipped and the peer is labelled `"unverified"`.
    pub async fn listen(&self) {
        let local_id  = self.local_id.clone();
        let local_ixn = self.local_ixn.clone();
        println!("[*] GSP: Listening on {}", self.endpoint.local_addr().unwrap());
        while let Some(conn) = self.endpoint.accept().await {
            let local_id  = local_id.clone();
            let local_ixn = local_ixn.clone();
            tokio::spawn(async move {
                if let Ok(quic_conn) = conn.await {
                    // ── GSP HELLO handshake ───────────────────────────────
                    // First bi-stream: exchange HELLO frames, then close.
                    let peer_ghost_id = match quic_conn.accept_bi().await {
                        Ok((mut send, mut recv)) => {
                            // Read peer's HELLO
                            let buf = recv.read_to_end(65536).await.unwrap_or_default();
                            let peer_id = if let Some(hello) = gsp::decode_hello(&buf) {
                                match gsp::verify_hello(&hello) {
                                    Ok(id) => {
                                        println!("[+] GSP: Peer verified: {}…",
                                            &id[..16.min(id.len())]);
                                        id
                                    }
                                    Err(reason) => {
                                        eprintln!("[!] GSP: KERI verification failed: {}", reason);
                                        "unverified".into()
                                    }
                                }
                            } else {
                                "unverified".into()
                            };

                            // Send our HELLO back
                            let gid = local_id.read().await.clone();
                            let ixn = local_ixn.read().await.clone();
                            if let Some(inception) = ixn {
                                let hello = gsp::GspHello { ghost_id: gid, inception };
                                let _ = send.write_all(&gsp::encode_hello(&hello)).await;
                            }
                            let _ = send.finish().await;
                            peer_id
                        }
                        Err(_) => return,
                    };

                    // ── Application data frames ───────────────────────────
                    loop {
                        match quic_conn.accept_bi().await {
                            Ok((_, mut recv)) => {
                                if let Ok(buf) = recv.read_to_end(65536).await {
                                    if let Some(frame) = gsp::GspFrame::from_bytes(&buf) {
                                        match frame.msg_type {
                                            gsp::MsgType::Chaff => { /* silently discard */ }
                                            gsp::MsgType::Data => {
                                                if let Ok(text) = String::from_utf8(frame.payload) {
                                                    println!("\n[+] GSP INGRESS [{}…]: {}",
                                                        &peer_ghost_id[..16.min(peer_ghost_id.len())],
                                                        text);
                                                }
                                            }
                                            _ => {
                                                // Plain bytes fallback (pre-framing messages)
                                                if let Ok(text) = String::from_utf8(buf.clone()) {
                                                    println!("\n[+] GSP INGRESS: {}", text);
                                                }
                                            }
                                        }
                                    } else if let Ok(text) = String::from_utf8(buf) {
                                        // Legacy plain-text messages (no frame wrapper)
                                        println!("\n[+] GSP INGRESS: {}", text);
                                    }
                                }
                            }
                            Err(_) => break,
                        }
                    }
                }
            });
        }
    }

    /// Runs the DHT discovery loop.
    ///
    /// - Announces the local GhostID immediately on start, then every 900 s.
    /// - Handles lookup requests from [`resolve_ghost`].
    /// - Handles re-announce requests from `ipc.rs` after identity changes.
    /// - Processes Kademlia query results.
    pub async fn run_discovery(
        &self,
        discovery:    crate::dht::GhostDiscovery,
        mut lookup_rx:     tokio::sync::mpsc::Receiver<LookupRequest>,
        mut reannounce_rx: tokio::sync::mpsc::Receiver<ReannounceRequest>,
    ) -> NetResult<()> {
        let local_key = libp2p::identity::Keypair::generate_ed25519();
        let peer_id   = local_key.public().to_peer_id();

        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default(),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )
            .map_err(|e| format!("TCP error: {:?}", e))?
            .with_behaviour(|_| Ok(GhostBehavior {
                kad:  kad::Behaviour::new(peer_id, kad::store::MemoryStore::new(peer_id)),
                mdns: mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id).unwrap(),
            }))
            .map_err(|e| format!("Behaviour error: {:?}", e))?
            .build();

        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap()).unwrap();

        let pending = Arc::clone(&self.pending);
        let local_id_lock = Arc::clone(&self.local_id);

        // Announce every 900 s (RFC-005); first tick fires immediately in the loop.
        let mut announce_interval = tokio::time::interval(Duration::from_secs(900));

        loop {
            tokio::select! {
                // ── Periodic self-announcement ─────────────────────────────
                _ = announce_interval.tick() => {
                    if let Ok(addr) = self.endpoint.local_addr() {
                        let current_id = local_id_lock.read().await.clone();
                        Self::do_announce(
                            &mut swarm, &current_id, &discovery, addr,
                        );
                    }
                }

                // ── Re-announce after identity change ──────────────────────
                Some(req) = reannounce_rx.recv() => {
                    if let Ok(addr) = self.endpoint.local_addr() {
                        let real_addr = if addr.ip().is_unspecified() {
                            SocketAddr::new("127.0.0.1".parse().unwrap(), addr.port())
                        } else {
                            addr
                        };
                        // Store directly in the local Kademlia store so
                        // get_record resolves immediately without peers.
                        let record = kad::Record {
                            key:       kad::RecordKey::new(&req.ghost_id.as_bytes()),
                            value:     req.value,
                            publisher: Some(peer_id),
                            expires:   None,
                        };
                        let _ = swarm.behaviour_mut().kad.store_mut().put(record);
                        println!("[*] DHT: Re-announced as {}.", &req.ghost_id[..16]);
                        let _ = real_addr; // used above in encode_coordinate
                    }
                }

                // ── Lookup request from resolve_ghost ──────────────────────
                Some(req) = lookup_rx.recv() => {
                    let current_id = local_id_lock.read().await;
                    let current_id_bytes = current_id.as_bytes().to_vec();
                    drop(current_id);

                    // Local shortcut for the current identity
                    if req.key == current_id_bytes {
                        let addr = self.endpoint.local_addr()
                            .map(|a| if a.ip().is_unspecified() {
                                SocketAddr::new("127.0.0.1".parse().unwrap(), a.port())
                            } else {
                                a
                            })
                            .ok();
                        let _ = req.reply.send(addr);
                    } else {
                        // Try Kademlia (local store first, then network)
                        let query_id = swarm
                            .behaviour_mut()
                            .kad
                            .get_record(kad::RecordKey::new(&req.key));
                        pending.lock().await.insert(query_id, req.reply);
                    }
                }

                // ── Swarm events ───────────────────────────────────────────
                event = swarm.select_next_some() => match event {
                    SwarmEvent::Behaviour(GhostEvent::Mdns(
                        mdns::Event::Discovered(list),
                    )) => {
                        for (pid, addr) in list {
                            swarm.behaviour_mut().kad.add_address(&pid, addr);
                            println!("[*] DHT: mDNS peer: {}", pid);
                        }
                    }

                    // Kademlia: record found
                    SwarmEvent::Behaviour(GhostEvent::Kad(
                        kad::Event::OutboundQueryProgressed {
                            id,
                            result: kad::QueryResult::GetRecord(Ok(
                                kad::GetRecordOk::FoundRecord(record),
                            )),
                            ..
                        },
                    )) => {
                        if let Some(reply) = pending.lock().await.remove(&id) {
                            let decoded = discovery.decode_coordinate(&record.record.value);
                            let _ = reply.send(decoded);
                        }
                    }

                    // Kademlia: not found or failed
                    SwarmEvent::Behaviour(GhostEvent::Kad(
                        kad::Event::OutboundQueryProgressed {
                            id,
                            result: kad::QueryResult::GetRecord(Err(_)),
                            ..
                        },
                    )) => {
                        if let Some(reply) = pending.lock().await.remove(&id) {
                            let _ = reply.send(None);
                        }
                    }

                    _ => {}
                }
            }
        }
    }

    /// Resolves a GhostID to a `SocketAddr` via the discovery loop.
    ///
    /// Times out after 10 seconds.
    pub async fn resolve_ghost(
        &self,
        id: String,
        _discovery: &crate::dht::GhostDiscovery,
    ) -> Option<SocketAddr> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let req = LookupRequest { key: id.into_bytes(), reply: reply_tx };

        if self.lookup_tx.send(req).await.is_err() {
            return None;
        }

        tokio::time::timeout(Duration::from_secs(10), reply_rx)
            .await
            .ok()
            .and_then(|r| r.ok())
            .flatten()
    }

    /// Connects to a remote QUIC endpoint and performs the GSP HELLO handshake.
    ///
    /// Sends the local `GspHello` on the first bi-directional stream, reads
    /// the responder's HELLO, and verifies it via KERI.
    ///
    /// Returns a `GspConnection` with `remote_ghost_id` set to the
    /// KERI-verified GhostID of the remote peer, or `"unverified"` if the
    /// responder is in ephemeral mode or the handshake fails gracefully.
    ///
    /// Returns `Err` only for hard transport failures.
    #[cfg(feature = "dev")]
    pub async fn connect(&self, addr: SocketAddr) -> NetResult<GspConnection> {
        let crypto = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();

        let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()));
        client_config.transport_config(Arc::new(transport));

        let quic_conn = self.endpoint
            .connect_with(client_config, addr, "tsc.local")
            .map_err(|e| format!("QUIC connect error: {:?}", e))?
            .await
            .map_err(|e| format!("QUIC connection failed: {:?}", e))?;

        // ── GSP HELLO handshake ───────────────────────────────────────────
        let remote_ghost_id = {
            let (mut send, mut recv) = quic_conn.open_bi().await
                .map_err(|e| format!("HELLO stream open failed: {:?}", e))?;

            // Send our HELLO
            let gid = self.local_id.read().await.clone();
            let ixn = self.local_ixn.read().await.clone();
            if let Some(inception) = ixn {
                let hello = gsp::GspHello { ghost_id: gid, inception };
                send.write_all(&gsp::encode_hello(&hello)).await
                    .map_err(|e| format!("HELLO send failed: {:?}", e))?;
            }
            send.finish().await
                .map_err(|e| format!("HELLO stream finish failed: {:?}", e))?;

            // Read and verify remote HELLO
            let buf = recv.read_to_end(65536).await.unwrap_or_default();
            if let Some(hello) = gsp::decode_hello(&buf) {
                match gsp::verify_hello(&hello) {
                    Ok(id) => {
                        println!("[+] GSP: Peer verified: {}…", &id[..16.min(id.len())]);
                        id
                    }
                    Err(reason) => {
                        eprintln!("[!] GSP: KERI verification failed: {}", reason);
                        "unverified".into()
                    }
                }
            } else {
                // Responder sent no HELLO (ephemeral mode) — accept anyway
                "unverified".into()
            }
        };

        Ok(GspConnection {
            remote_ghost_id,
            quic_connection: quic_conn,
        })
    }

    /// Puts a Kademlia record into the swarm and prints a log line.
    fn do_announce(
        swarm:      &mut libp2p::Swarm<GhostBehavior>,
        ghost_id:   &str,
        discovery:  &crate::dht::GhostDiscovery,
        addr:       SocketAddr,
    ) {
        let real_addr = if addr.ip().is_unspecified() {
            SocketAddr::new("127.0.0.1".parse().unwrap(), addr.port())
        } else {
            addr
        };
        let value = discovery.encode_coordinate(real_addr);
        let record = kad::Record {
            key:       kad::RecordKey::new(&ghost_id.as_bytes()),
            value,
            publisher: None,
            expires:   None,
        };
        let _ = swarm.behaviour_mut().kad.put_record(record, kad::Quorum::One);
        println!("[*] DHT: Announced {}.", &ghost_id[..16.min(ghost_id.len())]);
    }

    fn generate_self_signed_cert(
    ) -> Result<(rustls::Certificate, rustls::PrivateKey), Box<dyn std::error::Error + Send + Sync>>
    {
        let cert = rcgen::generate_simple_self_signed(vec!["tsc.local".into()])?;
        Ok((
            rustls::Certificate(cert.serialize_der()?),
            rustls::PrivateKey(cert.serialize_private_key_der()),
        ))
    }
}

/// An active GSP connection to a remote peer.
pub struct GspConnection {
    /// GhostID of the remote peer.
    pub remote_ghost_id: String,
    /// Underlying QUIC connection.
    pub quic_connection: Connection,
}

impl GspConnection {
    /// Opens a bidirectional QUIC stream for GSP message exchange.
    pub async fn open_ghost_stream(
        &self,
    ) -> Result<quinn::SendStream, quinn::WriteError> {
        let (send, _) = self
            .quic_connection
            .open_bi()
            .await
            .map_err(|_| quinn::WriteError::Stopped(0u32.into()))?;
        Ok(send)
    }
}
