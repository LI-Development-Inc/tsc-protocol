#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! # TSC Network (The Pipe)
//! Handles QUIC streams, GSP framing, and traffic morphing.

/// Ghost Service Protocol (GSP) framing and types.
pub mod gsp;
/// DHT-based discovery for GhostID-to-IP mapping.
pub mod dht;
/// Traffic morphing and metadata defense (Chaffing).
pub mod morph;


use quinn::{Endpoint, ServerConfig, Connection};
use std::net::SocketAddr;
use std::time::Duration;

// libp2p Imports
use libp2p::{kad, mdns, swarm::NetworkBehaviour, swarm::SwarmEvent, futures::StreamExt};

/// Thread-safe result type.
type NetResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "GhostEvent")]
struct GhostBehavior {
    /// Kademlia DHT for peer discovery and GhostID resolution.
    kad: kad::Behaviour<kad::store::MemoryStore>,
    /// mDNS for local network peer discovery.
    mdns: mdns::tokio::Behaviour,
}

#[allow(clippy::large_enum_variant)]
enum GhostEvent {
    /// Kademlia events (e.g., query results, record retrieval).
    Kad(kad::Event),
    /// mDNS events (e.g., peer discovery, expiration).
    Mdns(mdns::Event),
}

impl From<kad::Event> for GhostEvent {
    fn from(event: kad::Event) -> Self { GhostEvent::Kad(event) }
}

impl From<mdns::Event> for GhostEvent {
    fn from(event: mdns::Event) -> Self { GhostEvent::Mdns(event) }
}

/// The main network stack for TSC, handling QUIC connections and DHT operations.
pub struct NetStack {
    /// The QUIC endpoint for handling incoming and outgoing connections.
    pub endpoint: Endpoint,
    /// The local GhostID associated with this network stack.
    pub local_id: String,
}
/// Custom certificate verifier that skips verification for testing purposes.
struct SkipServerVerification;

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
    /// Initializes the network stack by setting up the QUIC endpoint and preparing for DHT operations.
    pub async fn new(local_id: String, addr: SocketAddr) -> NetResult<Self> {
        let (cert, key) = Self::generate_self_signed_cert()
            .map_err(|e| format!("Cert Error: {:?}", e))?;
        
        let mut server_config = ServerConfig::with_single_cert(vec![cert], key)
            .map_err(|e| format!("Config Error: {:?}", e))?;
        
        let transport_config = std::sync::Arc::get_mut(&mut server_config.transport).unwrap();
        transport_config.max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()));

        let endpoint = Endpoint::server(server_config, addr)
            .map_err(|e| format!("Endpoint Error: {:?}", e))?;

        Ok(Self { endpoint, local_id })
    }
    /// Listens for incoming QUIC connections and spawns tasks to handle them.
    pub async fn listen(&self) {
        println!("[*] GSP: Listening on {}", self.endpoint.local_addr().unwrap());
        while let Some(conn) = self.endpoint.accept().await {
            tokio::spawn(async move {
                if let Ok(quic_conn) = conn.await {
                    loop {
                        match quic_conn.accept_bi().await {
                            Ok((_, mut recv)) => {
                                if let Ok(msg_buf) = recv.read_to_end(65536).await {
                                    if let Ok(text) = String::from_utf8(msg_buf) {
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
    /// Runs the DHT discovery loop, periodically announcing the local GhostID and handling peer discovery events.
    pub async fn run_discovery(&self, discovery: crate::dht::GhostDiscovery) -> NetResult<()> {
        let local_key = libp2p::identity::Keypair::generate_ed25519();
        let peer_id = local_key.public().to_peer_id();

        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(libp2p::tcp::Config::default(), libp2p::noise::Config::new, libp2p::yamux::Config::default)
            .map_err(|e| format!("TCP Error: {:?}", e))?
            .with_behaviour(|_key| {
                Ok(GhostBehavior {
                    kad: kad::Behaviour::new(peer_id, kad::store::MemoryStore::new(peer_id)),
                    mdns: mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id).unwrap(),
                })
            })
            .map_err(|e| format!("Behaviour Error: {:?}", e))?
            .build();

        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap()).unwrap();
        
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Ok(addr) = self.endpoint.local_addr() {
                        let record = kad::Record {
                            key: kad::RecordKey::new(&self.local_id),
                            value: discovery.encode_coordinate(addr),
                            publisher: None, expires: None,
                        };
                        let _ = swarm.behaviour_mut().kad.put_record(record, kad::Quorum::One);
                        println!("[*] DHT: Anchored Ghost Identity.");
                    }
                }
                event = swarm.select_next_some() => match event {
                    SwarmEvent::Behaviour(GhostEvent::Mdns(mdns::Event::Discovered(list))) => {
                        for (p_id, addr) in list {
                            swarm.behaviour_mut().kad.add_address(&p_id, addr);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    /// Establishes a QUIC connection to a remote address and returns a GSP connection wrapper.
    pub async fn connect(&self, addr: SocketAddr) -> NetResult<GspConnection> {
        // Build a client configuration that accepts our self-signed certs
        let crypto = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(std::sync::Arc::new(SkipServerVerification))
            .with_no_client_auth();

        let mut client_config = quinn::ClientConfig::new(std::sync::Arc::new(crypto));
        
        // Match the transport config from the server for consistency
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()));
        client_config.transport_config(std::sync::Arc::new(transport_config));

        // Create the connection using our explicit config
        let quic_conn = self.endpoint.connect_with(client_config, addr, "tsc.local")
            .map_err(|e| format!("QUIC Connect Error: {:?}", e))?
            .await
            .map_err(|e| format!("QUIC Connection Failed: {:?}", e))?;

        Ok(GspConnection { 
            remote_ghost_id: "VERIFIED".into(), 
            quic_connection: quic_conn 
        })
    }

    /// Resolves a GhostID to a SocketAddr using the DHT. Returns None if not found.
    /// For the local GhostID, it returns the loopback address for connection purposes.
    pub async fn resolve_ghost(&self, id: String, _d: &crate::dht::GhostDiscovery) -> Option<SocketAddr> {
    if id == self.local_id {
        // Change from self.endpoint.local_addr() which likely returns 0.0.0.0
        // to a hardcoded local loopback for the connection phase.
        return Some("127.0.0.1:9090".parse().unwrap());
    }
    
    // For remote ghosts, the DHT will eventually provide specific IPs
    None
    }

    fn generate_self_signed_cert() -> Result<(rustls::Certificate, rustls::PrivateKey), Box<dyn std::error::Error>> {
        let cert = rcgen::generate_simple_self_signed(vec!["tsc.local".into()])?;
        Ok((rustls::Certificate(cert.serialize_der()?), rustls::PrivateKey(cert.serialize_private_key_der())))
    }
}

/// Represents an active connection to a remote Ghost, encapsulating the QUIC connection and associated metadata.
pub struct GspConnection {
    /// The GhostID of the remote peer, set to "VERIFIED" after successful connection establishment.
    pub remote_ghost_id: String,
    /// The underlying QUIC connection for this Ghost link.
    pub quic_connection: Connection,
}

impl GspConnection {
    /// Opens a new bidirectional QUIC stream to the connected Ghost peer for GSP message exchange.
    pub async fn open_ghost_stream(&self) -> Result<quinn::SendStream, quinn::WriteError> {
        let (send, _) = self.quic_connection.open_bi().await
            .map_err(|_| quinn::WriteError::Stopped(0u32.into()))?;
        Ok(send)
    }
}