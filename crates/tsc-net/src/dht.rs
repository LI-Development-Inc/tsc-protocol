//! DHT-based discovery for GhostID-to-IP mapping.
//! This module handles the encryption and serialization of location records 
//! to be stored in the libp2p Kademlia DHT.

//! DHT-based discovery for GhostID-to-IP mapping.
use serde::{Deserialize, Serialize};
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, aead::Aead};
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use rand::Rng;

/// The Coordinate Blob stores an encrypted IP address and metadata.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CoordinateBlob {
    /// The encrypted IP address and timestamp.
    pub encrypted_data: Vec<u8>,
    /// The nonce used for AES-GCM encryption.
    pub nonce: [u8; 12],
}

/// The RawCoordinate struct is the plaintext representation of a DHT record.
#[derive(Serialize, Deserialize, Debug)]
struct RawCoordinate {
    /// The IP address of the Ghost node.
    pub addr: SocketAddr,
    /// The timestamp when this record was created (for anti-stale).
    pub timestamp: u64,
}

/// The GhostDiscovery struct manages encoding and decoding of DHT records.
#[derive(Debug, Clone)]
pub struct GhostDiscovery {
    /// The local GhostID used for identity verification.
    pub local_id: String,
    /// Key used to encrypt DHT records so only authorized peers can see your IP.
    pub storage_key: [u8; 32], 
}

impl GhostDiscovery {
    /// Initializes discovery with a local ID and a storage key.
    pub fn new(local_id: String, storage_key: [u8; 32]) -> Self {
        Self { local_id, storage_key }
    }

    /// Encrypts the local IP address into a CoordinateBlob for libp2p.
    pub fn encode_coordinate(&self, addr: SocketAddr) -> Vec<u8> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let raw = RawCoordinate { addr, timestamp };
        let plaintext = bincode::serialize(&raw).expect("Serialization failed");

        let key = Key::<Aes256Gcm>::from_slice(&self.storage_key);
        let cipher = Aes256Gcm::new(key);
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill(&mut nonce_bytes);

        let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_ref())
            .expect("Encryption failed");

        let blob = CoordinateBlob { encrypted_data: ciphertext, nonce: nonce_bytes };
        bincode::serialize(&blob).expect("Blob serialization failed")
    }

    /// Decodes a blob retrieved from the DHT back into a SocketAddr.
    pub fn decode_coordinate(&self, bytes: &[u8]) -> Option<SocketAddr> {
        let blob: CoordinateBlob = bincode::deserialize(bytes).ok()?;
        let key = Key::<Aes256Gcm>::from_slice(&self.storage_key);
        let cipher = Aes256Gcm::new(key);

        let pt = cipher.decrypt(Nonce::from_slice(&blob.nonce), blob.encrypted_data.as_ref()).ok()?;
        let raw: RawCoordinate = bincode::deserialize(&pt).ok()?;
        
        // Anti-stale: ignore records older than 1 hour
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        if now.saturating_sub(raw.timestamp) > 3600 { return None; }
        
        Some(raw.addr)
    }
}