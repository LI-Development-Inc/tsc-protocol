//! OCI Bundle management and P2P image distribution.
//!
//! This module manages OCI bundle configuration and peer-to-peer image fetching.
//!
//! # Phase 3.2 Implementation Checklist
//!
//! - [ ] `GhostBundle::prepare_runtime_dir`: set up overlayfs (read-only base + tmpfs upper)
//! - [ ] `GhostBundle::write_config`: generate OCI `config.json` with TSC namespace spec
//! - [ ] `GhostFetcher::pull_from_swarm`: query DHT for image providers, pull via GSP
//! - [ ] BLAKE3 integrity check on each pulled layer
//! - [ ] Mount vault ref as read-only bind mount at `/vault` inside bundle
//!
//! See: RFC-004 §4.2, ROADMAP.md Phase 3.2

use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use std::fs;

/// An OCI Bundle ready to pass to the runtime (youki/crun).
pub struct GhostBundle {
    /// Host path to the bundle directory.
    pub bundle_path: PathBuf,
    /// Parsed OCI configuration.
    pub config: GhostConfig,
}

/// OCI `config.json` structure for TSC Ghost-Boxes.
#[derive(Serialize, Deserialize)]
pub struct GhostConfig {
    /// OCI specification version.
    pub version: String,
    /// Root filesystem configuration.
    pub root: Root,
    /// Linux-specific isolation settings.
    pub linux: LinuxConstraints,
}

/// Root filesystem specification.
#[derive(Serialize, Deserialize)]
pub struct Root {
    /// Path to the rootfs (relative to bundle_path).
    pub path: String,
    /// Whether the root filesystem is read-only.
    pub readonly: bool,
}

/// Linux namespace and resource constraint settings.
#[derive(Serialize, Deserialize)]
pub struct LinuxConstraints {
    /// Active namespace types for this bundle.
    pub namespaces: Vec<Namespace>,
}

/// A Linux namespace entry in the OCI config.
#[derive(Serialize, Deserialize)]
pub struct Namespace {
    /// Namespace type string as per OCI spec ("network", "pid", "mount", "user", etc.)
    pub r#type: String,
}

impl GhostBundle {
    /// Creates the bundle directory.
    ///
    /// **Phase 3.2 stub** — will set up overlayfs and generate `config.json`.
    pub fn prepare_runtime_dir(&self) -> std::io::Result<()> {
        fs::create_dir_all(&self.bundle_path)?;
        // TODO(Phase 3.2): mount overlayfs: ro base layer + tmpfs upper
        // TODO(Phase 3.2): write config.json via serde_json
        Ok(())
    }
}

/// Pulls OCI layers directly from TSC swarm peers via GSP.
pub struct GhostFetcher {
    /// BLAKE3 hash of the target OCI image (used for DHT lookup and integrity check).
    pub target_image_hash: String,
}

impl GhostFetcher {
    /// Initiates a BitTorrent-style pull of OCI layers from the TSC swarm.
    ///
    /// **Phase 3.2 stub** — will query the DHT for providers and pull via GspConnection.
    pub async fn pull_from_swarm(&self) -> Result<(), String> {
        // TODO(Phase 3.2): query DHT for providers of self.target_image_hash
        // TODO(Phase 3.2): open GspConnection to each provider, pull layers
        // TODO(Phase 3.2): verify each layer with BLAKE3(layer) == expected_hash
        Ok(())
    }
}
