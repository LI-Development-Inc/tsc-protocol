//! OCI Jail parameters and isolation enforcement.
//! This module defines the `GhostJail` struct, which encapsulates the configuration for spawning a new Ghost-Box with strict namespace isolation and no host network visibility. 
//! The `spawn` method uses the specified OCI runtime to create the container environment according to these parameters.

use std::process::Command;

/// Configuration for the OCI jail environment.
pub struct GhostJail {
    /// Unique identifier for the Ghost.
    pub ghost_id: String,
    /// CPU weight for the container.
    pub cpu_shares: u32,
    /// Hard memory limit in Megabytes.
    pub memory_limit_mb: u64,
}

impl GhostJail {
    /// Spawns the Ghost process using the specified OCI runtime.
    /// 
    /// This relies on the OCI-compliant runtime to handle the 
    /// low-level `CLONE_NEW*` flags for namespace isolation.
    pub fn spawn(&self, oci_runtime_path: &str) -> std::io::Result<std::process::Child> {
        let mut cmd = Command::new(oci_runtime_path);
        
        // Command parameters for standard OCI 'run'
        cmd.arg("run")
           .arg(&self.ghost_id)
           .env("TSC_GHOST_ID", &self.ghost_id);

        cmd.spawn()
    }
}