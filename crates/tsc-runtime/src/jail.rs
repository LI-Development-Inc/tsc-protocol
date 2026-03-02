//! OCI Jail parameters and isolation enforcement.
//!
//! This module will implement `GhostJail` — the namespace isolation layer for
//! Ghost-Box workloads.
//!
//! # Phase 3.1 Implementation Checklist
//!
//! - [ ] Replace `Command::new(oci_runtime)` stub with real `clone(2)` + namespace flags:
//!       `CLONE_NEWNET | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWUTS`
//! - [ ] Assign virtual IP from `10.ghost.0.0/16` (ADR-006)
//! - [ ] Create veth pair: `veth0` in Ghost netns ↔ `veth1` in Shell netns
//! - [ ] Wire cgroups v2: `cpu.max`, `memory.high`, `memory.max`
//! - [ ] Return `GhostHandle { pid, virtual_ip, cgroup_path }` to the daemon registry
//!
//! See: RFC-004 §4.1, ROADMAP.md Phase 3.1

use std::process::Command;

/// Configuration for the OCI jail environment.
pub struct GhostJail {
    /// Unique identifier for the Ghost.
    pub ghost_id: String,
    /// CPU weight for the container (cgroups v2 `cpu.weight`).
    pub cpu_shares: u32,
    /// Hard memory limit in MiB (cgroups v2 `memory.max`).
    pub memory_limit_mb: u64,
}

impl GhostJail {
    /// Spawns the Ghost process using the specified OCI runtime.
    ///
    /// **Phase 3.1 stub** — delegates to `oci_runtime_path run <ghost_id>`.
    /// Will be replaced by direct `clone(2)` namespace setup.
    pub fn spawn(&self, oci_runtime_path: &str) -> std::io::Result<std::process::Child> {
        let mut cmd = Command::new(oci_runtime_path);
        cmd.arg("run")
           .arg(&self.ghost_id)
           .env("TSC_GHOST_ID", &self.ghost_id);
        cmd.spawn()
    }
}
