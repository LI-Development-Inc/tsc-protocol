#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! # TSC Runtime (The Execution Domain)
//! Orchestrates isolated Ghost-Box environments and legacy protocol bridging.

/// Linux namespace and cgroup isolation logic.
pub mod jail;
/// OCI Runtime integration and P2P image swarming.
pub mod oci;
/// Bridge for mapping legacy TCP traffic to GSP streams.
pub mod bridge;

/// The runtime state of an active Ghost-Box.
pub struct GhostState {
    /// Process ID of the container leader.
    pub pid: u32,
    /// Internal IPv6 address assigned to the Ghost.
    pub virtual_ip: std::net::Ipv6Addr,
    /// Current operational status.
    pub status: GhostStatus,
}

/// Operational phases of a Ghost lifecycle.
#[derive(Debug, PartialEq)]
pub enum GhostStatus {
    /// Initializing the environment.
    Starting,
    /// Actively processing data.
    Running,
    /// In the process of moving to a different host Shell.
    Migrating,
    /// Process has exited or been killed.
    Terminated,
}