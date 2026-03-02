//! Legacy protocol bridging to GSP streams.
//!
//! This module maps TCP traffic from a Ghost's internal port to a GSP Stream ID,
//! allowing existing applications inside a Ghost-Box to communicate through the Shell.
//!
//! # Phase 3.3 Implementation Checklist
//!
//! - [ ] Listen on `10.ghost.0.1:<port>` (Shell side of veth)
//! - [ ] Accept TCP connections from Ghost workloads
//! - [ ] Wrap bytes in `GspFrame::new(MsgType::Data, ...)` with stream_id header
//! - [ ] Forward frames to the appropriate remote peer via `GspConnection`
//! - [ ] Reverse path: incoming GSP Data frames demuxed back to Ghost TCP socket
//!
//! See: RFC-007 §7.2, ROADMAP.md Phase 3.3

use tokio::net::TcpStream;
use tsc_net::gsp::{GspFrame, MsgType};

/// Maps legacy TCP application traffic into GSP Data Plane streams.
pub struct GhostBridge {
    /// The GhostID this bridge serves.
    pub ghost_id: String,
}

impl GhostBridge {
    /// Forwards bytes from a local TCP socket into a GSP Data frame.
    ///
    /// **Phase 3.3 stub** — framing logic is present but transmission is not wired.
    /// `stream_id` will be used to multiplex multiple ports per connection.
    pub async fn handle_legacy_traffic(&self, local_socket: TcpStream, stream_id: u16) {
        let mut buf = vec![0u8; 4096];

        // stream_id will map to a QUIC stream once Phase 3.3 is wired
        let _stream_id = stream_id;

        while let Ok(n) = local_socket.try_read(&mut buf) {
            if n == 0 { break; }

            let _frame = GspFrame::new(
                MsgType::Data,
                buf[..n].to_vec(),
            );

            // TODO(Phase 3.3): send _frame over the appropriate GspConnection
        }
    }
}
