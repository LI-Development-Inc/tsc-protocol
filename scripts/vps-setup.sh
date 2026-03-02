#!/bin/bash
# =============================================================================
# TSC Protocol — VPS Peer Bootstrap Script
# =============================================================================
#
# Run this on the VPS to set it up as a Phase 2.2 test peer.
#
# Usage:
#   scp scripts/vps-setup.sh user@vps:~/
#   ssh user@vps "bash ~/vps-setup.sh"
#
# After running, the VPS will:
#   1. Have tscd installed and running
#   2. Print its GhostID — add this to your local .env.test as TSC_GHOST_B
#   3. Have port 9090 open for GSP (TCP + UDP)
#
# Firewall note:
#   The script assumes UFW or iptables is configured externally.
#   Open port 9090/tcp and 9090/udp on the VPS before running make test-p2.
# =============================================================================

set -euo pipefail

REPO_DIR="${HOME}/tsc-work"
LOG_FILE="/tmp/tscd-test.log"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  TSC VPS Peer Setup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── Step 1: Check Rust ────────────────────────────────────────────────────────
if ! command -v cargo &>/dev/null; then
    echo "[*] Installing Rust toolchain..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    echo "[✓] Rust: $(rustc --version)"
fi

# ── Step 2: Build ─────────────────────────────────────────────────────────────
if [ ! -d "$REPO_DIR" ]; then
    echo "[!] $REPO_DIR not found."
    echo "    Copy the project to the VPS first:"
    echo "    rsync -av tsc-work/ user@vps:~/tsc-work/"
    exit 1
fi

cd "$REPO_DIR"
echo "[*] Building (this takes a few minutes on first run)..."
cargo build 2>&1 | tail -5
echo "[✓] Build complete."

# ── Step 3: Generate or load identity ────────────────────────────────────────
CLI="./target/debug/tsc-cli"
DAEMON="./target/debug/tscd"

# Kill any existing daemon
pkill -x tscd 2>/dev/null || true
sleep 0.3

# Start daemon in ephemeral mode to get a GhostID
nohup $DAEMON >> "$LOG_FILE" 2>&1 &
disown
sleep 2

GHOST_ID=$($CLI status 2>/dev/null | grep "GhostID" | sed 's/.*: //' | tr -d '[:space:]')

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  VPS GhostID: $GHOST_ID"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Add to your local .env.test:"
echo "  export TSC_GHOST_B=\"$GHOST_ID\""
echo ""
echo "  Then on your local machine:"
echo "  source .env.test && make test-p2"
echo ""
echo "  Firewall: ensure port 9090/tcp and 9090/udp are open on this VPS."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── Step 4: Confirm GSP is listening ─────────────────────────────────────────
if ss -tlnp 2>/dev/null | grep -q ":9090"; then
    echo "[✓] GSP listening on :9090"
else
    echo "[~] GSP port not showing in ss output (may still be bound via QUIC/UDP)"
fi
