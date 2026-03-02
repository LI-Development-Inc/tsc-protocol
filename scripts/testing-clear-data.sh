#!/bin/bash
# =============================================================================
# TSC Protocol — Clear Test State
# =============================================================================
# Superseded by: make clean-state
#
# This script clears vault and IEL data for a fresh test cycle.
# Use make targets instead when available:
#
#   make clean-state     # stop daemon + delete vault + IEL
#   make reset-iel       # delete IEL only (keeps vault)
#   make show-iel        # inspect IEL contents
#   make show-vault      # inspect vault metadata
# =============================================================================

set -euo pipefail

VAULT="${XDG_DATA_HOME:-$HOME/.local/share}/tsc/vault.bin"
IEL="${XDG_DATA_HOME:-$HOME/.local/share}/tsc/iel.jsonl"

echo "[*] Wiping TSC Protocol state..."

# Stop any running daemon
if pkill -x tscd 2>/dev/null; then
    echo "[✓] tscd stopped."
    sleep 0.3
else
    echo "[~] tscd was not running."
fi

# Remove persistent data
removed=0
if rm -f "$VAULT" 2>/dev/null; then
    echo "[✓] Vault removed: $VAULT"
    removed=$((removed+1))
fi
if rm -f "$IEL" 2>/dev/null; then
    echo "[✓] IEL removed: $IEL"
    removed=$((removed+1))
fi

if [ $removed -eq 0 ]; then
    echo "[~] Nothing to remove — already clean."
fi

echo "[+] System ready for fresh init."
