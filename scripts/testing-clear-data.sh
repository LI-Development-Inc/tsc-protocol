#!/bin/bash
echo "[*] Wiping TSC Protocol state..."
# Kill any running daemon
pkill tscd 
# Remove persistent data
rm -f /tmp/tsc_vault.bin
rm -f /tmp/tscd.sock
echo "[+] System Ready for fresh Init."