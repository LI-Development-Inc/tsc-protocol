# Accounts for use later if needed for testing

## Removing Files

rm -f /tmp/tsc_vault.bin /tmp/tscd.sock crates/tscd/identity.json

/tmp/tsc_vault.bin: This is the encrypted container that holds your 24-word mnemonic and master seed. Removing it forces the system to treat the next run as a "First Boot" scenario.

/tmp/tscd.sock: This is the Unix Domain Socket used for IPC. While the code attempts to remove this on startup, manual removal ensures no "Address already in use" errors occur if the daemon crashed.

identity.json (if exists): Depending on your specific tsc_crypto implementation, identity metadata might be cached here.

### Fresh Start Script

```bash
#!/bin/bash
echo "[*] Wiping TSC Protocol state..."
# Kill any running daemon
pkill tscd 
# Remove persistent data
rm -f /tmp/tsc_vault.bin
rm -f /tmp/tscd.sock
echo "[+] System Ready for fresh Init."
```

## First Test Account

user@debian:~/tsc-protocol$ ./target/debug/tsc-cli
[+] Connection established with TSCD

--- SOVEREIGN IDENTITY INITIALIZED ---
CRITICAL: Write down these 24 words. They are your Master Seed.
If you lose these, you lose your Ghosts forever.

wife gravity feed ribbon ugly robot bracket fury myth potato razor service february advance slot sell alarm laugh clay answer wrestle tuna twice slice

--------------------------------------

## Second Key

user@debian:~/tsc-protocol$ ./target/debug/tsc-cli init
[+] Connection established with TSCD

--- SOVEREIGN IDENTITY INITIALIZED ---
CRITICAL: Write down these 24 words. They are your Master Seed.

trust girl scatter lady jar taxi fire seed bullet sock crater purpose lock clock monster half stadium hand mammal stick reopen rebuild segment work

--------------------------------------

## Third Key

[+] Connection established with TSCD

--- SOVEREIGN IDENTITY INITIALIZED ---
CRITICAL: Write down these 24 words. They are your Master Seed.

liar kiss ocean flee hawk risk episode okay axis unveil canyon track cheap cargo language attend lizard sausage cactus canyon acquire tomorrow chaos duty

## Fourth Key

user@debian:~/tsc-protocol$ ./target/debug/tsc-cli init
[+] Connection established with TSCD

--- SOVEREIGN IDENTITY INITIALIZED ---
CRITICAL: Write down these 24 words. They are your Master Seed.

shuffle slight city have ten swamp master horse know trip rival profit top lottery position boy inflict weekend lobster theme weird goddess public siren

--------------------------------------

## Fifth Key

user@debian:~/tsc-protocol$ ./target/debug/tsc-cli init
[+] Connection established with TSCD

--- SOVEREIGN IDENTITY INITIALIZED ---
CRITICAL: Write down these 24 words. They are your Master Seed.

west estate hotel door march cup sketch twin example will pair panic august update alpha oil immune suffer manual amused napkin sunset shy lady

--------------------------------------

## Sixth Key

user@debian:~/tsc-protocol$ ./target/debug/tsc-cli init
[+] Connection established with TSCD

--- SOVEREIGN IDENTITY INITIALIZED ---
CRITICAL: Write down these 24 words. They are your Master Seed.

tennis must recall process sand poverty warfare pair sweet gauge wife sausage magic hazard online atom leg wrap cry cancel winner vendor aspect master

--------------------------------------

## Seventh Key

user@debian:~/Dev/tsc-protocol$ ./target/debug/tsc-cli init

```bash
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SOVEREIGN IDENTITY INITIALIZED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  CRITICAL: Write down these 24 words and store
  them securely offline. This is your Master Seed.
  If you lose it, your identity is unrecoverable.

   1. sweet          2. potato         3. eternal        4. vapor
   5. sunset         6. all            7. chimney        8. lawn
   9. garden        10. allow         11. fence         12. erosion
  13. boil          14. plastic       15. region        16. decade
  17. turkey        18. dad           19. bacon         20. office
  21. number        22. labor         23. usual         24. engage

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```
