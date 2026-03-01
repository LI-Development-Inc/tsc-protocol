# TSC Project File Structure

**Version:** 2.0  
**Last Updated:** 2026-02-28

---

## Workspace Layout

```bash
tsc-protocol/
├── Cargo.toml                      # Workspace root
├── rust-toolchain.toml             # Pins Rust ≥ 1.75
├── .cargo/
│   └── config.toml                 # -D warnings, forbid(unsafe_code)
├── .gitignore
│
├── crates/
│   │
│   ├── tsc-crypto/                 ← IDENTITY DOMAIN (Root of Trust)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs              # Persona struct, public API
│   │       ├── bip39.rs            # BIP-39 mnemonic generation + master seed
│   │       ├── slip10.rs           # SLIP-0010 hardened Ed25519 derivation [NEW]
│   │       ├── keri.rs             # IXN, ROT events, VerificationEngine
│   │       └── vault.rs            # Argon2id KDF, ChaCha20 vault encrypt/decrypt
│   │
│   ├── tsc-proto/                  ← SHARED PROTOCOL TYPES [NEW CRATE]
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs              # Re-exports all public types
│   │       ├── commands.rs         # GhostCommand enum
│   │       ├── responses.rs        # GhostResponse, DaemonStatus, GhostInfo
│   │       └── framing.rs          # u32-prefixed IPC read/write helpers
│   │
│   ├── tsc-net/                    ← TRANSPORT DOMAIN (The Pipe)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs              # NetStack, GspConnection
│   │       ├── gsp.rs              # GSP frame format, handshake logic
│   │       ├── dht.rs              # CoordinateBlob, GhostDiscovery
│   │       └── morph.rs            # Chaff injection (always-on)
│   │
│   ├── tsc-runtime/                ← EXECUTION DOMAIN (The Ghost)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs              # GhostState, GhostStatus
│   │       ├── jail.rs             # Namespace/cgroup setup, OCI spawn
│   │       ├── oci.rs              # GhostBundle, GhostConfig generation
│   │       ├── bridge.rs           # SOCKS5 proxy, legacy TCP → GSP
│   │       └── fetcher.rs          # P2P OCI image pulling [NEW]
│   │
│   ├── tscd/                       ← THE SHELL (Privileged Daemon)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs             # Entry point, boot sequence, tokio::select!
│   │       ├── ipc.rs              # Unix Domain Socket server (SO_PEERCRED auth)
│   │       └── identity.rs         # Vault load/init, boot sequence logic [NEW]
│   │
│   └── tsc-cli/                    ← USER INTERFACE (CLI Controller)
│       ├── Cargo.toml
│       └── src/
│           └── main.rs             # Argument parsing, IPC client
│
├── docs/
│   ├── ARCHITECTURE.md             # System design, three-domain model, data flows
│   ├── ROADMAP.md                  # Phased implementation plan with task checklist
│   ├── rfcs/
│   │   └── RFCS.md                 # All RFCs (001-012)
│   ├── adrs/
│   │   └── ADRS.md                 # All ADRs (001-013)
│   ├── specs/
│   │   └── TECHNICAL_SPECS.md      # Crypto primitives, data formats, constraints
│   └── FILE_STRUCTURE.md           # This file
│
├── config/
│   ├── config.toml.example         # Annotated example configuration
│   ├── lighthouse.toml.example     # Lighthouse node configuration
│   └── update-keys.json.example    # Community update key template
│
├── scripts/
│   ├── testing-clear-data.sh       # Wipe XDG state for fresh test run
│   └── setup-dev-env.sh            # Install youki/crun, configure cgroups [NEW]
│
└── tests/
    ├── integration/
    │   ├── handshake_test.rs        # Two tscd instances, GSP handshake
    │   └── vault_test.rs           # Vault create/lock/unlock round trip
    └── fixtures/
        └── test_mnemonic.txt       # Known mnemonic for deterministic tests
```

---

## Crate Dependency Graph

```bash
tsc-cli ──────────────────────────────────► tsc-proto
                                                 ▲
tscd ────────────────────────────────────────────┤
  │                                              │
  ├──────────────────────────────────────► tsc-proto
  │
  ├──────────────────────────────────────► tsc-crypto
  │
  ├──────────────────────────────────────► tsc-net
  │                                           │
  │                                           └──► tsc-crypto (for KERI verification)
  │
  └──────────────────────────────────────► tsc-runtime
                                               │
                                               └──► tsc-net (for GspFrame, bridge)
```

**Key rules:**

- `tsc-crypto` has NO dependencies on other TSC crates (it is the root of trust)
- `tsc-proto` depends only on `serde` and `bincode` (no TSC crates)
- `tsc-net` depends on `tsc-crypto` (for KERI verification during handshake)
- `tsc-runtime` depends on `tsc-net` (for bridging Ghost traffic to GSP)
- `tscd` is the integration point; it depends on all library crates

---

## Required Build & Configuration Files

| File | Purpose | Status |
|------|---------|--------|

| `rust-toolchain.toml` | Pins Rust ≥ 1.75 | Missing — needs creation |
| `.cargo/config.toml` | `-D warnings`, linter settings | Present |
| `config/config.toml.example` | Reference configuration | Missing — needs creation |
| `config/update-keys.json` | Community update signing keys | Missing — needs creation |
| `scripts/setup-dev-env.sh` | Developer environment setup | Missing — needs creation |

---

## Runtime Directory Layout (per-user, XDG)

```bash
~/.local/share/tsc/           ($XDG_DATA_HOME/tsc/)
├── vault.bin                 # Encrypted mnemonic vault
├── identity/
│   └── blake3:7f3a2c.../    # Per-GhostID subdirectory
│       └── iel.json         # Identifier Event Log
└── vaults/
    ├── <ghost_id>.img        # LUKS2 sparse file (per persistent Ghost)
    └── <ghost_id>.roothash   # Signed dm-verity root hash

~/.config/tsc/                ($XDG_CONFIG_HOME/tsc/)
├── config.toml
├── lighthouse.toml           # Only present on Lighthouse nodes
└── update-keys.json

~/.local/state/tsc/           ($XDG_STATE_HOME/tsc/)
└── tscd.log

/run/user/<uid>/tsc/          ($XDG_RUNTIME_DIR/tsc/)
└── tscd.sock                 # Unix Domain Socket
```
