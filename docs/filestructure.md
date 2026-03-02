# 📂 TSC Project File Structure

```text
tsc-work/
├── Cargo.toml                  # Workspace — all crate versions & shared deps
├── Makefile                    # Manual test runner (make help for full list)
├── .env.test.example           # Environment variable template for testing
├── docs/
│   ├── ROADMAP.md              # Phase-by-phase implementation status
│   ├── RFCs.md                 # Protocol RFCs 001–008
│   ├── DesignDocs.md           # Architecture, design, requirements, crypto spec
│   └── filestructure.md        # This file
├── scripts/
│   ├── testing-clear-data.sh   # Legacy wipe script (superseded by make clean-state)
│   └── vps-setup.sh            # VPS peer bootstrap (Phase 2.2)
└── crates/
    │
    ├── tsc-crypto/             # THE IDENTITY DOMAIN (Root of Trust)
    │   ├── Cargo.toml
    │   └── src/
    │       ├── lib.rs          # Persona struct, rotate(), from_seed()
    │       ├── bip39.rs        # BIP-39 entropy, SLIP-0010 key derivation
    │       ├── keri.rs         # KERI event types, verify_event_log()
    │       ├── iel.rs          # Identity Event Log: append-only JSONL persistence
    │       └── vault.rs        # Argon2id + ChaCha20-Poly1305 vault
    │
    ├── tsc-net/                # THE TRANSPORT DOMAIN (The Pipe)
    │   ├── Cargo.toml
    │   └── src/
    │       ├── lib.rs          # NetStack, QUIC endpoint, listen(), connect()
    │       ├── gsp.rs          # GSP wire format: GspHello, GspFrame, verify_hello()
    │       ├── dht.rs          # GhostDiscovery: CoordinateBlob, encode/decode
    │       └── morph.rs        # Chaff injection (scaffolded — Phase 2.3)
    │
    ├── tsc-proto/              # SHARED IPC CONTRACT
    │   ├── Cargo.toml
    │   └── src/
    │       └── lib.rs          # GhostCommand, GhostResponse, framing (RFC-003)
    │
    ├── tsc-runtime/            # THE EXECUTION DOMAIN (The Ghost) — Phase 3
    │   ├── Cargo.toml
    │   └── src/
    │       ├── lib.rs          # GhostState, GhostStatus types
    │       ├── jail.rs         # GhostJail: OCI spawn stub (Phase 3.1)
    │       ├── oci.rs          # GhostBundle, GhostFetcher: OCI config stubs (Phase 3.2)
    │       └── bridge.rs       # GhostBridge: TCP→GSP proxy stub (Phase 3.3)
    │
    ├── tscd/                   # THE SHELL (Privileged Daemon)
    │   ├── Cargo.toml
    │   └── src/
    │       ├── main.rs         # Boot sequence, task spawning, identity loading
    │       └── ipc.rs          # IPC command dispatch (SO_PEERCRED auth)
    │
    └── tsc-cli/                # THE CONTROLLER (User-facing CLI)
        ├── Cargo.toml
        └── src/
            └── main.rs         # Command parsing, response rendering
```

---

## Crate Dependency Graph

```
tsc-cli ──────────────────────────────► tsc-proto
tscd ──────────► tsc-net ──────────────► tsc-proto
      └──────────► tsc-crypto             │
      └──────────► tsc-runtime            │
                   └──────────► tsc-net   │
tsc-net ──────────────────────────────► tsc-crypto
tsc-proto ── (no internal deps, bincode/serde only)
```

---

## Key Data Paths (XDG)

| Data | Location |
|------|----------|
| Vault | `$XDG_DATA_HOME/tsc/vault.bin` (default: `~/.local/share/tsc/vault.bin`) |
| IEL | `$XDG_DATA_HOME/tsc/iel.jsonl` |
| IPC socket | `$XDG_RUNTIME_DIR/tsc/tscd.sock` (default: `/run/user/<uid>/tsc/tscd.sock`) |
| Config *(Phase 4)* | `$XDG_CONFIG_HOME/tsc/config.toml` |
| Daemon log *(dev)* | `/tmp/tscd-test.log` (make daemon-start) |

---

## Required Files *(not yet created)*

| File | Purpose |
|------|---------|
| `rust-toolchain.toml` | Pin Rust ≥ 1.75 |
| `.cargo/config.toml` | `-D warnings` enforced workspace-wide |
| `$XDG_CONFIG_HOME/tsc/config.toml` | Bootstrap nodes, chaff rate, log level (Phase 4.1) |
