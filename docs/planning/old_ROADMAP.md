# TSC Protocol — Implementation Roadmap

**Version:** 2.0  
**Last Updated:** 2026-02-28

---

## Guiding Principle: Bottom-Up, Correctness First

We build from the lowest layer upward. No layer builds on a broken foundation. Each phase ends with a working, testable deliverable. Code review against the new design documents happens before starting the next phase.

---

## Pre-Phase: Documentation & Debt Resolution

**Status:** IN PROGRESS

Before writing new code, the design documents have been fully revised (see `/docs/`). The following code-level issues were identified in the review and MUST be resolved before Phase 1 resumes:

| Issue | File | RFC/ADR Reference | Priority |
|-------|------|-------------------|----------|

| `next_key_commitment` hardcoded to `[0u8; 32]` | `bip39.rs`, `ipc.rs` | RFC-012, RFC-002 | CRITICAL |
| `seed[0..32]` direct slice used as Ed25519 key | `bip39.rs` | RFC-012, ADR-004 | CRITICAL |
| Static Argon2 salt `"TSCVaultSaltV001"` | `vault.rs` | RFC-006, ADR-005 | CRITICAL |
| Vault hardcoded to `/tmp/tsc_vault.bin` | `vault.rs`, `tscd/main.rs` | ADR-009 | HIGH |
| IPC socket hardcoded to `/tmp/tscd.sock` | `tscd/main.rs`, `ipc.rs` | RFC-003, ADR-009 | HIGH |
| `GhostCommand`/`GhostResponse` duplicated | `ipc.rs`, `proto.rs` | RFC-011, ADR-007 | HIGH |
| Ephemeral key generated before vault check | `tscd/main.rs` | RFC-010 | HIGH |
| `SkipServerVerification` not gated | `tsc-net/lib.rs` | ADR-008 | HIGH |
| AES-GCM used instead of ChaCha20-Poly1305 | `dht.rs`, `vault.rs` | ADR-011 | MEDIUM |
| Key reuse: same key for vault and DHT | `tscd/main.rs`, `dht.rs` | Technical Specs §2.5 | MEDIUM |
| No unit tests anywhere | all crates | — | HIGH |
| `mnemonic generation` duplicated in `bip39.rs` and `vault.rs` | both | — | MEDIUM |
| `libp2p` identity keypair conflated with KERI keypair | `lib.rs` | ADR-006 | MEDIUM |
| DHT `resolve_ghost` returns `None` for all remote peers | `lib.rs` | RFC-005 | MEDIUM |

---

## Phase 1: Cryptographic Foundations (`tsc-crypto`)

**Goal:** A correct, tested Identity Domain.

### Milestone 1.0 — Debt Resolution

- [ ] **1.0.1** Add `slip10` crate to workspace (per RFC-012). Evaluate `slip10_ed25519` or `ed25519-bip32`.
- [ ] **1.0.2** Replace `seed[0..32]` slice with SLIP-0010 hardened derivation at path `m/44'/7777'/0'/0'/0'`.
- [ ] **1.0.3** Replace `next_key_commitment = [0u8; 32]` with real SLIP-0010 derivation of K2 at path `m/44'/7777'/0'/0'/1'`. Hash K2 public key with BLAKE3. Zeroize K2 private scalar after hash.
- [ ] **1.0.4** Fix Argon2id salt: generate 16 random bytes; store in vault header (per RFC-006 §6.2).
- [ ] **1.0.5** Replace vault path `/tmp/tsc_vault.bin` with XDG path (per ADR-009). Use the `dirs` crate.
- [ ] **1.0.6** Replace AES-GCM with ChaCha20-Poly1305 in `vault.rs` (per ADR-011).
- [ ] **1.0.7** Merge duplicate mnemonic generation: keep `bip39::generate_sovereign_entropy`, delete `vault::generate_mnemonic`.
- [ ] **1.0.8** Add `zeroize::ZeroizeOnDrop` to all key-holding structs (`Persona`, etc.).

### Milestone 1.1 — Complete KERI State Machine

- [ ] **1.1.1** Implement `RotationEvent` creation: derives K2 from seed, verifies `BLAKE3(K2.pub) == previous.n`, signs with both K1 and K2.
- [ ] **1.1.2** Implement `VerificationEngine`: given an IEL as `Vec<KeyEvent>`, verify the entire chain from inception through all rotations.
- [ ] **1.1.3** Implement IEL persistence: serialize/deserialize the event log to `$XDG_DATA_HOME/tsc/identity/<ghost_id>/iel.json`.
- [ ] **1.1.4** Implement conflict detection: two ROT events at the same sequence number → alert + refuse.

### Milestone 1.2 — Testing

- [ ] **1.2.1** Unit test: `generate_sovereign_entropy` → `derive_genesis_persona` → verify IXN digest matches `ghost_id`.
- [ ] **1.2.2** Unit test: `lock_vault` → `unlock_vault` round trip with correct key succeeds.
- [ ] **1.2.3** Unit test: `unlock_vault` with wrong key returns `Err`.
- [ ] **1.2.4** Unit test: vault file tampered (single byte flipped) → `Err` (Poly1305 auth tag check).
- [ ] **1.2.5** Unit test: full IEL chain — inception + two rotations — verifies correctly.
- [ ] **1.2.6** Unit test: malformed ROT event (bad commitment) → `VerificationEngine` rejects.

**Phase 1 Deliverable:** `tsc-cli init` creates a persistent sovereign identity that survives `tscd` restarts. The GhostID is stable. The vault file at the XDG path passes tamper detection.

---

## Phase 2: Transport Layer (`tsc-net` + `tsc-proto`)

**Goal:** Two `tscd` instances can discover and communicate with each other.

### Milestone 2.0 — Shared Protocol Crate

- [ ] **2.0.1** Create `crates/tsc-proto/` crate.
- [ ] **2.0.2** Move all command/response enums and structs to `tsc-proto` per RFC-011.
- [ ] **2.0.3** Add IPC framing helpers: `write_framed(writer, payload)` and `read_framed(reader) -> payload` (u32 length prefix).
- [ ] **2.0.4** Add `PROTO_VERSION: u32 = 1` constant.
- [ ] **2.0.5** Update `tscd` and `tsc-cli` to depend on `tsc-proto`. Delete `tsc-cli/src/proto.rs`.

### Milestone 2.1 — GSP Framing

- [ ] **2.1.1** Update `GspFrame` to include `stream_id: u16` and `flags: u8` (per RFC-001 §1.3).
- [ ] **2.1.2** Implement frame serializer/deserializer: `to_bytes()` / `from_bytes()` with strict length validation.
- [ ] **2.1.3** Implement `GspHandshake` full verification: parse KERI event, verify self-signature, derive GhostID, verify challenge signature (per RFC-001 §1.5).
- [ ] **2.1.4** Gate `SkipServerVerification` behind `#[cfg(feature = "dev")]` (per ADR-008).

### Milestone 2.2 — DHT & Discovery

- [ ] **2.2.1** Replace AES-GCM with ChaCha20-Poly1305 in `dht.rs` CoordinateBlob encryption.
- [ ] **2.2.2** Implement separate DHT coordinate key using HKDF-SHA256 (per Technical Specs §2.5).
- [ ] **2.2.3** Implement `GetRecord` query in `run_discovery`: when `resolve_ghost` is called for a non-local ID, query the Kademlia DHT and await the result.
- [ ] **2.2.4** Implement record freshness check: reject CoordinateBlob with `timestamp > now - 3600`.
- [ ] **2.2.5** Implement auto-republish: PUT_COORDINATE every 900 seconds.

### Milestone 2.3 — Daemon Boot Sequence

- [ ] **2.3.1** Implement correct boot sequence per RFC-010: probe vault first, load identity, derive keys, then start network.
- [ ] **2.3.2** Implement ephemeral mode: if no vault, start with ephemeral ID prefixed `"ephemeral:"`.
- [ ] **2.3.3** Move IPC socket path to XDG runtime dir (per ADR-009).
- [ ] **2.3.4** Implement IPC framing with `u32` length prefix in both `tscd::ipc` and `tsc-cli`.

### Milestone 2.4 — Testing

- [ ] **2.4.1** Integration test: two `tscd` instances start, exchange GSP handshakes, verify each other's GhostIDs.
- [ ] **2.4.2** Unit test: `GspFrame` serialization round trip.
- [ ] **2.4.3** Unit test: `CoordinateBlob` encrypt/decrypt round trip.
- [ ] **2.4.4** Unit test: stale record (timestamp > 1hr) is rejected.
- [ ] **2.4.5** Unit test: malformed handshake (wrong challenge signature) is rejected.

**Phase 2 Deliverable:** Two `tscd` instances on different machines can discover each other via GhostID (mDNS on LAN; DHT over internet) and exchange an authenticated GSP ping. `tsc-cli send <ghost_id> "hello"` delivers a verified message.

---

## Phase 3: Ghost-Box Orchestrator (`tsc-runtime`)

**Goal:** A Ghost-Box can be spawned and serves a real application accessible via the Shell.

### Milestone 3.1 — Jail & Cgroup Setup

- [ ] **3.1.1** Implement `GhostJail::spawn()` with real namespace flags passed to the OCI runtime: bundle path, state dir, all namespace types.
- [ ] **3.1.2** Implement cgroup v2 provisioning: create cgroup at `/sys/fs/cgroup/tsc/<ghost_id>/`, write `cpu.max`, `memory.max`, `memory.high`, `memory.swap.max`.
- [ ] **3.1.3** Implement `GhostConfig` (OCI `config.json`) generation: read-only root, tmpfs mounts, no network gateway.
- [ ] **3.1.4** Implement virtual ethernet pair setup: create `veth-<id>` pair, assign Ghost side to Ghost netns.
- [ ] **3.1.5** Implement `GhostState` tracking in `tscd`: map from `ghost_id` to `GhostState`, poll PID status.

### Milestone 3.2 — Ghost Persistence

- [ ] **3.2.1** Implement LUKS2 volume creation for Ghosts that request persistence.
- [ ] **3.2.2** Implement dm-verity root hash signing on Ghost shutdown.
- [ ] **3.2.3** Implement dm-verity verification on Ghost boot.

### Milestone 3.3 — Legacy Bridge

- [ ] **3.3.1** Implement SOCKS5 proxy server inside Ghost namespace.
- [ ] **3.3.2** Implement local DNS resolver: `.tsc` hostnames → DHT → GSP stream.
- [ ] **3.3.3** Complete `GhostBridge::handle_legacy_traffic`: wire TCP socket bytes to GSP Data Plane stream.

### Milestone 3.4 — P2P OCI Image Distribution

- [ ] **3.4.1** Implement `GhostFetcher::pull_from_swarm`: find providers via DHT, download eStargz layers, verify BLAKE3 hashes.
- [ ] **3.4.2** Implement Ghost image seeding: a node serving an image publishes provider records to the DHT.

**Phase 3 Deliverable:** `tsc-cli spawn nginx-ghost` pulls an Nginx OCI image from the swarm, spawns it in an isolated namespace, and the Nginx HTTP server is reachable from another Ghost via `curl http://nginx.tsc/`.

---

## Phase 4: Sovereign Interface

**Goal:** A user can manage their entire TSC environment through a polished CLI and browser interface.

### Milestone 4.1 — CLI Dashboard

- [ ] **4.1.1** Implement `tsc-cli status` displaying: GhostID, vault state, peer count, running Ghosts, uptime.
- [ ] **4.1.2** Implement `tsc-cli list` showing all running Ghosts with status.
- [ ] **4.1.3** Implement `tsc-cli stop <ghost_id>`.
- [ ] **4.1.4** Implement `tsc-cli rotate-key` triggering KERI key rotation.
- [ ] **4.1.5** Implement `tsc-cli recover <mnemonic>` for identity restoration.
- [ ] **4.1.6** Improve error messages: structured `MODULE:CODE: description` format (per RFC-003 §3.4).

### Milestone 4.2 — Sovereign Update System

- [ ] **4.2.1** Implement update manifest verification (per RFC-008).
- [ ] **4.2.2** Implement P2P update distribution over GSP.
- [ ] **4.2.3** Implement rollback mechanism (3-failure threshold).

### Milestone 4.3 — WASM Browser Interface (`tsc-window`)

- [ ] **4.3.1** Compile micro-shell to WASM targeting modern browsers.
- [ ] **4.3.2** Implement WebSocket bridge between browser and local `tscd` (IPC via WebSocket proxy).
- [ ] **4.3.3** Implement basic Ghost management UI.

**Phase 4 Deliverable:** A user can type `tsc spawn my-blog`, manage their Ghosts via the browser UI, rotate their keys, and receive automatic P2P software updates.

---

## Ongoing (All Phases)

- **Security audit:** Each phase's cryptographic code should be reviewed by at least one person not involved in writing it before the phase is marked complete.
- **`cargo audit`** runs in CI on every PR.
- **`cargo clippy -- -D warnings`** is a required CI check.
- **`cargo test`** must pass with zero failures before merging to main.
- **Documentation:** All public API items require doc comments (`#![deny(missing_docs)]` is enforced).
