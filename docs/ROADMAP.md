# 🗺️ TSC Protocol — Implementation Roadmap

**Approach:** Bottom-Up. Each phase delivers a runnable, testable binary.
**Last updated:** Phase 2.1 complete. Next: VPS peer test to validate cross-node KERI handshake.

---

## ✅ Pre-Phase: Debt Resolution (COMPLETE)

| # | Issue | Fix |
|---|-------|-----|
| C1 | `next_key_commitment` hardcoded `[0u8;32]` | SLIP-0010 `prerotation_commitment()` in `bip39.rs` |
| C2 | `seed[0..32]` used directly as Ed25519 key | Full SLIP-0010 derivation `m/44'/7777'/0'/0'/0'` |
| C3 | Static Argon2id salt | 16-byte random salt per vault write, stored in header |
| C4 | DHT `GetRecord` not implemented | Kademlia `get_record()` wired in Phase 1.5 |
| H1 | Vault path `/tmp` hardcoded | `$XDG_DATA_HOME/tsc/vault.bin` |
| H2 | IPC socket `/tmp` hardcoded | `$XDG_RUNTIME_DIR/tsc/tscd.sock` |
| H3 | `GhostCommand`/`GhostResponse` duplicated | `tsc-proto` crate (RFC-011, ADR-007) |
| H4 | Ephemeral key derived before vault check | Vault-first boot sequence (RFC-010) |
| H5 | `SkipServerVerification` not gated | `#[cfg(feature = "dev")]` on entire `connect()` fn |
| M1 | AES-GCM → ChaCha20-Poly1305 | `vault.rs` updated (ADR-011) |
| M2 | Key reuse (vault KDF = DHT key) | Separate HKDF-SHA256 derivation for DHT key |
| M3 | No unit tests | 24 tests across `bip39.rs`, `vault.rs`, `keri.rs`, `lib.rs` |
| M4 | Mnemonic generation duplicated | Consolidated in `bip39.rs` |
| M5 | libp2p identity conflated with KERI | Separated: libp2p `PeerId` ≠ `GhostID` |
| M6 | `resolve_ghost` returns `None` for remote | DHT lookup channel + Kademlia `get_record` |

---

## ✅ Phase 1: Cryptographic Foundations (COMPLETE)

**Deliverable achieved:** CLI creates a Sovereign Identity, signs an Inception Event,
stores an Argon2id vault, and resolves/connects/sends to the local GhostID.

### 1.1 — BIP-39 + SLIP-0010 (`bip39.rs`)
- `generate_sovereign_entropy()` → 24-word mnemonic + 512-byte seed
- `restore_from_phrase()` → validated BIP-39 restore
- `derive_active_key()` → K1 at `m/44'/7777'/0'/0'/0'`
- `derive_key_at_index(n)` → Kn at `m/44'/7777'/0'/0'/n'`
- `prerotation_commitment()` → `BLAKE3(K2.verifying_key)`, K2 immediately zeroized

### 1.2 — KERI Inception Event (`keri.rs`, RFC-002)
- `InceptionEvent::new()` → self-referential digest `d == i`, self-signed by K1
- `InceptionEvent::verify_signature()` + `calculate_digest()`
- `verify_event_log()` → walks full IXN→ROT→ROT chain with commitment checking
- `RotationEvent::new()` → dual-signed by outgoing + incoming key

### 1.3 — Argon2id Vault (`vault.rs`, RFC-006)
- Binary format: magic + version + random salt + random nonce + ciphertext
- Argon2id: t=3, m=64MiB, p=4 — hardware UUID binding
- ChaCha20-Poly1305 AEAD encryption

### 1.4 — Daemon Boot + IPC (`main.rs`, `ipc.rs`, RFC-010, RFC-003)
- Vault-first boot: `TSC_MNEMONIC` env var unlocks on restart
- Live identity reload: `init`/`recover` updates daemon state without restart
- `DaemonState` behind `Arc<RwLock<>>` — status reflects live GhostID
- `SO_PEERCRED` auth on IPC socket

### 1.5 — DHT Local Resolution (RFC-005)
- `NetStack.local_id` behind `Arc<RwLock<String>>` — updated live after `init`
- `ReannounceRequest` channel: `init` stores record in local Kademlia MemoryStore
- `resolve_ghost()` local shortcut + `kad.get_record()` for remote GhostIDs

### Verified (test session, local loopback)
```
make test-p1    → 10/10 green (ping, status, list, resolve, connect, send ×2,
                   recover, persistent resolve/connect/send)
```

---

## ✅ Phase 1.1: KERI Key Rotation (COMPLETE)

**Deliverable achieved:** `rotate-key` advances the KERI succession chain;
GhostID is invariant across all rotations; IEL persists across daemon restarts.

### What was built
- `RotationEvent::new(prev_key, new_key, next_commitment, prev_digest, seq, ghost_id, path)`
- Dual-signature: `sig_prev` (outgoing K_n) + `sig_new` (incoming K_{n+1})
- `verify_event_log()` extended to walk full IXN→ROT chain
- `iel.rs`: append-only JSONL at `$XDG_DATA_HOME/tsc/iel.jsonl`
- `Persona::rotate()`: re-derives keys, appends ROT event, updates counters
- `RotateKey` IPC handler: loads IEL, verifies chain, derives new keys, re-announces to DHT
- **Critical fix:** `KeyEvent` changed from `#[serde(tag = "t")]` to `#[serde(untagged)]` —
  the internally-tagged representation was injecting a duplicate `"t"` field, breaking
  IEL deserialization and causing the rotation counter to not persist

### Verified (test session)
```
make test-p1-1  → 4/4 green (GhostID stable, new key returned,
                   distinct keys per rotation, IEL written with 2+ events)
Running test-p1-1 twice: IEL grew from 5 → 9 events (inception + 8 rotations)
```

---

## ✅ Phase 2.1: GSP HELLO Handshake (COMPLETE — loopback verified)

**Deliverable:** `connect()` and `listen()` exchange `GspHello` frames;
remote GhostID is KERI-verified before any data frames are accepted.

### What was built
- `GspHello { ghost_id, inception }` wire type in `gsp.rs`
- `encode_hello()` / `decode_hello()` / `verify_hello()` helpers
  - `verify_hello` checks: (1) Ed25519 self-sig valid, (2) `BLAKE3(ixn) == ghost_id`
- `NetStack.local_ixn: Arc<RwLock<Option<InceptionEvent>>>` — set at boot and after init/recover
- `listen()` rewired: first QUIC stream = HELLO exchange, subsequent = Data/Chaff frames
- `connect()` sends HELLO on stream 0, reads and verifies responder's HELLO
- `SendMessage` wraps payload in `GspFrame::new(MsgType::Data, ...)` — ingress handler decodes
- Chaff frames silently discarded in ingress loop
- Ephemeral mode: `local_ixn = None`, sends no HELLO, peer labelled `"unverified"`

### Verified (test session, loopback)
```
make test-p2    → resolve ✓, connect ✓, send ✓ (loopback with TSC_GHOST_B=self)
daemon log shows: [+] GSP: Peer verified: e40054f2…
```

### ⚠️ Pending: cross-node validation
- **Need:** VPS peer with `make daemon-start` + `TSC_GHOST_B` set to remote GhostID
- **Validates:** KERI verification on a key the responder has never seen
- **Test:** `make test-p2` with `TSC_GHOST_B=<vps-ghost-id>` from local machine

---

## 🔧 Phase 2.2: Remote DHT Resolution (PENDING VPS)

**Goal:** Two `tscd` instances resolve each other via mDNS → Kademlia.

### What exists
- mDNS peer discovery already implemented (adds peers to routing table)
- `kad.get_record()` query path wired
- Anti-stale: records older than 1 hour rejected in `decode_coordinate`

### Checklist
- [ ] VPS peer setup: install tscd, open UDP 9090 + TCP 9090
- [ ] Bootstrap config: `[net] bootstrap = ["<multiaddr>"]` in config.toml (Phase 4.1)
- [ ] Test: local resolves VPS GhostID via DHT after mDNS peer add
- [ ] Test: VPS resolves local GhostID

---

## 🔧 Phase 2.3: Traffic Morphing (PENDING)

**Goal:** Chaff injection defeats DPI metadata heuristics (RFC-007).

### What exists
- `morph.rs`: `send_chaff_stream(tx)` scaffolded — generates random-size frames at random interval
- `MsgType::Chaff` defined and silently discarded in ingress loop

### Checklist
- [ ] Wire `send_chaff_stream` into the QUIC write path alongside real data
- [ ] Configurable rate: `[net] chaff_rate = 1` (frames per real frame) in config.toml
- [ ] `tsc-cli status` peer entry shows chaff statistics

---

## 📦 Phase 3: Ghost Orchestrator (`tsc-runtime`) (PENDING)

**Goal:** Spawn an isolated workload reachable only through the Shell.

### 3.1 — Linux Namespace Isolation (RFC-004)
- [ ] `SpawnGhost` handler: `clone(CLONE_NEWNET|NEWPID|NEWNS|NEWUSER)`
- [ ] Assign virtual IP from `10.ghost.0.0/16` (ADR-006)
- [ ] `GhostHandle` registry: `HashMap<GhostId, GhostHandle>` in `DaemonState`
- [ ] `ListGhosts` / `StopGhost` backed by registry

### 3.2 — OCI Runtime Integration
- [ ] `youki` or `crun` integration via `jail.rs`
- [ ] overlayfs: read-only base + ephemeral upper layer
- [ ] Vault ref as read-only bind mount inside Ghost namespace

### 3.3 — Shell Proxy
- [ ] Ghost→Host: UDP/TCP proxy through Shell virtual interface (`bridge.rs`)
- [ ] Host→Ghost: only via `tsc-cli send` or registered port mappings

**Deliverable:** `tsc-cli spawn nginx-ghost` starts an Nginx container;
`tsc-cli send nginx-ghost "GET / HTTP/1.0"` returns the index page.

---

## 🖥️ Phase 4: Sovereign Interface (PENDING)

### 4.1 — `tsc-cli` Enhancements
- [ ] `tsc-cli logs <ghost-id>` — stream Ghost stdout/stderr
- [ ] `tsc-cli inspect <ghost-id>` — namespace, virtual IP, uptime, CPU/mem
- [ ] `$XDG_CONFIG_HOME/tsc/config.toml` — `[net]`, `[vault]`, `[log]` sections

### 4.2 — The Window (Browser Shell)
- [ ] Compile `tsc-cli` core logic to WASM (`wasm32-unknown-unknown`)
- [ ] WebSocket bridge: browser ↔ `tscd` IPC socket
- [ ] Sovereign Browser extension: intercepts `.ghost` TLD

**Deliverable:** User opens browser, navigates to `my-blog.ghost`, sees their Ghost-hosted site.

---

## 🔐 Security Hardening (ongoing)

| Item | Status |
|------|--------|
| `#![forbid(unsafe_code)]` on all crates | ✅ Done |
| `SkipServerVerification` gated behind `dev` feature | ✅ Done |
| Vault keys zeroized on drop (`Zeroizing<>`, manual `Drop`) | ✅ Done |
| No `/tmp` paths for secrets | ✅ Done (XDG throughout) |
| `SO_PEERCRED` auth on IPC socket | ✅ Done |
| KERI-based TLS verifier (replace `dev` gate) | Phase 2.1 ✅ (HELLO layer) |
| Audit `clone()` on key material | ✅ Done (Phase 1.1) |
| `cargo deny` / `cargo audit` in CI | Phase 2 complete |
| Release build smoke test (no `dev` feature) | Phase 2 complete |
| Peer count wired to libp2p swarm | Phase 2.2 |
| `memfd_secret` for vault key in RAM | Phase 4 |
