# TSC Architecture Decision Records (ADRs)

**Version:** 1.0  
**Last Updated:** 2026-02-28

An ADR captures a significant architectural decision: the context, the options considered, and the rationale for the choice made. ADRs are immutable once accepted — they are historical records. If a decision changes, a new ADR supersedes the old one.

---

## ADR-001: Use Rust as the Sole Implementation Language

**Status:** Accepted  
**Deciders:** Core team  
**Date:** Project inception

### Context

We need a systems programming language capable of:

- Direct Linux syscall access (namespaces, cgroups, io_uring)
- Memory safety without a garbage collector
- Strong async support for QUIC networking
- A rich cryptography ecosystem

### Options Considered

| Option | Pros | Cons |
|--------|------|------|

| **Rust** | Memory safety, no GC, excellent async, `#![forbid(unsafe_code)]` enforcement, growing crypto crate ecosystem | Steeper learning curve, longer compile times |
| Go | Fast compilation, good stdlib, familiar | GC introduces latency, weaker memory safety guarantees, `unsafe` less controlled |
| C | Maximum control, no GC | Manual memory management = high vulnerability surface. Unacceptable for a security-critical system. |

### Decision

**Rust.** The memory safety guarantees are non-negotiable for a system handling cryptographic key material. The `#![forbid(unsafe_code)]` attribute provides a compile-time enforced boundary that no other mainstream language offers for this use case.

### Consequences

- All crates MUST declare `#![forbid(unsafe_code)]` in their `lib.rs` or `main.rs`.
- Cryptographic primitives MUST use audited crates from the RustCrypto organization.
- Build times will be longer. This is accepted.

---

## ADR-002: Use QUIC as the Transport Protocol

**Status:** Accepted  
**Deciders:** Core team  
**Date:** Project inception

### Context

TSC requires a transport that supports:

- Multiplexed streams without head-of-line blocking
- Built-in TLS 1.3 encryption
- Resilience to NAT rebinding (connection migration)
- UDP-based operation (for NAT traversal flexibility)

### Options Considered

| Option | Pros | Cons |
|--------|------|------|
| **QUIC (quinn)** | Multiplexed, TLS 1.3 built-in, UDP, connection migration, well-maintained Rust crate | Newer protocol, some firewalls block UDP |
| TCP + TLS | Widely supported | Head-of-line blocking, no built-in multiplexing, connection-bound |
| libp2p TCP | P2P-native, good Rust support | TCP limitations, more complex stack |
| WebRTC | Browser-compatible | Enormously complex, heavyweight dependency |

### Decision

**QUIC via the `quinn` crate.** The multiplexing capability is essential for the GSP model (multiple Ghost streams on one connection). TLS 1.3 built-in eliminates a class of configuration errors. Connection migration assists with mobile/roaming scenarios.

### Consequences

- `tscd` binds a UDP endpoint for all GSP traffic.
- A fallback TCP-wrapped QUIC mode should be considered for firewalled environments (future ADR).
- Self-signed certificates are used for QUIC (identity verification happens via KERI, not PKI). The `SkipServerVerification` workaround in development MUST be gated behind a `dev` feature flag and replaced with KERI-based peer verification in production (see ADR-008).

---

## ADR-003: Use KERI-Lite for Cryptographic Identity

**Status:** Accepted  
**Deciders:** Core team  
**Date:** Project inception

### Context

TSC needs a self-sovereign identity system where:

- Identity can survive key compromise (rotation without a CA)
- There is no central registry or authority
- Identity is verifiable by any third party from first principles

### Options Considered

| Option | Pros | Cons |
|--------|------|------|
| **KERI-lite** | Self-certifying, CA-free, supports pre-rotation commitment, well-reasoned academic foundation | Not yet widely deployed, requires custom implementation |
| DID (W3C) | Standardized, broad ecosystem | Many variants require blockchain or centralized resolvers; complexity |
| OpenPGP Web of Trust | Established, well-understood | No key succession mechanism; trust graphs become stale; no pre-rotation |
| X.509 / PKI | Widely deployed | Requires CA; CA is a single point of failure and control |
| Simple Ed25519 keypair | Simple | No rotation path; losing or compromising the key means permanent identity loss |

### Decision

**KERI-lite.** The pre-rotation commitment is the decisive feature. An attacker who steals the current signing key cannot rotate the identity because they don't know the pre-committed next key. This is not achievable with simple keypairs or traditional PKI.

### Consequences

- GhostID is permanent. It is derived from the Inception Event hash and never changes, even through key rotations.
- The Identifier Event Log (IEL) must be persisted and gossiped.
- The `tsc-crypto` crate implements KERI event creation and verification. It MUST NOT implement a full KERI node — only the succession logic needed by TSC.
- Full KERI spec compliance is NOT a goal. TSC uses KERI's core concepts adapted to its specific threat model.

---

## ADR-004: Use BIP-39 + SLIP-0010 for Key Derivation

**Status:** Accepted  
**Deciders:** Core team  
**Date:** Project inception

### Context

We need a user-recoverable master secret that can deterministically reproduce all key material. Users must be able to restore their identity from a memorizable backup.

### Options Considered

| Option | Pros | Cons |
|--------|------|------|

| **BIP-39 mnemonic + SLIP-0010** | Human-memorizable, widely understood, battle-tested, deterministic derivation of unlimited keys | BIP-39 wordlist is well-known (slight fingerprinting risk in extreme scenarios) |
| Random 32-byte key + base58 | Simpler | Not memorizable; harder to back up securely |
| Passphrase only | Simple for users | Entropy is too low; no standard derivation |
| Hardware-only key | Strong physical security | No recovery path if hardware lost |

### Decision

**BIP-39 (24 words) + SLIP-0010 hardened derivation.** The 24-word format provides 256 bits of entropy. SLIP-0010 handles Ed25519 derivation correctly (unlike BIP-32 which is designed for secp256k1). All key derivation MUST use hardened paths to prevent parent key recovery from child keys.

### Consequences

- The `bip39` crate handles mnemonic generation and seed derivation.
- A SLIP-0010 implementation crate MUST be added to workspace dependencies (see RFC-012).
- The current code's `seed[0..32]` direct-slice approach is **incorrect and must be replaced** (tracked as a code issue).
- A BIP-44 coin type (`7777'` placeholder) is used in derivation paths.

---

## ADR-005: Use Argon2id for Vault Key Derivation

**Status:** Accepted  
**Deciders:** Core team  
**Date:** Project inception

### Context

The vault stores the mnemonic encrypted at rest. The encryption key must be derived from something the user knows (the mnemonic) combined with something bound to the hardware. The KDF must be resistant to brute-force and GPU-accelerated attacks.

### Options Considered

| Option | Pros | Cons |
|--------|------|------|

| **Argon2id** | Memory-hard, GPU-resistant, PHC winner, balances time and memory cost, side-channel resistant | Requires tuning; memory cost has UX implications on low-end hardware |
| bcrypt | Well-established | Not memory-hard; vulnerable to dedicated hardware |
| PBKDF2 | Simple, standard | CPU-only; easily GPU-accelerated |
| scrypt | Memory-hard | Less flexible than Argon2id; harder to tune |

### Decision

**Argon2id** with parameters: `t=3, m=65536 (64 MiB), p=4`. These provide strong resistance on modern hardware at a ~1-2 second derivation time, which is acceptable for a vault unlock that happens once at daemon startup.

### Consequences

- The `argon2` crate is used.
- **The current code uses a hardcoded static salt. This MUST be fixed.** The salt must be randomly generated and stored in the vault file header (see RFC-006).
- KDF parameters are stored in the vault header to allow future parameter upgrades without breaking existing vaults.

---

## ADR-006: Use libp2p Kademlia for DHT

**Status:** Accepted  
**Deciders:** Core team  
**Date:** Phase 2 planning

### Context

TSC requires a distributed hash table for GhostID → coordinate resolution. The DHT must be decentralized, resilient to node churn, and integrate with the existing Rust networking stack.

### Options Considered

| Option | Pros | Cons |
|--------|------|------|

| **libp2p Kademlia** | Battle-tested, active Rust crate, integrates with mDNS, well-documented | Uses TCP by default (separate from QUIC GSP layer); adds a second transport |
| Custom Kademlia over QUIC | Single transport, tighter integration | Significant implementation effort; no existing battle-tested Rust implementation |
| BitTorrent DHT (mainline) | Proven at massive scale | Not designed for our use case; limited key flexibility |
| Centralized discovery server | Simple | Violates Axiom A4 (No Central Registry) |

### Decision

**libp2p Kademlia.** The implementation quality and maintenance track record outweigh the dual-transport complexity. The DHT runs on TCP; the GSP data plane runs on QUIC. This is an acceptable architecture.

### Consequences

- `tscd` maintains two listening ports: one UDP (QUIC/GSP) and one TCP (libp2p/DHT).
- The libp2p identity keypair is ephemeral per session. It is NOT the KERI identity keypair. These MUST NOT be conflated.
- DHT records store encrypted Coordinate Blobs, not raw IP addresses (see RFC-005).
- mDNS local discovery supplements the DHT for LAN scenarios.

---

## ADR-007: Extract `tsc-proto` as a Shared Crate

**Status:** Accepted  
**Deciders:** Core team  
**Date:** 2026-02-28 (derived from code review)

### Context

`GhostCommand` and `GhostResponse` are duplicated in `tscd/src/ipc.rs` and `tsc-cli/src/proto.rs`. This creates a maintenance hazard: any change to the command schema must be made in two places, and a mismatch causes silent `bincode` deserialization failures.

### Decision

Extract all shared IPC types into `crates/tsc-proto`. Both `tscd` and `tsc-cli` depend on `tsc-proto`. Neither may define their own command/response types. See RFC-011 for full specification.

### Consequences

- New crate `tsc-proto` must be added to the workspace.
- `tscd/src/ipc.rs` imports from `tsc-proto` instead of defining its own types.
- `tsc-cli/src/proto.rs` is deleted entirely.
- This is a **breaking change** to the internal IPC protocol version. A `PROTO_VERSION` constant is added.

---

## ADR-008: KERI-Based QUIC Peer Verification (No X.509 PKI)

**Status:** Accepted  
**Deciders:** Core team  
**Date:** 2026-02-28

### Context

QUIC requires TLS certificates. Currently, `tscd` uses self-signed certificates and `SkipServerVerification` — essentially no peer authentication at the TLS layer. Peer identity is supposed to be verified via KERI during the GSP handshake. But `SkipServerVerification` in production code is a significant security gap.

### Options Considered

1. **Use the KERI public key as the TLS certificate** — embed the Ed25519 public key as a self-signed cert, verified against the KERI event log.
2. **Use a separate self-signed cert per session** — regenerate for each `tscd` startup; verify identity only at the GSP handshake layer.
3. **Skip TLS verification entirely and rely only on GSP handshake** — current approach.

### Decision

**Option 2 with a hardened GSP handshake.** Generate a fresh self-signed TLS cert per `tscd` session (already done). The TLS layer provides transport confidentiality and forward secrecy. Peer *identity* verification is the responsibility of the GSP handshake (RFC-001 §1.5), which checks KERI events and challenge signatures. `SkipServerVerification` MUST be gated behind `#[cfg(feature = "dev")]` and MUST NOT compile in release builds.

### Consequences

- Add a `dev` feature to `tsc-net/Cargo.toml`.
- `SkipServerVerification` is wrapped in `#[cfg(feature = "dev")]`.
- The GSP handshake implementation (RFC-001 §1.5) is the authoritative identity check. It MUST be complete before data streams are accepted.
- Release builds that attempt to compile with `SkipServerVerification` will fail at compile time.

---

## ADR-009: Vault Path Uses XDG Base Directories

**Status:** Accepted  
**Deciders:** Core team  
**Date:** 2026-02-28

### Context

The vault file is currently hardcoded to `/tmp/tsc_vault.bin` and the IPC socket to `/tmp/tscd.sock`. Both are wrong:

- `/tmp` is not a suitable location for persistent secrets.
- `/tmp` is often a world-readable `tmpfs` — hostile to sensitive data.
- The RFC specifies `/run/tsc/tscd.sock` for the socket.

### Decision

Follow the XDG Base Directory Specification:

- **Vault file:** `$XDG_DATA_HOME/tsc/vault.bin` (default: `~/.local/share/tsc/vault.bin`)
- **Identity store (IEL):** `$XDG_DATA_HOME/tsc/identity/`
- **Config file:** `$XDG_CONFIG_HOME/tsc/config.toml` (default: `~/.config/tsc/config.toml`)
- **IPC socket:** `/run/tsc/tscd.sock` (system) or `$XDG_RUNTIME_DIR/tsc/tscd.sock` (user session)
- **Logs:** `$XDG_STATE_HOME/tsc/` (default: `~/.local/state/tsc/`)

Use the `dirs` crate for XDG path resolution.

### Consequences

- All hardcoded `/tmp/` paths are replaced.
- `tscd` creates required directories on startup if they don't exist, with `0700` permissions.
- The test cleanup script (`scripts/testing-clear-data.sh`) is updated to reflect new paths.
- User data from the `/tmp` era is not automatically migrated (acceptable for pre-release).

---

## ADR-010: OCI Runtime — Prefer `youki`, Accept `crun`

**Status:** Accepted  
**Deciders:** Core team  
**Date:** Phase 3 planning

### Context

TSC needs an OCI-compliant container runtime to spawn Ghost-Boxes. The runtime must support the full Linux namespace set and cgroups v2.

### Options Considered

| Runtime | Language | Cgroups v2 | Notes |
|---------|----------|------------|-------|

| **youki** | Rust | Yes | Rust-native, aligns with TSC's language philosophy; actively maintained |
| **crun** | C | Yes | Highly performant, widely deployed, Red Hat-maintained |
| runc | Go | Yes | Reference implementation; Go dependency |
| gVisor (runsc) | Go | Partial | Additional isolation but different threat model; heavyweight |

### Decision

**`youki` as the default, `crun` as the supported alternative.** Using a Rust-native OCI runtime reduces the foreign-code surface. Both are configurable via the `[runtime]` section in `config.toml`:

```toml
[runtime]
oci_runtime = "/usr/bin/youki"  # or /usr/bin/crun
```

### Consequences

- `GhostJail::spawn()` reads the runtime path from configuration, not hardcoded.
- The CI/CD pipeline MUST test with both `youki` and `crun`.
- `runc` is explicitly not supported; it introduces a Go toolchain dependency.

---

## ADR-011: Use ChaCha20-Poly1305 for Symmetric Encryption

**Status:** Accepted  
**Deciders:** Core team  
**Date:** Project inception

### Context

We need an AEAD (Authenticated Encryption with Associated Data) cipher for:

- Vault encryption (mnemonic at rest)
- DHT coordinate blob encryption
- Future: Ghost payload encryption

### Options Considered

| Cipher | Hardware Accel | Side-Channel | Notes |
|--------|----------------|--------------|-------|

| **ChaCha20-Poly1305** | Software (no hw needed) | Resistant (no timing variance) | Preferred for software implementations |
| AES-256-GCM | Yes (AES-NI) | Timing attacks without AES-NI | Current code uses this in some places |
| AES-256-CCM | Yes | Similar to GCM | Less common |

### Decision

**ChaCha20-Poly1305 as the primary AEAD.** It has no timing-side-channel vulnerabilities in software implementations (unlike AES-GCM without AES-NI). It is the standard for software-only cryptographic systems.

### Consequences

- **The current `dht.rs` and `vault.rs` use AES-256-GCM. This MUST be changed to ChaCha20-Poly1305** to be consistent with the design spec and architecture.
- The `chacha20poly1305` crate from RustCrypto is already in workspace dependencies.
- `aes-gcm` is removed from workspace dependencies once the migration is complete.

---

## ADR-012: Traffic Morphing is Always-On

**Status:** Accepted  
**Deciders:** Core team  
**Date:** Project inception

### Context

Traffic analysis (observing connection timing, packet sizes, and rates) can reveal communication patterns even when payload content is encrypted. This is especially relevant for a privacy-focused system.

### Decision

Traffic morphing (chaff injection) is **always on** and is not user-configurable to disable. It is a core security invariant, not a feature.

Rationale: If it's optional, users who disable it become identifiable by their absence of chaff. The protection is only effective if all nodes participate.

### Consequences

- `morph::send_chaff_stream` runs as a background task for every active QUIC connection.
- The chaff overhead (64–512 bytes every 50–150ms per connection) is considered an acceptable bandwidth cost.
- Chaff frames use `msg_type = 0xFF` and are silently discarded by receivers.
- No configuration option to disable chaff will be added.

---

## ADR-013: Cgroup v2 Required; No v1 Support

**Status:** Accepted  
**Deciders:** Core team  
**Date:** Phase 3 planning

### Context

TSC requires resource limiting for Ghost-Boxes. Linux cgroups come in two versions with different APIs and capabilities.

### Decision

**Cgroups v2 only.** v2 provides a unified hierarchy and better memory isolation semantics. v1 is fragmented and has known security issues with hierarchical accounting.

Minimum kernel requirement: Linux ≥ 5.15 (LTS with stable cgroups v2 and io_uring).

### Consequences

- If cgroups v2 is not mounted at `/sys/fs/cgroup`, `tscd` MUST fail to start with a clear error message.
- This sets a minimum OS requirement. Debian 12+, Ubuntu 22.04+, Fedora 31+ are all supported.
- Older distros (Ubuntu 20.04 with v1 by default) are NOT supported.
