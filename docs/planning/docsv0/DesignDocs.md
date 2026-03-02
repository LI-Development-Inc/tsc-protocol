# 1. ARCHITECTURE.md: The Domain Isolation Model

**Title:** The Standalone Complex (TSC) - Core Architecture v2.0

## 1.1 Structural Philosophy

TSC is not a monolithic application; it is a micro-architecture defined by strict boundary enforcement. It operates across three physically and cryptographically isolated domains:

* **The Identity Domain (Root of Trust):** An offline-capable state machine managing entropy (BIP-39) and key succession (KERI). It never touches a network socket.
* **The Transport Domain (The Pipe):** The `tscd` network daemon. It handles QUIC streams, GSP multiplexing, DHT routing, and traffic morphing. It has no access to the application data inside a Ghost.
* **The Execution Domain (The Ghost):** An OCI-compliant namespace jail running user-space applications. It has zero visibility into the host OS or the Transport Domain's cryptography.

## 1.2 Component Topology

* **`tscd` (The Shell):** The privileged Rust daemon handling local orchestration and P2P networking.
* **`tsc-window` (The Sovereign Browser):** A client utilizing a WASM-compiled micro-shell for isolated, in-browser network participation.
* **Lighthouse:** A FOSS community-run `tscd` node configured strictly for signaling and NAT traversal routing (no local Ghosts).
* **Ghost-Box:** The ephemeral `tmpfs`-backed `runC`/`crun` container environment.

---

# 2. DESIGN.md: Identity & Discovery State

**Title:** Sovereignty, Naming, and Trust Logic v2.0

## 2.1 Identity Lifecycle (KERI-Lite)

Identity is a cryptographic temporal chain, not a static key.

* **Genesis:** A user generates a 24-word seed.
* **Pre-Rotation:** The active signing key ($K_1$) signs a commitment to the hash of the next key ($\text{BLAKE3}(K_2)$).
* **Rotation:** When migrating hardware or mitigating a suspected breach, the user broadcasts a signature from $K_2$. The network accepts $K_2$ because it matches the prior commitment made by $K_1$.

## 2.2 The Triad Naming Model (Ghost-DNS)

Central registries are attack vectors. TSC uses a 3-tier local-first resolution model:

1. **GhostID:** The BLAKE3 hash of the active Persona's public key (Machine Layer).
2. **Petname:** A local, private alias stored in the user's `tsc-cli` config (User Layer).
3. **Web of Trust (WoT):** Cryptographically signed JSON manifests shared via GSP. If a user trusts Node A, they automatically resolve Node A's signed Petnames (Social Layer).

---

# 3. FEATURES.md: Sovereign Capabilities

**Title:** TSC Functional Capabilities v2.0

* **P2P OCI Swarming (Lazy-Pull):** Ghost images are distributed directly between nodes via GSP-integrated BitTorrent logic using `eStargz`. No central registry.
* **Ghost Migration (Live Teleport):** Integration with CRIU (Checkpoint/Restore in Userspace). A running Ghost's RAM is serialized, encrypted, and streamed to a new Shell over QUIC, resuming instantly.
* **Traffic Morphing:** `tscd` injects constant-rate padding (Chaff) into QUIC streams to defeat Deep Packet Inspection (DPI) metadata heuristics.
* **Legacy Bridging:** Ability to route standard TCP/UDP protocols (IRC, HTTP/3, WebRTC) through GSP streams, acting as an overlay VPN for specific Ghost-Boxes.

---

# 4. REQUIREMENTS.md: Engineering Guardrails

**Title:** TSC Hard Constraints v2.0

## 4.1 Host & Runtime Environment

* **Language:** 100% Rust (`#![forbid(unsafe_code)]` enforced in all parsers and crypto modules).
* **Kernel Capabilities:** Linux $\ge 5.15$ (requires `io_uring` for async networking, `cgroups v2` for resource limiting).
* **Containerization:** Must interface with a standard OCI runtime (e.g., `youki` or `crun`).

## 4.2 Security Invariants

* **No-Egress Default:** `CLONE_NEWNET` namespaces must be spawned with no default gateway to the host LAN. Network access is strictly a virtual tap bridged to the `tscd` GSP router.
* **Cold-Boot Protection:** The Vault encryption keys must utilize `memfd_secret` or CPU secure enclaves (if available) to prevent RAM scraping.
* **Deterministic Serialization:** All cryptographic signatures must strictly use Canonical JSON (RFC 8785) or `bincode` to prevent parsing ambiguity attacks.

---

# 5. TECHNICALSPECS.md: Cryptographic Primitives

**Title:** Applied Cryptography and Storage v2.0

## 5.1 Primitives Suite

* **Asymmetric Key Exchange:** X25519
* **Digital Signatures:** Ed25519
* **Symmetric AEAD:** ChaCha20-Poly1305
* **Hashing / KDF:** BLAKE3 / Argon2id

## 5.2 The Vault Mechanism (Data Persistence)

Ghosts are volatile. To save state, a Vault is attached:

1. **Keying:** $K_{vault} = \text{Argon2id}(\text{MasterSeed} \parallel \text{GhostID} \parallel \text{Salt})$
2. **Format:** LUKS2 volume formatted over a sparse file.
3. **Runtime Integrity:** The shell maintains a `dm-verity` Merkle tree. If the physical host file is modified while the Ghost is inactive, the cryptographic mount will hard-fail on the next boot, alerting the user to host-level tampering.
