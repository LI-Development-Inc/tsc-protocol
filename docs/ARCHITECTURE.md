# The Standalone Complex (TSC) — System Architecture

**Version:** 3.0  
**Status:** Authoritative  
**Last Updated:** 2026-02-28

---

## 1. Mission Statement

The Standalone Complex is a sovereign P2P runtime stack. Its purpose is to let any person run services, communicate, and persist data without requiring trust in any third party — no DNS registrar, no certificate authority, no cloud provider, no platform. The system's security model is rooted in cryptographic identity, not organizational trust.

This document defines the canonical architecture. All RFCs, ADRs, and implementation work derive from this foundation.

---

## 2. Core Design Axioms

These are non-negotiable constraints that shape every design decision:

| # | Axiom | Implication |
|---|-------|-------------|

| A1 | **Zero Trust by Default** | No component trusts another without cryptographic proof. |
| A2 | **Identity Precedes Network** | A node cannot participate in the network until it has a verified cryptographic identity. |
| A3 | **The Host is Untrusted** | The machine running TSC is treated as a potential adversary. Data at rest must be protected from the host OS. |
| A4 | **No Central Registry** | No component may depend on a centrally-controlled naming or routing authority for correctness. |
| A5 | **Metadata is Data** | Traffic patterns, timing, and connection graphs are treated as sensitive as payload content. |
| A6 | **Ephemerality is Safety** | Computation is volatile by default. Persistence is an explicit, audited privilege. |
| A7 | **Rust Enforced Safety** | `#![forbid(unsafe_code)]` in all parser, crypto, and protocol modules. No exceptions. |

---

## 3. The Three-Domain Model

TSC enforces strict physical and cryptographic boundaries between three isolated domains. No domain has direct access to the internals of another. Communication between domains happens only through defined, authenticated interfaces.

```bash
┌─────────────────────────────────────────────────────────────┐
│                    HOST MACHINE                             │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │           IDENTITY DOMAIN (Root of Trust)           │   │
│  │   tsc-crypto: BIP-39, SLIP-0010, KERI, Vault        │   │
│  │   ● No network socket access. Ever.                 │   │
│  │   ● Holds master entropy and key succession state   │   │
│  └──────────────────────┬──────────────────────────────┘   │
│                         │ Signed Identity Assertions        │
│  ┌──────────────────────▼──────────────────────────────┐   │
│  │          TRANSPORT DOMAIN (The Pipe)                │   │
│  │   tscd: QUIC/GSP, DHT, Traffic Morphing, IPC        │   │
│  │   ● Sees encrypted blobs only, not Ghost payloads   │   │
│  │   ● Owns the network socket and routing state       │   │
│  └──────────────────────┬──────────────────────────────┘   │
│                         │ Virtual TAP (no LAN gateway)      │
│  ┌──────────────────────▼──────────────────────────────┐   │
│  │          EXECUTION DOMAIN (The Ghost)               │   │
│  │   tsc-runtime: OCI Namespace Jail, Vault Mount      │   │
│  │   ● Zero visibility into host OS or crypto keys     │   │
│  │   ● All network egress flows through TSC daemon     │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 3.1 The Identity Domain

**Crate:** `tsc-crypto`  
**Threat model:** Even if the host OS is compromised, an attacker must not be able to impersonate or rotate the user's identity without the physical master seed.

- Manages all entropy generation (BIP-39, 24-word mnemonic).
- Performs SLIP-0010 hardened key derivation from the master seed.
- Maintains the KERI-lite Identifier Event Log (IEL) for verifiable key succession.
- Provides the Vault mechanism: Argon2id KDF over a hardware-bound key, encrypting the mnemonic at rest with ChaCha20-Poly1305.
- **Hard constraint:** This domain never opens, reads from, or writes to a network socket.

### 3.2 The Transport Domain

**Crate:** `tsc-net`, **Binary:** `tscd`  
**Threat model:** A network-level adversary should learn nothing about who is communicating with whom, or what the content is.

- Operates the QUIC endpoint, multiplexed via the Ghost Service Protocol (GSP).
- Maintains the libp2p/Kademlia DHT for GhostID-to-coordinate resolution.
- Enforces Traffic Morphing (chaff injection) to defeat DPI.
- Presents the IPC Unix Domain Socket to the CLI and future frontends.
- **Hard constraint:** This domain sees only encrypted payloads tagged with stream IDs. It cannot access plaintext Ghost data.

### 3.3 The Execution Domain

**Crate:** `tsc-runtime`  
**Threat model:** A compromised Ghost must not be able to escape the jail, access the host filesystem, observe other Ghosts, or touch cryptographic key material.

- Spawns OCI-compliant namespace jails (`CLONE_NEWNS | NEWUTS | NEWIPC | NEWPID | NEWNET | NEWUSER`).
- Mounts the root filesystem read-only. Only `/tmp`, `/var/log` (tmpfs), and `/vault` (LUKS2, if persistence requested) are writable.
- Enforces cgroups v2 resource limits (CPU, memory hard kill limit).
- Bridges legacy TCP/UDP traffic from Ghost applications into GSP streams.
- **Hard constraint:** Ghost network namespace has no default gateway to the host LAN. All outbound traffic routes through the TSC virtual tap.

---

## 4. Component Inventory

| Component | Type | Domain | Responsibility |
|-----------|------|--------|----------------|

| `tsc-crypto` | Library crate | Identity | BIP-39, SLIP-0010, KERI, Vault |
| `tsc-net` | Library crate | Transport | GSP framing, DHT, Traffic Morphing |
| `tsc-runtime` | Library crate | Execution | Jail, OCI, Bridge |
| `tscd` | Binary (daemon) | Transport | Orchestrator, IPC server, lifecycle manager |
| `tsc-cli` | Binary (CLI) | User Interface | Command interface to `tscd` via UDS |
| `tsc-proto` | Library crate | Shared | IPC command/response type definitions *(to be extracted)* |
| `Lighthouse` | `tscd` variant | Transport | Signaling-only node; no local Ghosts |
| `tsc-window` | WASM binary | User Interface | Sovereign browser-based interface *(future)* |

---

## 5. Data Flow: Sending a Message

End-to-end flow when a user sends an encrypted message to a remote Ghost:

```markdown
tsc-cli "send <GhostID> <content>"
    │
    ▼
[1] tsc-cli serializes GhostCommand::SendMessage via bincode
    │  (Unix Domain Socket: /run/tsc/tscd.sock)
    ▼
[2] tscd::ipc validates SO_PEERCRED (caller UID must match daemon owner)
    │
    ▼
[3] tsc-net::resolve_ghost queries DHT for GhostID → CoordinateBlob
    │  CoordinateBlob is decrypted using KDF-derived key
    ▼
[4] tsc-net::NetStack::connect opens QUIC connection to remote SocketAddr
    │  GSP handshake: sends InceptionEvent, receives challenge, signs response
    ▼
[5] GspConnection::open_ghost_stream opens bidirectional QUIC stream
    │
    ▼
[6] Content is written to the stream, wrapped in GspFrame (MsgType::Data)
    │  (morph.rs chaff continues injecting on idle streams in parallel)
    ▼
[7] Remote tscd receives frame, validates GhostID, routes to target Ghost
    │
    ▼
[8] GhostResponse::MessageSent returned to tsc-cli
```

---

## 6. Identity Lifecycle

```markdown
[Genesis]
  User generates 24-word BIP-39 mnemonic
  SLIP-0010 derives K1 (active) and K2 (next, pre-committed as BLAKE3(K2))
  KERI Inception Event (IXN) is created, signed by K1
  GhostID = BLAKE3(canonical_json(IXN))
  IXN is broadcast to the DHT

[Operation]
  All network messages are signed by K1
  The commitment BLAKE3(K2) is public in the IXN

[Rotation]
  User publishes a Rotation Event (ROT):
    - Reveals K2 (which must match BLAKE3(K2) from IXN)
    - Signed by both K1 (old key) and K2 (new key)
    - Pre-commits to BLAKE3(K3) (next future key)
  Network verifies K2 matches prior commitment before accepting ROT
  K1 is retired. K2 becomes the active signing key.

[Recovery]
  If K1 is compromised before rotation:
    Attacker cannot rotate because they don't know K2
    User must rotate from K2 before the attacker can publish a fraudulent ROT
```

---

## 7. Naming and Discovery Model

TSC uses a three-tier, local-first naming system. There is no global naming authority.

| Tier | Name | Scope | Example |
|------|------|-------|---------|

| 1 | **GhostID** | Global (machine-readable) | `blake3:7f3a2c...` |
| 2 | **Petname** | Local (user-defined alias) | `"alice-homeserver"` |
| 3 | **Web of Trust** | Social (signed by trusted peers) | Node A vouches that GhostID X is "alice" |

Resolution order: `Petname cache → Local WoT manifest → DHT lookup`

---

## 8. Threat Model Summary

| Threat | Mitigation |
|--------|------------|

| Network eavesdropping | QUIC + ChaCha20-Poly1305 per-stream encryption |
| Traffic analysis / DPI | Constant-rate chaff injection (morph.rs) |
| Identity spoofing | KERI event chain; GhostID is a cryptographic commitment |
| Key theft (current key) | Pre-rotation commitment prevents attacker from rotating identity |
| Cold-boot RAM scraping | `memfd_secret` for key material (planned: RFC-009) |
| Evil Maid (disk tampering) | dm-verity Merkle tree on Vault; mount fails if tampered |
| Container escape | Full Linux namespace isolation; no host LAN gateway |
| Host OS reading Vault | Hardware UUID bound into KDF; Vault unreadable without hardware + seed |
| Replay attacks | Per-handshake challenge nonce in GspHandshake |
| Centralized takedown | No central registry; Kademlia DHT with Lighthouse fallback |

---

## 9. What This Document Does Not Cover

- Wire format byte layout → **RFC-001**
- KERI event schema → **RFC-002**
- IPC command schema → **RFC-003**
- Ghost-Box spawn parameters → **RFC-004**
- DHT record format → **RFC-005**
- Vault key derivation → **RFC-006**
- Legacy protocol bridging → **RFC-007**
- Sovereign binary updates → **RFC-008**
- Secure key memory → **RFC-009**
- Identity boot sequence → **RFC-010**
- Shared IPC protocol crate → **RFC-011**
- SLIP-0010 key derivation → **RFC-012**
