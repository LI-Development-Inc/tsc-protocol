# TSC Protocol — Request for Comments

**Version:** 2.0  
**Status:** Proposed (all)  
**Last Updated:** 2026-02-28

Each RFC defines a precise interface or protocol contract. Implementations MUST conform exactly. Where previous RFCs were vague or incomplete, this revision adds the missing specificity.

---

## RFC-001: The GSP Wire Format

**Status:** PROPOSED  
**Domain:** Transport  
**Implements:** ARCHITECTURE §3.2

### 1.1 Overview

The Ghost Service Protocol (GSP) is the application-layer protocol that runs over QUIC streams. It is responsible for framing messages, multiplexing Ghost connections, and performing identity handshakes.

ALPN identifier: `tsc-gsp-v1`

### 1.2 Stream Allocation

A single QUIC connection between two `tscd` nodes carries multiple logical streams:

| Stream ID | Direction | Purpose |
|-----------|-----------|---------|

| 0 | Bidirectional | Control Plane: handshakes, KERI sync, Ghost lifecycle signals |
| 1–N | Bidirectional | Data Plane: one stream per active Ghost-to-Ghost connection |
| Reserved `0xFF` | Unidirectional (outbound) | Chaff Plane: traffic morphing padding only |

Stream 0 MUST be established and the GSP handshake MUST complete before any Data Plane streams are opened.

### 1.3 Frame Format

Every GSP message uses a length-prefixed frame. All multi-byte integers are **Big Endian**.

```bash
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├───────────────────────────────────────────────────────────────┤
│                    frame_length (u32)                         │
├───────────────────────────────────────────────────────────────┤
│  msg_type (u8)  │  stream_id (u16)   │  flags (u8)            │
├───────────────────────────────────────────────────────────────┤
│                    payload (variable)                         │
│                         ...                                   │
├───────────────────────────────────────────────────────────────┤
```

| Field | Type | Size | Description |
|-------|------|------|-------------|

| `frame_length` | `u32` | 4 bytes | Byte length of everything after this field |
| `msg_type` | `u8` | 1 byte | `0x01` Control, `0x02` Data, `0x03` Migration, `0xFF` Chaff |
| `stream_id` | `u16` | 2 bytes | Logical stream identifier within this connection |
| `flags` | `u8` | 1 byte | Bit flags (see §1.4) |
| `payload` | `bytes` | Variable | `bincode`-serialized message body |

**Maximum frame size:** 65,536 bytes (64 KiB). Frames exceeding this MUST be rejected with a `ProtocolError`.

### 1.4 Frame Flags

| Bit | Mask | Meaning |
|-----|------|---------|

| 0 | `0x01` | `FIN` — This is the final frame in the stream |
| 1 | `0x02` | `SYN` — This frame opens a new logical stream |
| 2 | `0x04` | `ACK` — Acknowledgment frame |
| 3–7 | — | Reserved, MUST be zero |

### 1.5 Handshake Sequence

```bash
Alice                              Bob
  │                                 │
  │── GspHandshake(IXN, nonce_A) ──►│  (Stream 0, SYN flag)
  │                                 │  Bob verifies IXN signature
  │◄─ GspHandshake(IXN, nonce_B) ──│  Bob sends his own handshake
  │                                 │
  │── HandshakeAck(sig_over_nonce_B)►│  Alice proves key ownership
  │◄─ HandshakeAck(sig_over_nonce_A)│  Bob proves key ownership
  │                                 │
  │      [Data streams may open]    │
```

A `GspHandshake` payload contains:

- The sender's full KERI Inception Event (or latest valid Rotation Event)
- A 32-byte random challenge nonce
- A signature over the challenge nonce using the sender's active signing key

Verification steps:

1. Parse the KERI event and extract the public key.
2. Verify the event's own self-signature.
3. Derive the GhostID (`BLAKE3(canonical_json(event))`) and confirm it matches the expected peer.
4. Verify the challenge-nonce signature using the extracted public key.

If any step fails, send `HandshakeResult::Failed(reason)` and close the QUIC connection.

### 1.6 Traffic Morphing (Chaff)

See RFC-001 §1.3 for stream allocation. Chaff behavior:

- Chaff frames use `msg_type = 0xFF` and MUST be silently discarded by the receiver.
- The sender MUST generate chaff at a jittered interval of 50–150ms when the connection is otherwise idle.
- Chaff payload MUST be cryptographically random bytes (not zeroes).
- Chaff frame size MUST be drawn randomly from the range [64, 512] bytes.
- Implementation: see `tsc-net::morph`.

---

## RFC-002: KERI Identity State Machine

**Status:** PROPOSED  
**Domain:** Identity  
**Implements:** ARCHITECTURE §6

### 2.1 Overview

TSC uses a KERI-lite (Key Event Receipt Infrastructure) model to provide verifiable, self-certifying identifiers that survive key rotation without any central authority.

All events MUST be serialized using **Canonical JSON (RFC 8785)** before hashing or signing.

### 2.2 Event Types

Three event types are defined:

| Type Tag | Name | Purpose |
|----------|------|---------|

| `ixn` | Inception | Creates a new identity |
| `rot` | Rotation | Migrates to a new key pair |
| `ixl` | Interaction | Signs arbitrary data under the current key without rotating |

### 2.3 Inception Event (IXN) Schema

```json
{
  "v":  "TSC2.0",
  "t":  "ixn",
  "d":  "<BLAKE3 hash of this object with d='' >",
  "i":  "<GhostID: BLAKE3 hash of this object>",
  "s":  0,
  "kt": 1,
  "k":  ["<Ed25519 public key, base64url>"],
  "n":  "<BLAKE3 hash of next public key, base64url>",
  "di": "<SLIP-0010 derivation path, e.g. m/44'/7777'/0'/0/0>",
  "sig": "<Ed25519 signature over canonical JSON with d='', base64url>"
}
```

**Field definitions:**

| Field | Type | Description |
|-------|------|-------------|

| `v` | string | Protocol version. MUST be `"TSC2.0"`. |
| `t` | string | Event type tag. MUST be `"ixn"`. |
| `d` | string | Self-referential BLAKE3 digest. Computed with `d` set to empty string, then inserted. |
| `i` | string | The GhostID. Equal to `d`. Both are included for clarity. |
| `s` | integer | Sequence number. MUST be `0` for inception. |
| `kt` | integer | Key threshold. MUST be `1` (single-signature) in v1. |
| `k` | array | Array of active public keys (base64url encoded). Length MUST equal `kt`. |
| `n` | string | Pre-rotation commitment: `BLAKE3(next_public_key_bytes)`, base64url. |
| `di` | string | SLIP-0010 derivation path used to derive this key from the master seed. |
| `sig` | string | Ed25519 signature over canonical JSON of this object (with `sig` omitted). |

### 2.4 Rotation Event (ROT) Schema

```json
{
  "v":   "TSC2.0",
  "t":   "rot",
  "d":   "<BLAKE3 hash of this event>",
  "i":   "<GhostID (unchanged)>",
  "s":   1,
  "p":   "<BLAKE3 hash of previous event>",
  "k":   ["<new Ed25519 public key, base64url>"],
  "n":   "<BLAKE3 hash of next-next public key>",
  "sig_prev": "<Signature by previous (outgoing) key>",
  "sig_new":  "<Signature by new (incoming) key>"
}
```

**Rotation verification rules (all MUST pass):**

1. `s` MUST equal `previous_event.s + 1`.
2. `p` MUST equal `BLAKE3(canonical_json(previous_event))`.
3. `BLAKE3(k[0])` MUST equal `previous_event.n` (the pre-rotation commitment).
4. `sig_prev` MUST verify against the public key in `previous_event.k[0]`.
5. `sig_new` MUST verify against the public key in `k[0]`.
6. The new `n` MUST be a valid BLAKE3 hash (non-zero, 32 bytes).

### 2.5 Identifier Event Log (IEL)

The IEL is the ordered, append-only chain of all events for a given GhostID. Rules:

- Events MUST be applied in strict sequence order.
- The IEL MUST be persisted locally by `tscd`.
- The IEL SHOULD be gossiped to trusted peers for redundancy.
- Conflicting rotation events (two ROT events at the same sequence number) indicate a key compromise attack. The node MUST reject both and alert the user.

### 2.6 GhostID Derivation

```rust
GhostID = BLAKE3(canonical_json(IXN_with_d_field_empty))
```

The `d` field of the IXN is first computed using this formula, then re-inserted into the object. This creates a self-referential digest (the event is its own identifier). The `i` field is set equal to `d`.

---

## RFC-003: IPC Command Contract

**Status:** PROPOSED  
**Domain:** Transport / Identity  
**Implements:** ARCHITECTURE §4 (tscd IPC interface)

### 3.1 Transport

- **Socket path:** `/run/tsc/tscd.sock`
- **Authentication:** `getsockopt(SO_PEERCRED)` — caller UID MUST match the daemon owner UID, or be root (`uid == 0`).
- **Serialization:** `bincode` (little-endian, length-prefixed internally by bincode).
- **Framing:** A `u32` length prefix MUST be written before each `bincode`-serialized payload to allow reliable stream reading. This prevents partial-read bugs.

```rust
[u32: payload_length][bytes: bincode_payload]
```

### 3.2 Command Schema

```rust
pub enum GhostCommand {
    /// Heartbeat check.
    Ping,
    /// Create a new sovereign identity. Generates entropy, creates IXN, locks vault.
    InitIdentity,
    /// Load an existing identity from a mnemonic phrase.
    RecoverIdentity { mnemonic: String },
    /// Return current daemon status: GhostID, vault state, peer count.
    Status,
    /// Resolve a GhostID to a network address via DHT.
    Resolve { ghost_id: String },
    /// Establish a GSP connection to a peer.
    Connect { ghost_id: String },
    /// Send an encrypted message to a connected peer.
    SendMessage { target_id: String, content: String },
    /// Spawn a new Ghost-Box from an OCI image hash.
    SpawnGhost { image_hash: String, vault_id: Option<String> },
    /// List all currently running Ghost processes.
    ListGhosts,
    /// Terminate a running Ghost by ID.
    StopGhost { ghost_id: String },
    /// Rotate the active signing key.
    RotateKey,
}
```

### 3.3 Response Schema

```rust
pub enum GhostResponse {
    /// Generic success.
    Ok(String),
    /// Error with human-readable reason.
    Err(String),
    /// 24-word mnemonic after InitIdentity.
    Mnemonic(Vec<String>),
    /// Daemon status report.
    Status(DaemonStatus),
    /// A resolved network address.
    Resolved { ghost_id: String, addr: String },
    /// Link established to a remote peer.
    LinkEstablished { remote_id: String, addr: String },
    /// Message delivered confirmation.
    MessageSent { target_id: String },
    /// Ghost spawned successfully.
    GhostSpawned { pid: u32, virtual_ip: String },
    /// List of running Ghosts.
    GhostList(Vec<GhostInfo>),
    /// Ghost stopped.
    GhostStopped { ghost_id: String },
    /// Key rotation completed. New GhostID is stable; only the signing key changes.
    KeyRotated { new_public_key: String },
}

pub struct DaemonStatus {
    pub ghost_id: String,
    pub vault_state: VaultState,
    pub peer_count: usize,
    pub active_ghosts: usize,
    pub uptime_secs: u64,
}

pub enum VaultState {
    Unlocked,
    Locked,
    Ephemeral, // No vault on disk; identity is session-only
}

pub struct GhostInfo {
    pub ghost_id: String,
    pub pid: u32,
    pub virtual_ip: String,
    pub status: String,
    pub uptime_secs: u64,
}
```

### 3.4 Error Handling

All errors MUST return `GhostResponse::Err(String)`. The error string SHOULD follow the format:

```bash
"<MODULE>:<ERROR_CODE>: <human description>"
```

Example: `"IDENTITY:NO_VAULT: No vault found at /run/tsc/vault.bin. Run 'init' first."`

---

## RFC-004: Ghost-Box Orchestration

**Status:** PROPOSED  
**Domain:** Execution  
**Implements:** ARCHITECTURE §3.3

### 4.1 Overview

A Ghost-Box is an ephemeral OCI-compliant container environment. It is the execution unit of TSC. Each Ghost runs in complete isolation from the host OS, other Ghosts, and the cryptographic state of the shell.

### 4.2 Namespace Configuration

When `tscd` spawns a Ghost, the following Linux namespaces MUST be created:

| Namespace | Flag | Purpose |
|-----------|------|---------|

| Mount | `CLONE_NEWNS` | Isolated filesystem view |
| UTS | `CLONE_NEWUTS` | Isolated hostname (set to Ghost ID prefix) |
| IPC | `CLONE_NEWIPC` | Isolated System V IPC and POSIX message queues |
| PID | `CLONE_NEWPID` | Isolated process tree (Ghost PID 1 is container init) |
| Network | `CLONE_NEWNET` | Isolated network stack; no host LAN gateway |
| User | `CLONE_NEWUSER` | UID/GID mapping (Ghost root = unprivileged host UID) |

### 4.3 Filesystem Layout

| Mount Point | Source | Type | Options |
|-------------|--------|------|---------|

| `/` | OCI image rootfs | overlay | `ro` (read-only) |
| `/tmp` | — | tmpfs | `rw`, `size=64m`, `noexec` |
| `/var/log` | — | tmpfs | `rw`, `size=16m`, `noexec` |
| `/run` | — | tmpfs | `rw`, `size=8m`, `noexec` |
| `/vault` | LUKS2 block device | ext4 | `rw`, only if persistence requested |
| `/dev` | — | devtmpfs | Minimal device set only |

The `/vault` mount MUST NOT be present if no persistence was requested. Omission is enforced by the spawn parameters, not by runtime checks.

### 4.4 Cgroup v2 Resource Limits

All Ghosts MUST be placed in a named cgroup under `/sys/fs/cgroup/tsc/<ghost_id>/`:

| Controller | Key | Default | Notes |
|------------|-----|---------|-------|

| `cpu` | `cpu.max` | `50000 100000` | 50% of one CPU |
| `memory` | `memory.high` | `384m` | Soft throttle limit |
| `memory` | `memory.max` | `512m` | Hard kill limit |
| `memory` | `memory.swap.max` | `0` | No swap |
| `io` | `io.max` | `rbps=50m wbps=20m` | I/O bandwidth cap |

All limits are user-configurable at spawn time but cannot exceed host-defined maximums.

### 4.5 Network Architecture

The Ghost network namespace has:

- A virtual ethernet pair: `veth-<ghost_id_prefix>` (host side) ↔ `eth0` (Ghost side)
- Ghost `eth0` address: a link-local IPv6 address derived from the GhostID
- Host veth is bridged to the `tscd` virtual tap (`tsc0`)
- `tsc0` routes all Ghost traffic through the GSP data plane
- No default IPv4 or IPv6 gateway to the host LAN is configured

```bash
Ghost eth0 (fd00:ghost::/64)
    │
    ▼
veth pair
    │
    ▼
tsc0 bridge (tscd-managed)
    │
    ▼
GSP Data Plane (QUIC stream)
    │
    ▼
Remote Ghost
```

### 4.6 OCI Runtime Integration

TSC interfaces with an external OCI runtime (`youki` preferred; `crun` acceptable). The spawn call:

```markdown
<runtime> run \
  --bundle <path_to_ghost_bundle> \
  --root   <path_to_state_dir> \
  <ghost_id>
```

The bundle directory MUST contain a `config.json` generated by `tsc-runtime::oci` conforming to OCI Runtime Spec v1.1.

### 4.7 Ghost Lifecycle

```markdown
Requested → Provisioning → Running → [Migrating] → Terminating → Terminated
```

| State | Description |
|-------|-------------|

| Requested | Spawn command received, image not yet verified |
| Provisioning | Image pulled/verified, namespace setup in progress |
| Running | Container init process alive, network bridge active |
| Migrating | CRIU checkpoint in progress (see RFC-007) |
| Terminating | SIGTERM sent; cleanup in progress |
| Terminated | All resources released |

---

## RFC-005: Global Discovery DHT

**Status:** PROPOSED  
**Domain:** Transport  
**Implements:** ARCHITECTURE §7

### 5.1 Overview

TSC uses libp2p's Kademlia DHT to map a static GhostID to a dynamic, encrypted network coordinate (IP + port). The DHT is a privacy-preserving lookup table — to an outside observer, all DHT values are indistinguishable ciphertext.

### 5.2 The Coordinate Blob

DHT values are never raw IP addresses. They are **Coordinate Blobs**:

```rust
CoordinateBlob {
    ciphertext: bytes,  // AES-256-GCM encrypted RawCoordinate
    nonce:      [u8; 12],
    version:    u8,     // Schema version, currently 1
}

RawCoordinate {
    addr:      SocketAddr,   // IP:port of the QUIC endpoint
    timestamp: u64,          // Unix timestamp (seconds)
    relay_addr: Option<SocketAddr>, // If behind symmetric NAT, Lighthouse relay
}
```

**Encryption key:** `HKDF-SHA256(persona_active_key_bytes, salt="tsc-dht-coord-v1", length=32)`

This key is distinct from the vault storage key. Only a peer who knows the GhostID's public key (which they obtain from the KERI Inception Event) can derive this key and decrypt the coordinate.

### 5.3 Record Freshness

- Records MUST include a timestamp.
- Records older than **3600 seconds (1 hour)** MUST be treated as stale and ignored.
- Nodes MUST re-publish their coordinate every **900 seconds (15 minutes)**.

### 5.4 DHT Operations

| Operation | Description |
|-----------|-------------|

| `PUT_COORDINATE` | Publish or refresh the local node's coordinate. Key = `BLAKE3(ghost_id_bytes)`. |
| `GET_COORDINATE` | Retrieve a peer's coordinate by GhostID. Returns raw ciphertext blob. |
| `FIND_NODE` | Standard Kademlia: find nodes closest to a target key. |

### 5.5 Lighthouse Nodes

Lighthouse nodes are `tscd` instances with no local Ghosts. Their only function is:

1. Kademlia routing (holding DHT records, forwarding FIND_NODE queries).
2. Acting as QUIC relays for nodes behind symmetric NAT that cannot receive direct connections.

Lighthouse operators MUST configure:

```toml
[lighthouse]
relay_enabled = true
max_relayed_bandwidth_mbps = 10
ghost_hosting = false
```

A relay session is a blind forwarding pipe. The Lighthouse sees only encrypted QUIC packets and never the plaintext content.

### 5.6 mDNS Local Discovery

For LAN-local scenarios, `tscd` MUST also run an mDNS discovery loop. Peers discovered via mDNS are added to the Kademlia routing table. This allows two TSC nodes on the same network to find each other without any Lighthouse.

---

## RFC-006: The Vault & Persistence

**Status:** PROPOSED  
**Domain:** Identity  
**Implements:** ARCHITECTURE §3.1, Threat Model (Evil Maid, Host OS)

### 6.1 The Key Derivation Chain

```bash
[User Input]
    24-word BIP-39 Mnemonic
         │
         ▼
    512-byte Master Seed
    (BIP-39 PBKDF2: 2048 rounds, no passphrase in v1)
         │
         ├─► K1 = SLIP-0010(seed, "m/44'/7777'/0'/0/0")   ← Active signing key
         │
         ├─► K2 = SLIP-0010(seed, "m/44'/7777'/0'/0/1")   ← Pre-rotation key
         │        BLAKE3(K2.public) stored as IXN.n
         │
         └─► K_ghost = HKDF-SHA256(seed, salt="tsc-ghost-key-v1")
                  │
                  ▼
             K_storage = Argon2id(K_ghost ‖ HW_UUID, salt=random_16_bytes, t=3, m=65536, p=4)
```

**Argon2id parameters:**

- Time cost (`t`): 3 iterations
- Memory cost (`m`): 65536 KiB (64 MiB)
- Parallelism (`p`): 4 lanes
- Output length: 32 bytes
- Salt: 16 random bytes, stored in the vault header (NOT hardcoded)

### 6.2 Vault File Format

The vault is a single binary file stored at a configurable path (default: `$XDG_DATA_HOME/tsc/vault.bin`).

```markdown
┌──────────────────────────────────────┐
│  MAGIC: b"TSCVAULT" (8 bytes)        │
├──────────────────────────────────────┤
│  Version: u8 (currently 0x01)        │
├──────────────────────────────────────┤
│  Argon2id Salt: [u8; 16]             │
├──────────────────────────────────────┤
│  ChaCha20-Poly1305 Nonce: [u8; 12]   │
├──────────────────────────────────────┤
│  Encrypted Payload Length: u32       │
├──────────────────────────────────────┤
│  Encrypted Payload: bytes            │
│  (ChaCha20-Poly1305 ciphertext +     │
│   16-byte Poly1305 authentication    │
│   tag appended)                      │
└──────────────────────────────────────┘
```

The vault ciphertext decrypts to a UTF-8 string of the 24 space-separated mnemonic words.

### 6.3 Hardware UUID Binding

The `K_storage` derivation includes the hardware UUID (`/sys/class/dmi/id/product_uuid` on Linux). This binds the vault to the specific machine.

- If the UUID is unavailable (VM, container, or unsupported hardware), a SHA-256 hash of persistent system identifiers (machine-id, CPU model string) MUST be used as a fallback.
- The fallback MUST be logged as a warning. It provides weaker binding than a DMI UUID.
- The fallback MUST NOT be the static string `"FALLBACK_STATIC_ID_DO_NOT_USE_IN_PROD"`.

### 6.4 LUKS2 Ghost Persistence Volume

For Ghosts that request persistent state, `tscd` provisions a LUKS2 sparse file:

1. Create a sparse file at `$XDG_DATA_HOME/tsc/vaults/<ghost_id>.img`.
2. Format with `cryptsetup luksFormat` using `K_storage` as the passphrase.
3. Open the device: `cryptsetup luksOpen ... tsc-<ghost_id>`.
4. Format the plaintext device as ext4.
5. Mount at `/vault` inside the Ghost namespace.

On Ghost shutdown:

1. Unmount `/vault`.
2. Record the dm-verity root hash: `veritysetup format ...`.
3. Sign the root hash with the Ghost's active key.
4. Store the signed hash in `$XDG_DATA_HOME/tsc/vaults/<ghost_id>.roothash`.

On next Ghost boot:

1. Open LUKS2 device.
2. Verify dm-verity tree against stored root hash.
3. If verification fails: refuse to mount, alert user of potential tampering.

---

## RFC-007: The Ghost-Bridge (Legacy Proxy)

**Status:** PROPOSED  
**Domain:** Execution / Transport  
**Implements:** ARCHITECTURE §3.3

### 7.1 Purpose

The Ghost-Bridge allows applications inside a Ghost-Box that speak standard TCP/UDP protocols to communicate with the outside world (other Ghosts or Legacy Nodes) through the GSP Data Plane. The Ghost application is unaware it is using GSP.

### 7.2 SOCKS5 Interface

`tscd` runs a SOCKS5 proxy server inside the Ghost's network namespace on `127.0.0.1:1080`. Ghost applications that support SOCKS5 (most modern HTTP clients, curl, etc.) can be configured to use this endpoint.

The SOCKS5 server:

- Intercepts `CONNECT <hostname>:<port>` requests.
- Resolves `*.tsc` hostnames via the local DNS resolver (§7.3).
- Opens a GSP Data Plane stream to the target Ghost.
- Bidirectionally forwards bytes between the TCP socket and the GSP stream.

### 7.3 Local DNS Resolver

`tscd` runs a DNS listener on `127.0.0.53:53` in the Ghost's network namespace.

Resolution logic:

1. If hostname ends in `.tsc`: extract the GhostID or Petname, resolve via DHT (RFC-005).
2. If hostname is a known Petname: resolve via local Petname cache.
3. Otherwise: forward to the host's configured resolver (allows legacy internet access, subject to operator policy).

### 7.4 Stream ID Mapping

A single Ghost-to-Ghost GSP connection can serve multiple application ports via stream IDs:

| Service | Conventional Stream ID |
|---------|------------------------|

| HTTP(S) | 80 / 443 |
| SSH | 22 |
| IRC | 6667 |
| Custom | Negotiated on control stream |

Stream IDs are negotiated on the GSP Control Plane (Stream 0) before data flows.

### 7.5 Legacy Node Bridging

For communicating with non-TSC internet services, `tscd` can act as an exit node (similar to a Tor exit node) for a Ghost's traffic. This is an opt-in configuration:

```toml
[ghost.network]
allow_legacy_egress = true
legacy_egress_domains = ["api.example.com"]  # Allowlist
```

All legacy egress traffic is logged (metadata only) in the Ghost's volatile `/var/log`.

---

## RFC-008: Sovereign Binary Updates

**Status:** PROPOSED  
**Domain:** Transport  
**Implements:** ARCHITECTURE §A4 (No Central Registry)

### 8.1 Overview

TSC software updates are distributed over the GSP P2P layer, not from a central server. Updates are accepted only if they bear a valid threshold signature from a quorum of trusted community keys.

### 8.2 Update Manifest

```json
{
  "v": "TSC2.0",
  "t": "update",
  "version": "0.2.0",
  "prev_version": "0.1.0",
  "target_arch": "x86_64-unknown-linux-gnu",
  "binary_hash": "<BLAKE3 of new binary>",
  "diff_hash": "<BLAKE3 of binary diff>",
  "diff_url": "ghost://<distributor_id>/updates/0.2.0.patch",
  "signatures": [
    { "key_id": "<public key fingerprint>", "sig": "<Ed25519 signature over manifest with sig omitted>" },
    ...
  ],
  "threshold": 3
}
```

### 8.3 Verification Rules

1. Count valid signatures from keys listed in the local `update-keys.json`.
2. Count MUST be `>= threshold`.
3. The BLAKE3 hash of the downloaded binary MUST match `binary_hash`.
4. The new binary MUST successfully start and pass a self-test within 30 seconds.
5. If the new binary fails to start 3 consecutive times, automatically revert to the previous version.

### 8.4 Key Governance

Community update keys are defined in `update-keys.json`, distributed with the initial installation. Adding or removing keys requires a new update manifest signed by the current quorum.

---

## RFC-009: Secure Key Memory

**Status:** PROPOSED  
**Domain:** Identity  
**Implements:** ARCHITECTURE Threat Model (Cold-Boot)

### 9.1 Threat

Key material held in standard heap memory is vulnerable to:

- Cold-boot attacks (reading RAM after power cycle)
- `/proc/<pid>/mem` reads by a compromised host OS
- Core dumps

### 9.2 `memfd_secret` (Linux ≥ 5.14)

When available, active signing key bytes MUST be stored in a `memfd_secret` allocation:

```rust
// Pseudo-code
let fd = unsafe { libc::syscall(libc::SYS_memfd_secret, 0u64) };
// mmap the fd and write key bytes
// This memory is excluded from /proc/pid/mem, swap, and core dumps
```

### 9.3 Zeroization on Drop

All key structs MUST implement the `zeroize::Zeroize` trait. Key memory MUST be zeroed before deallocation. The `zeroize` crate provides this via the `ZeroizeOnDrop` derive macro.

### 9.4 Fallback

If `memfd_secret` is unavailable (older kernel, non-Linux), use `mlock` to prevent the key pages from being swapped to disk. Log a warning that full cold-boot protection is not available.

### 9.5 `mlock` Budget

`mlock` is limited per-process by `RLIMIT_MEMLOCK`. `tscd` MUST set this limit high enough to lock all active key material at startup, or fail with a clear error message.

---

## RFC-010: Identity Boot Sequence

**Status:** PROPOSED  
**Domain:** Identity  
**Implements:** ARCHITECTURE §6, RFC-006

### 10.1 Problem

The current `tscd` startup generates a fresh ephemeral `SigningKey` before checking the vault. This means every restart creates a new GhostID, making identity non-persistent. This is the opposite of intended behavior.

### 10.2 Correct Boot Sequence

```bash
tscd starts
    │
    ▼
[1] Read HW_UUID from DMI (or fallback)
    │
    ▼
[2] Probe for vault file at $XDG_DATA_HOME/tsc/vault.bin
    │
    ├─► [Vault Found]
    │       │
    │       ▼
    │   Prompt user for mnemonic (or read from stdin/env in non-interactive mode)
    │   Derive K_storage from mnemonic + HW_UUID
    │   Unlock vault → extract mnemonic words
    │   Derive K1, K2 via SLIP-0010 (RFC-012)
    │   Reconstruct Persona from IEL (load from identity store)
    │   Verify IEL tip signature matches K1
    │   Initialize NetStack with persistent GhostID
    │   Log: "[+] Identity Loaded: <GhostID prefix>"
    │
    └─► [No Vault]
            │
            ▼
        Log: "[!] No vault found. Running in ephemeral mode."
        Generate ephemeral key (NOT derived from mnemonic)
        Assign ephemeral GhostID (prefixed with "ephemeral:")
        Do NOT write vault file
        Log: "[!] Ephemeral GhostID: <id>. Run 'tsc-cli init' to create persistent identity."
```

### 10.3 Non-Interactive Unlock

For headless deployments, the mnemonic MAY be provided via:

- Environment variable: `TSC_MNEMONIC="word1 word2 ... word24"` (NOT recommended for production; logged as security warning)
- A named pipe or file descriptor: `TSC_MNEMONIC_FD=3`
- A hardware security module (HSM) interface (future work)

### 10.4 Vault Path Configuration

The vault path MUST be configurable via `$XDG_DATA_HOME/tsc/` (default) or a `--vault-path` flag. It MUST NOT be hardcoded to `/tmp/`.

---

## RFC-011: Shared Protocol Crate (`tsc-proto`)

**Status:** PROPOSED  
**Domain:** All  
**Implements:** ARCHITECTURE §4 (Component Inventory)

### 11.1 Problem

`GhostCommand` and `GhostResponse` are currently duplicated in:

- `crates/tscd/src/ipc.rs`
- `crates/tsc-cli/src/proto.rs`

These two copies will inevitably diverge, causing serialization mismatches and silent bugs.

### 11.2 Solution

Extract all shared IPC types into a new `tsc-proto` crate:

```bash
crates/tsc-proto/
    Cargo.toml
    src/
        lib.rs        ← re-exports everything
        commands.rs   ← GhostCommand enum
        responses.rs  ← GhostResponse, DaemonStatus, GhostInfo, VaultState enums
        framing.rs    ← IPC framing: u32 length prefix read/write helpers
```

Both `tscd` and `tsc-cli` MUST depend on `tsc-proto`. Neither may define their own copies of these types.

### 11.3 Versioning

The `tsc-proto` crate MUST include a protocol version constant:

```rust
pub const PROTO_VERSION: u32 = 1;
```

The IPC handshake MUST exchange and verify protocol versions before processing commands.

---

## RFC-012: SLIP-0010 Hierarchical Key Derivation

**Status:** PROPOSED  
**Domain:** Identity  
**Implements:** ARCHITECTURE §6, RFC-006 §6.1

### 12.1 Problem

`bip39.rs` currently slices `seed[0..32]` directly as the Ed25519 signing key. This is cryptographically incorrect — the 512-byte BIP-39 seed is not a valid Ed25519 private key format, and using raw bytes bypasses all derivation hardening.

### 12.2 SLIP-0010 Derivation

TSC MUST use SLIP-0010 (BIP-32 for non-secp256k1 curves, including Ed25519) for all key derivation.

**Derivation paths:**

| Purpose | Path |
|---------|------|

| Active signing key (K1) | `m/44'/7777'/0'/0'/0'` |
| Pre-rotation key (K2) | `m/44'/7777'/0'/0'/1'` |
| Future rotation key (K3) | `m/44'/7777'/0'/0'/2'` |
| Ghost-specific key | `m/44'/7777'/1'/<ghost_index>'` |

Note: Coin type `7777'` is a placeholder for TSC. A real BIP-44 registration should be pursued.

All paths use **hardened derivation** (indicated by `'`). Non-hardened paths MUST NOT be used for signing keys.

### 12.3 Implementation

Use the `slip10_ed25519` or `ed25519-bip32` Rust crate for derivation. The implementation MUST:

1. Accept the 512-byte BIP-39 master seed as input.
2. Derive the SLIP-0010 master key: `HMAC-SHA512("ed25519 seed", seed_bytes)`.
3. Apply child derivations for each path component using hardened HMAC-SHA512.
4. Output a valid 32-byte Ed25519 scalar.

### 12.4 Next-Key Pre-Commitment

At identity creation time, BOTH K1 and K2 MUST be derived. K2's public key is hashed with BLAKE3 and stored as the `n` field in the Inception Event. K2's private key bytes MUST be zeroized from memory after the hash is computed (it should only be re-derived from the mnemonic when a rotation is requested).
