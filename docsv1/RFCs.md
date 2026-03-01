# RFC-001: The GSP Wire Format (Transport Layer)

**Status:** PROPOSED

**Protocol:** GSP over QUIC (ALPN: `tsc-gsp-v1`)

## 1.1 Stream Multiplexing

TSC uses **QUIC Streams** to separate concerns. A single connection between two Shells can handle multiple Ghosts.

* **Stream 0 (Bidirectional):** Control Plane (Handshakes, KERI sync, Ghost spawning).
* **Stream 1..N (Bidirectional):** Data Plane (One stream per active Ghost-to-Ghost connection).

## 1.2 The Packet Frame

Every GSP message is prefixed with a length-prefixed frame to prevent "splintering" during parsing.

| Field | Type | Size | Description |
| --- | --- | --- | --- |
| `length` | `u32` | 4B | Size of the following frame (Big Endian) |
| `msg_type` | `u8` | 1B | `0x01` (Control), `0x02` (Data), `0x03` (Migration) |
| `payload` | `bytes` | Var | The encoded message (Serialized via `bincode`) |

## 1.3 Traffic Morphing (Chaffing)

To defeat Deep Packet Inspection, the GSP implementation **MUST** include a "Jitter Buffer." If real data isn't flowing, the Shell sends "Chaff" packets (random bytes) at a randomized frequency to maintain a constant-rate traffic signature.

---

# RFC-002: KERI Identity State Machine (Identity Layer)

**Status:** PROPOSED

**Format:** Canonical JSON (RFC 8785)

## 2.1 The Inception Event (IXN)

The first entry in a user's Succession Log.

```json
{
  "v": "TSC1.0",
  "t": "ixn", 
  "d": "BLAKE3_HASH_OF_THIS_OBJECT",
  "i": "PUBLIC_KEY_ED25519",
  "s": "0",
  "kt": "1",
  "k": ["PRIMARY_PUBLIC_KEY"],
  "n": "HASH_OF_NEXT_PUBLIC_KEY",
  "di": "BIP39_DERIVATION_PATH"
}

```

* **`n` (The Commitment):** This is the secret sauce. You are revealing your current key, but only the *hash* of your next one. An attacker who steals your current key cannot rotate your identity because they don't know what key matches that hash.

## 2.2 The Rotation Event (ROT)

To move to a new key, the user must publish:

1. The new Public Key (which must match the previous `n` hash).
2. A signature from the *old* key.
3. A signature from the *new* key.

---

# RFC-003: Core IPC Contract (UDS/Local Layer)

**Status:** PROPOSED

**Transport:** Unix Domain Sockets (`/run/tsc/tscd.sock`)

## 3.1 Authentication (Peer Credentials)

The `tscd` daemon **MUST** verify the UID of the process connecting to the socket.

* Only the user who started the daemon (or root) can issue commands.
* We use `getsockopt(SO_PEERCRED)` to verify the caller's identity before processing any IPC requests.

## 3.2 Command Schema (Example: Spawning a Ghost)

We use a request-response pattern over the UDS.

* **Request:** `SpawnGhost(image_hash: String, vault_id: Option<String>)`
* **Response:** `GhostStatus { pid: u32, virtual_ip: IPv6, status: Enum }`

---

# RFC-004: Ghost-Box Orchestration (Execution Layer)

**Status:** PROPOSED

## 4.1 The Jail Parameters

When `tscd` spawns a Ghost, it executes the equivalent of the following (in Rust):

1. **Namespaces:** `NEWNS | NEWUTS | NEWIPC | NEWPID | NEWNET | NEWUSER`.
2. **Mounts:** * `/` -> Read-only OCI image layer.

* `/tmp` & `/var/log` -> `tmpfs` (RAM only).
* `/vault` -> The decrypted LUKS2 block device (if persistence is requested).

1. **Cgroups v2:**

* `cpu.max`: Limited to user-defined quota.
* `memory.high`: Throttling limit.
* `memory.max`: Hard kill limit to prevent OOM (Out of Memory) on the host.

# RFC-005: Global Discovery DHT (The Lighthouse Layer)

**Status:** PROPOSED

**Protocol:** Kademlia over QUIC/UDP

**Goal:** Map a static `GhostID` to a dynamic `Encrypted_IP_Blob`.

## 5.1 The Coordinate Blob

To prevent metadata harvesting, the DHT does **not** store raw IP addresses. It stores a **Coordinate Blob**:

* **Payload:** `AES_GCM(Real_IP + Port + Timestamp)`
* **Key:** Derived from the target Ghost’s Public Key.
* **Result:** Only someone who already knows your `GhostID` (Public Key) can decrypt your current location. To everyone else, the DHT is just a sea of random noise.

## 5.2 Distance Metric & Routing

We utilize the XOR metric (standard Kademlia).

1. **FindNode:** "Who is closest to the hash of `ghost://sovereign.tsc`?"
2. **Store:** "I am the owner of `ghost://sovereign.tsc`; here is my encrypted coordinate."
3. **Lighthouse Relay:** If a node is behind a Symmetric NAT, it registers a **Relay Address** pointing to a Lighthouse. The Lighthouse acts as a "turnstile," passing encrypted packets without ever seeing the contents.

---

# RFC-006: The Vault & Persistence (Storage Layer)

**Status:** PROPOSED

**Technology:** LUKS2 + dm-verity + Argon2id

## 6.1 The "Blind Host" Invariant

The Host (The Shell) must be able to store the Vault file but **MUST NOT** be able to read it without the active Master Seed.

### The Key Wrap Chain

1. **The Root:** BIP-39 Master Seed ($S$).
2. **The Ghost-Key:** $K_g = \text{HKDF}(S, \text{Ghost_ID})$.
3. **The Storage-Key:** $K_s = \text{Argon2id}(K_g + \text{Unique_Hardware_UUID})$.

* *Why Hardware UUID?* This prevents "Portable Disk" attacks. If someone steals your hard drive but not your laptop, the Vault won't open because the Hardware UUID is missing.

## 6.2 Forensic Integrity (dm-verity)

To prevent a "Evil Maid" attack (where someone modifies your database files while you're away), the Vault uses a **Merkle Tree**:

* **The Root Hash:** When a Ghost shuts down, the Shell signs the Root Hash of the storage state.
* **Verification:** Upon next boot, every block read from the disk is hashed and compared against the tree. If a single bit was changed by the host OS, the Ghost crashes immediately.

---

# RFC-007: The Ghost-Bridge (The Legacy Proxy)

**Status:** PROPOSED

**Function:** Mapping `ghost://` to Standard Protocols.

## 7.1 The Internal Resolver

The `tscd` daemon runs a local DNS listener (e.g., `127.0.0.53:53`).

* When the Ghost-Browser asks for `api.service.tsc`, the Shell intercepts the request.
* It looks up the `GhostID` in the DHT.
* It opens a GSP stream to the target.
* It presents a **SOCKS5 Interface** to the browser.

## 7.2 Service Multiplexing

A single Ghost-Box can expose multiple "Ports" over a single GSP stream using **Stream IDs**:

* `Stream ID 80`: Routed to the Ghost's internal Nginx.
* `Stream ID 6667`: Routed to the Ghost's internal IRCd.
* `Stream ID 22`: Routed to the Ghost's internal SSH (for remote admin).

### The Final "Pre-Flight" RFC

# **RFC-008: Sovereign Binary Updates & Protocol Evolution**

* **The Mechanism:** Signed binary diffs distributed via the GSP P2P layer.
* **The Governance:** A "Threshold Signature" model where the network only accepts an update if it's signed by a quorum of trusted community keys (defined in your initial `tscd` config).
* **The Safety:** A "Rollback" state. If the new binary fails to boot 3 times, the Shell automatically reverts to the previous stable version.

---
