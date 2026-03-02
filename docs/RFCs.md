# TSC Protocol RFCs

> **Status key:** ✅ Implemented · 🔧 Partial · 📋 Specified · 🔮 Future

---

# RFC-001: GSP Wire Format (Transport Layer)
**Status:** 🔧 Partial — framing implemented; stream multiplexing and ALPN pending

**Protocol:** GSP over QUIC

## 1.1 Stream Assignment

| Stream | Direction | Purpose |
|--------|-----------|---------|
| 0 | Bidirectional | Control plane: HELLO handshake, KERI sync |
| 1..N | Bidirectional | Data plane: one stream per active Ghost-to-Ghost connection |

**Current implementation:** Each `connect()` call opens a new QUIC connection.
Stream 0 carries the HELLO exchange; subsequent `open_bi()` calls carry Data frames.
True stream multiplexing (multiple Ghosts per connection) is Phase 2+.

## 1.2 Frame Format ✅

Every GSP message is wrapped in a `GspFrame`:

| Field | Type | Size | Description |
|-------|------|------|-------------|
| `length` | `u32` | 4B | Byte length of payload (bincode-encoded) |
| `msg_type` | `u8` | 1B | `0x01` Control, `0x02` Data, `0x03` Migration, `0xFF` Chaff |
| `payload` | `[u8]` | Var | bincode-encoded message body |

## 1.3 HELLO Handshake ✅ (RFC-001 §1.5)

On every new QUIC connection both sides exchange a `GspHello` in a Control frame:

```
Initiator                          Responder
   │── Control(GspHello) ──────────►│
   │◄── Control(GspHello) ──────────│
   │── Data(payload) ───────────────►│
```

`GspHello` fields:
- `ghost_id: String` — sender's GhostID (hex BLAKE3 of InceptionEvent)
- `inception: InceptionEvent` — full inception event for KERI verification

Verification steps (responder and initiator both verify the peer):
1. `inception.verify_signature()` — Ed25519 self-signature must be valid
2. `BLAKE3(inception) == ghost_id` — claimed identity must match event hash

Failure results in peer being labelled `"unverified"`. Future: hard-reject (Phase 2.2).

## 1.4 Traffic Morphing / Chaff 🔧 (Phase 2.3)

- `MsgType::Chaff` defined; ingress silently discards
- `morph.rs::send_chaff_stream()` scaffolded but not wired into write path
- Spec: `Chaff` frames sent at randomized 50–150ms intervals, 64–512 random bytes

---

# RFC-002: KERI Identity State Machine (Identity Layer)
**Status:** ✅ Implemented

**Format:** JSON with `serde` (untagged enum dispatch — see implementation note)

## 2.1 Inception Event (IXN) ✅

```json
{
  "v": "TSC1.0",
  "t": "ixn",
  "d": "<BLAKE3 of this event with sig=\"\">",
  "i": "<BLAKE3 of this event>",
  "s": "0",
  "kt": "1",
  "k": ["<Ed25519 public key hex>"],
  "n": "<BLAKE3(K2.verifying_key) hex>",
  "di": "m/44'/7777'/0'/0'/0'",
  "sig": "<Ed25519 signature hex>"
}
```

Note: `d == i` at inception (GhostID = digest of first event). This is a TSC simplification
vs. full KERI where `i` is fixed and `d` varies per event.

## 2.2 Rotation Event (ROT) ✅

```json
{
  "v": "TSC1.0",
  "t": "rot",
  "d": "<BLAKE3 of this event with sigs=\"\",\"\">",
  "i": "<GhostID — invariant>",
  "s": "<sequence number>",
  "p": "<BLAKE3 of previous event>",
  "kt": "1",
  "k": ["<new Ed25519 public key hex>"],
  "n": "<BLAKE3(K_{n+2}.verifying_key) hex>",
  "di": "m/44'/7777'/0'/0'/<n>'",
  "sig_prev": "<signature by outgoing key>",
  "sig_new": "<signature by incoming key>"
}
```

## 2.3 Event Log (IEL) ✅

- Stored as append-only JSONL at `$XDG_DATA_HOME/tsc/iel.jsonl`
- `verify_event_log()` validates: sequence order, commitment chain, all signatures
- **Serde note:** `KeyEvent` uses `#[serde(untagged)]` — the struct's own `t` field
  acts as the discriminant. Do not add `#[serde(tag = "t")]` (causes duplicate `"t"` key).

## 2.4 Key Derivation Indices

| Key | SLIP-0010 Path | Used for |
|-----|----------------|----------|
| K_0 | `m/44'/7777'/0'/0'/0'` | Inception (K1) |
| K_1 | `m/44'/7777'/0'/0'/1'` | Pre-rotation commitment at inception |
| K_n | `m/44'/7777'/0'/0'/<n>'` | Active key after rotation n |
| K_{n+1} | `m/44'/7777'/0'/0'/<n+1>'` | Pre-rotation commitment after rotation n |

---

# RFC-003: Core IPC Contract (UDS / Local Layer)
**Status:** ✅ Implemented

**Transport:** Unix Domain Sockets at `$XDG_RUNTIME_DIR/tsc/tscd.sock`

## 3.1 Authentication ✅

`tscd` verifies `SO_PEERCRED` on every incoming connection.
Only the daemon owner's UID (or root) may issue commands.

## 3.2 Framing ✅

Length-prefixed bincode frames. See `tsc-proto/src/lib.rs`:
- `write_framed()` — encode + send
- `read_framed()` — receive + decode

## 3.3 Command Schema ✅

See `tsc-proto/src/lib.rs` for full `GhostCommand` / `GhostResponse` enum definitions.

Active commands: `Ping`, `InitIdentity`, `RecoverIdentity`, `Status`,
`Resolve`, `Connect`, `SendMessage`, `ListGhosts`, `RotateKey`

Stubbed (Phase 3): `SpawnGhost`, `StopGhost`

---

# RFC-004: Ghost-Box Orchestration (Execution Layer)
**Status:** 📋 Specified — stubs in `tsc-runtime/`

## 4.1 Namespace Jail (Phase 3.1)

When `tscd` spawns a Ghost:
1. `clone(CLONE_NEWNET | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWUTS | CLONE_NEWIPC)`
2. Virtual IP assigned from `10.ghost.0.0/16`
3. No default gateway — all external traffic must go through Shell proxy

## 4.2 Mounts (Phase 3.2)
- `/` → Read-only OCI image layer (overlayfs)
- `/tmp`, `/var/log` → `tmpfs` (RAM only, volatile)
- `/vault` → Read-only bind mount of decrypted vault ref (if persistence requested)

## 4.3 Cgroups v2 (Phase 3.1)
- `cpu.max` — user-defined quota
- `memory.high` — throttling limit
- `memory.max` — hard OOM kill limit

---

# RFC-005: Global Discovery DHT (Lighthouse Layer)
**Status:** 🔧 Partial — local DHT working; bootstrap nodes and remote resolution pending

**Protocol:** Kademlia DHT over libp2p (mDNS for LAN peer discovery)

## 5.1 Coordinate Blob ✅

DHT values are encrypted to prevent metadata harvesting:

```
CoordinateBlob = AES-GCM-256(
    plaintext: IP + Port + Timestamp,
    key:       BLAKE3(GhostID),
    nonce:     random 96-bit
)
```

Only someone who knows the GhostID can decrypt the location.
The DHT key is `BLAKE3(ghost_id_bytes)`.

## 5.2 DHT Key Separation ✅

The DHT signing key is derived separately from the vault key:
```
dht_key = HKDF-SHA256(vault_key, info="tsc-dht-v1", salt=ghost_id_bytes)[..32]
```

## 5.3 Anti-Stale ✅
Records with timestamp older than 1 hour are rejected in `decode_coordinate`.

## 5.4 Bootstrap (Phase 4.1) 📋
- `[net] bootstrap = ["<multiaddr>", ...]` in `config.toml`
- Lighthouse nodes: community-run `tscd` instances with no local Ghosts

---

# RFC-006: Vault & Persistence (Storage Layer)
**Status:** ✅ Implemented

## 6.1 Blind Host Invariant ✅

The Shell stores the vault file but cannot read it without the Master Seed + Hardware UUID.

### Key Derivation Chain
1. `Master Seed` (BIP-39, 512 bits)
2. `K1 = SLIP-0010(seed, m/44'/7777'/0'/0'/0')` — Ed25519 signing key
3. `storage_key = Argon2id(K1.to_bytes(), hw_uuid_hash, random_salt)` — vault encryption key
4. Vault ciphertext = `ChaCha20-Poly1305(storage_key, random_nonce, mnemonic_words)`

### Binary Format
```
[4B magic] [1B version] [16B salt] [12B nonce] [ciphertext + 16B auth tag]
```

## 6.2 Hardware Binding ✅

Hardware UUID sourced from DMI (`/sys/class/dmi/id/product_uuid`) or
`/etc/machine-id` hash as fallback (logged as WARN).

## 6.3 Forensic Integrity (dm-verity) 🔮 (Future)

Merkle tree over Ghost storage state — planned for Phase 4 production hardening.

---

# RFC-007: Traffic Morphing (Metadata Defence)
**Status:** 🔧 Scaffolded — chaff generator exists; not wired to write path

## 7.1 Chaff Injection (Phase 2.3)

`morph.rs::send_chaff_stream()` generates `MsgType::Chaff` frames:
- Random size: 64–512 bytes
- Random interval: 50–150ms jitter
- Silently discarded by all receivers

## 7.2 Ghost-Bridge / SOCKS5 (Phase 3.3) 📋

`bridge.rs` stub maps Ghost TCP ports to GSP stream IDs:
- `Stream ID 80` → Ghost's internal Nginx
- `Stream ID 22` → Ghost's internal SSH (remote admin)

## 7.3 Local DNS Listener 🔮 (Future)

`tscd` local DNS on `127.0.0.53:53` — intercepts `.ghost` TLD queries,
resolves via DHT, presents SOCKS5 interface to browser.

---

# RFC-008: Sovereign Binary Updates & Protocol Evolution
**Status:** 🔮 Future

- Signed binary diffs distributed over GSP P2P layer
- Threshold signature governance: quorum of community keys required
- 3-strike rollback: auto-revert if new binary fails to boot 3 times

---

# RFC-009: Daemon Boot Sequence
**Status:** ✅ Implemented (`tscd/src/main.rs`)

```
1. Resolve hardware UUID (DMI or machine-id hash)
2. Locate vault ($XDG_DATA_HOME/tsc/vault.bin)
   a. Vault exists + TSC_MNEMONIC set → unlock vault, load IEL, verify chain
   b. Vault exists, no mnemonic      → ephemeral mode (warn)
   c. No vault                       → ephemeral mode
3. Build NetStack (QUIC endpoint + DHT lookup channel)
4. Set local_ixn on NetStack (None in ephemeral mode)
5. Spawn parallel tasks:
   a. GSP listener (listen())
   b. DHT discovery loop (run_discovery())
   c. IPC server (IpcServer::serve())
```

Ephemeral identity: random Ed25519 key, GhostID = `"ephemeral:<first 16 hex chars>"`.
No vault, no IEL — HELLO handshake sends no inception event.

---

# RFC-010: IPC Protocol ADRs

**ADR-007:** `tsc-proto` crate owns all shared IPC types. Neither `tsc-cli` nor `tscd`
define their own command/response types.

**ADR-008:** `SkipServerVerification` (accept self-signed QUIC certs) is gated behind
`#[cfg(feature = "dev")]`. Production builds require a real KERI-verified TLS chain.

**ADR-011:** Vault encryption uses ChaCha20-Poly1305, not AES-GCM. Rationale: constant-time
on all platforms without hardware AES acceleration; no timing side-channel risk.
Note: AES-GCM is available as a workspace dependency (`aes-gcm = "0.10"`) for use in
the DHT Coordinate Blob (RFC-005 §5.1) where AES-256-GCM is specified.
