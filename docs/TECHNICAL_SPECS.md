# TSC Technical Specifications

**Version:** 2.0  
**Status:** Authoritative  
**Last Updated:** 2026-02-28

This document is the definitive reference for cryptographic primitives, data formats, and engineering constraints. All implementation work must conform to these specifications.

---

## 1. Cryptographic Primitive Suite

| Purpose | Algorithm | Crate | Notes |
|---------|-----------|-------|-------|

| Digital signatures | Ed25519 | `ed25519-dalek 2.x` | All KERI events, GSP handshakes |
| Key exchange | X25519 | `x25519-dalek 2.x` | Future: session key negotiation |
| Symmetric AEAD | ChaCha20-Poly1305 | `chacha20poly1305 0.10` | Vault, DHT blobs, stream encryption |
| Hashing | BLAKE3 | `blake3 1.5` | Event digests, GhostID, pre-rotation commitment |
| KDF (password) | Argon2id | `argon2 0.5` | Vault key derivation from mnemonic + HW UUID |
| KDF (key material) | HKDF-SHA256 | `hkdf` | DHT coordinate key, Ghost-specific keys |
| Mnemonic entropy | BIP-39 | `bip39` | 24-word, 256-bit entropy |
| Key hierarchy | SLIP-0010 | TBD (see RFC-012) | Hardened Ed25519 derivation |
| Serialization (canonical) | Canonical JSON (RFC 8785) | `serde_json` + custom sort | KERI event hashing |
| Serialization (binary) | bincode | `bincode 1.3` | GSP frames, IPC messages, DHT blobs |

### 1.1 Algorithm Selection Rationale

**Why Ed25519 over secp256k1?** Ed25519 has faster verification, smaller signatures (64 bytes), and is not vulnerable to the ECDSA nonce-reuse attack. SLIP-0010 supports Ed25519 derivation.

**Why ChaCha20-Poly1305 over AES-GCM?** ChaCha20-Poly1305 has no timing side-channel vulnerabilities in pure software implementations. AES-GCM requires AES-NI hardware acceleration for safe constant-time operation. See ADR-011.

**Why BLAKE3 over SHA-256?** BLAKE3 is faster, parallelizable, and has a clean modern design. It is used for non-password hashing (event digests, commitments) where hardware SHA acceleration is less relevant.

**Why Argon2id for vault KDF?** Memory-hard KDF resistant to GPU/ASIC brute force. The `id` variant combines Argon2i (side-channel resistance) and Argon2d (GPU resistance). See ADR-005.

---

## 2. Key Derivation Reference

### 2.1 Master Seed Derivation

```bash
mnemonic_phrase (24 words)
    │
    ▼ BIP-39 PBKDF2-HMAC-SHA512, 2048 rounds, password="", salt="mnemonic" + passphrase
    │
    ▼
master_seed: [u8; 64]  (512 bits)
```

### 2.2 SLIP-0010 Key Derivation

```bash
master_seed
    │
    ▼ HMAC-SHA512("ed25519 seed", master_seed)
    │
    ├─► master_key_left:  [u8; 32]  (private scalar)
    └─► master_key_right: [u8; 32]  (chain code)

For each path level (hardened only, index >= 0x80000000):
    HMAC-SHA512(chain_code, 0x00 ‖ private_scalar ‖ index_big_endian)
    → child_key_left, child_key_right
```

### 2.3 Standard Derivation Paths

| Key Purpose | Full Path | Index |
|-------------|-----------|-------|

| Active signing key K1 | `m/44'/7777'/0'/0'/0'` | `0x80000000` |
| Pre-rotation key K2 | `m/44'/7777'/0'/0'/1'` | `0x80000001` |
| Ghost-specific key (slot 0) | `m/44'/7777'/1'/0'` | — |
| DHT coordinate key | Derived via HKDF from K1, not SLIP-0010 | — |

### 2.4 Storage Key (Vault KDF)

```rust
ghost_key_material = K1.private_scalar_bytes

K_storage = Argon2id(
    password = ghost_key_material ‖ hw_uuid_bytes,
    salt     = random_salt_16_bytes,   ← stored in vault header
    t        = 3,
    m        = 65536,   ← 64 MiB
    p        = 4,
    len      = 32
)
```

### 2.5 DHT Coordinate Encryption Key

```markdown
K_dht = HKDF-SHA256(
    ikm  = K1.private_scalar_bytes,
    salt = "tsc-dht-coord-v1",
    info = ghost_id_bytes,
    len  = 32
)
```

This key is distinct from `K_storage`. Key reuse between vault encryption and DHT coordinate encryption is explicitly forbidden.

---

## 3. Data Format Specifications

### 3.1 GhostID Format

```markdown
ghost_id = "blake3:" + base64url_no_padding(BLAKE3(canonical_json(IXN with d="")))
```

Human display: first 16 characters after the prefix. Example: `blake3:7f3a2c91...`

### 3.2 Vault File Binary Layout

```markdown
Offset  Size   Field
0       8      Magic: b"TSCVAULT"
8       1      Version: 0x01
9       16     Argon2id Salt (random, stored here)
25      12     ChaCha20-Poly1305 Nonce (random, per-encryption)
37      4      Payload Length (u32, big-endian)
41      N+16   Encrypted Payload + 16-byte Poly1305 auth tag
```

Total minimum size: 57 bytes + mnemonic length (typical ~250 bytes).

### 3.3 GSP Frame Binary Layout

```bash
Offset  Size   Field
0       4      frame_length (u32, big-endian): byte count of bytes 4..end
4       1      msg_type (u8): 0x01=Control, 0x02=Data, 0x03=Migration, 0xFF=Chaff
5       2      stream_id (u16, big-endian)
7       1      flags (u8)
8       N      payload (bincode-serialized message body)
```

### 3.4 DHT Coordinate Blob Binary Layout

```text
[bincode-serialized CoordinateBlob]
    ├── version: u8 = 0x01
    ├── nonce: [u8; 12]
    └── ciphertext: Vec<u8>
        └── [bincode-serialized RawCoordinate, ChaCha20-Poly1305 encrypted]
                ├── addr: SocketAddr
                ├── timestamp: u64
                └── relay_addr: Option<SocketAddr>
```

### 3.5 IPC Frame Layout

```bash
Offset  Size   Field
0       4      payload_length (u32, little-endian): length of bincode payload
4       N      bincode-serialized GhostCommand or GhostResponse
```

---

## 4. Engineering Constraints

### 4.1 Host Environment Requirements

| Requirement | Minimum | Notes |
|-------------|---------|-------|

| OS | Linux | No Windows or macOS support planned |
| Kernel | ≥ 5.15 | Required for stable io_uring, cgroups v2, memfd_secret |
| Rust toolchain | ≥ 1.75 | Async stability, latest features |
| OCI runtime | youki or crun | See ADR-010 |
| Cgroups | v2 only | Must be mounted at `/sys/fs/cgroup` |
| Available RAM | ≥ 256 MiB | Argon2id needs 64 MiB per vault unlock |
| Disk space | ≥ 1 GiB | For Ghost image storage |

### 4.2 Compile-Time Invariants

These MUST be enforced via `Cargo.toml` and crate-level attributes:

```rust
// Required in all lib.rs and main.rs files
#![forbid(unsafe_code)]
#![deny(missing_docs)]
```

```toml
# .cargo/config.toml
[build]
rustflags = ["-D", "warnings"]
```

### 4.3 Security Invariants

| Invariant | Enforcement |
|-----------|-------------|

| No raw IP in DHT | DHT values are always CoordinateBlob (encrypted) |
| No plaintext keys in logs | Signing key bytes MUST NOT appear in any log output |
| Static salt forbidden | `K_storage` Argon2id salt MUST be random and stored in vault header |
| No direct seed slice | `seed[0..32]` as Ed25519 key is forbidden; SLIP-0010 MUST be used |
| No `/tmp` for secrets | Vault and IPC socket MUST NOT use `/tmp` in production |
| `SkipServerVerification` gated | MUST be `#[cfg(feature = "dev")]` only |
| Chaff always on | No configuration option to disable traffic morphing |
| Pre-rotation commitment non-zero | `n` field in IXN MUST NOT be all-zero bytes |

### 4.4 Dependency Policy

- Cryptographic dependencies MUST come from the **RustCrypto** organization on crates.io.
- Dependencies with `unsafe` code MUST be explicitly reviewed and noted in their workspace dependency entry.
- Dependency updates that change major versions require an ADR review.
- `audit` via `cargo-audit` MUST be run in CI.

---

## 5. File & Path Reference

| Item | Path | Notes |
|------|------|-------|

| Vault file | `$XDG_DATA_HOME/tsc/vault.bin` | Default: `~/.local/share/tsc/vault.bin` |
| Identity store (IEL) | `$XDG_DATA_HOME/tsc/identity/` | Per-GhostID subdirectories |
| Ghost persistence volumes | `$XDG_DATA_HOME/tsc/vaults/<ghost_id>.img` | LUKS2 sparse files |
| Ghost root hashes | `$XDG_DATA_HOME/tsc/vaults/<ghost_id>.roothash` | Signed dm-verity hashes |
| Config file | `$XDG_CONFIG_HOME/tsc/config.toml` | Default: `~/.config/tsc/config.toml` |
| IPC socket (user session) | `$XDG_RUNTIME_DIR/tsc/tscd.sock` | Default: `/run/user/<uid>/tsc/tscd.sock` |
| IPC socket (system) | `/run/tsc/tscd.sock` | When running as a system service |
| Logs | `$XDG_STATE_HOME/tsc/` | Default: `~/.local/state/tsc/` |
| Update keys | `$XDG_CONFIG_HOME/tsc/update-keys.json` | Threshold signature public keys |
| Lighthouse config | `$XDG_CONFIG_HOME/tsc/lighthouse.toml` | Only for Lighthouse nodes |

---

## 6. Configuration File Reference

`$XDG_CONFIG_HOME/tsc/config.toml` (default values shown):

```toml
[daemon]
listen_addr = "0.0.0.0:9090"   # QUIC/GSP UDP endpoint
log_level = "info"              # trace, debug, info, warn, error

[identity]
vault_path = ""                 # Empty = XDG default
non_interactive = false         # true = read mnemonic from env/fd

[runtime]
oci_runtime = "/usr/bin/youki"  # or /usr/bin/crun
ghost_image_dir = ""            # Empty = XDG default

[network]
bootstrap_peers = []            # List of Lighthouse multiaddrs
dht_refresh_interval_secs = 900
enable_mdns = true

[ghost.defaults]
cpu_max_percent = 50
memory_limit_mb = 512
allow_legacy_egress = false

[security]
chaff_enabled = true            # Read-only; always true. Present for documentation.
memfd_secret = true             # Attempt to use memfd_secret for key storage
```

---

## 7. Workspace Dependency Reference

Complete list of required workspace-level dependencies:

```toml
[workspace.dependencies]
# Cryptography (RustCrypto)
blake3              = "1.5"
ed25519-dalek       = { version = "2.1", features = ["rand_core", "zeroize"] }
x25519-dalek        = { version = "2.0", features = ["zeroize"] }
chacha20poly1305    = "0.10"
argon2              = "0.5"
hkdf                = "0.12"
sha2                = "0.10"
zeroize             = { version = "1.7", features = ["derive"] }
rand                = "0.8"
hex                 = "0.4"

# BIP-39 / SLIP-0010
bip39               = "2.0"
# slip10 crate TBD — to be selected per RFC-012

# Serialization
serde               = { version = "1.0", features = ["derive"] }
serde_json          = "1.0"
bincode             = "1.3"

# Async & Networking
tokio               = { version = "1.35", features = ["full"] }
quinn               = "0.10"
rustls              = "0.21"
rcgen               = "0.12"

# P2P
libp2p              = { version = "0.53", features = ["kad", "mdns", "tcp", "noise", "yamux", "tokio"] }

# System
nix                 = { version = "0.27", features = ["socket", "process"] }
dirs                = "5.0"

# Utilities
thiserror           = "1.0"
tracing             = "0.1"
tracing-subscriber  = "0.3"
```
