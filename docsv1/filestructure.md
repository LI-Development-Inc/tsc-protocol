# 📂 TSC Project File Structure

```text
standalone-complex/
├── Cargo.toml                # Workspace configuration
├── README.md                 # Project overview & setup
├── .gitignore                # Rust/OCI build artifacts
├── crates/
│   ├── tsc-crypto/           # THE IDENTITY DOMAIN (Root of Trust)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── bip39.rs      # Entropy & Seed generation
│   │       ├── keri.rs       # Succession logs & Key rotation
│   │       └── vault.rs      # Argon2id & Key-wrap logic
│   ├── tsc-net/              # THE TRANSPORT DOMAIN (The Pipe)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── gsp.rs        # GSP over QUIC framing
│   │       ├── dht.rs        # Kademlia & Encrypted Discovery
│   │       └── morph.rs      # Chaffing/Traffic morphing logic
│   ├── tsc-runtime/          # THE EXECUTION DOMAIN (The Ghost)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── jail.rs       # Namespace/Cgroup orchestration
│   │       ├── oci.rs        # Integration with youki/crun
│   │       └── bridge.rs     # SOCKS5/Legacy protocol proxy
│   └── tscd/                 # THE SHELL (Local Daemon)
│   |   ├── Cargo.toml
│   |   └── src/
│   |       ├── main.rs       # Entry point & Orchestrator
│   |       └── ipc.rs        # Unix Domain Socket (SO_PEERCRED)
|   ├── tsc-cli/          # THE EXECUTION DOMAIN (The Ghost)
|   │   │   ├── Cargo.toml
|   │   │   └── src/
|   │   │       ├── main.rs
|   │   │       ├── main.rs       # Namespace/Cgroup orchestration
|   │   │       ├── oci.rs        # Integration with youki/crun
|   │   │       └── bridge.rs     # SOCKS5/Legacy protocol proxy
|
|
├── scripts/
│   └── setup-bridge.sh       # Linux virtual tap configuration
└── docker/                   # OCI Ghost templates
    └── base-ghost.Dockerfile

```

---

### 🛠️ Required Build & Configuration Files

Beyond the source code, the following files are mandatory to satisfy our **Engineering Guardrails**:

| File | Purpose | Requirement Satisfied |
| --- | --- | --- |
| **`rust-toolchain.toml`** | Pins Rust version to $\ge 1.75$. | Ensures `io_uring` and `async` stability. |
| **`.cargo/config.toml`** | Sets `-D warnings` and `forbid(unsafe_code)`. | Enforces strict safety invariants. |
| **`policy.json`** | Defines OCI runtime security profiles. | Configures `NEWNET` and `NEWUSER` isolation. |
| **`lsh-config.toml`** | Default configuration for "Lighthouse" nodes. | Enables signaling and NAT traversal. |
| **`update-keys.json`** | Threshold signature public keys. | Facilitates Sovereign Binary Updates. |
