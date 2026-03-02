

## 🗺️ The TSC Implementation Roadmap: From Paper to Steel

With the RFCs locked, we move into the execution phases. We will build this using a **"Bottom-Up"** approach.

### Phase 1: The Cryptographic Foundations (`tsc-crypto`)

**Goal:** Implement the "Identity Domain."

* **Task 1.1:** BIP-39 mnemonic generation and SLIP-0010 hardened derivation.
* **Task 1.2:** The KERI Succession Log implementation (RFC-002).
* **Task 1.3:** Argon2id Vault key derivation logic (RFC-006).
* **Deliverable:** A CLI tool that can create a "Sovereign Identity" and sign its first Inception Event.

### Phase 2: The GSP Transport Layer (`tsc-net`)

**Goal:** Establish the "Transport Domain."

* **Task 2.1:** QUIC integration using the `quinn` crate.
* **Task 2.2:** Implementation of RFC-001 (GSP Wire Format) and framing.
* **Task 2.3:** Basic DHT (Kademlia) node discovery (RFC-005).
* **Deliverable:** Two `tscd` instances on different machines "pinging" each other via GhostID.

### Phase 3: The Ghostbox Orchestrator (`tsc-runtime`)

**Goal:** Build the "Execution Domain."

* **Task 3.1:** Programming the Linux Namespace/Cgroup wrappers (RFC-004).
* **Task 3.2:** Integration of `youki` (Rust OCI runtime) or `crun`.
* **Task 3.3:** The internal bridge/proxy logic for Ghost-to-Host communication.
* **Deliverable:** Spawning a "Ghost" running a simple Nginx server accessible only via the Shell.

### Phase 4: The Sovereign Interface (`tsc-cli` & `the-window`)

**Goal:** The User Experience.

* **Task 4.1:** The Unix Domain Socket (UDS) IPC interface (RFC-003).
* **Task 4.2:** Developing the `tsc-cli` dashboard.
* **Task 4.3:** Compiling the Micro-Shell to WASM for browser integration.
* **Deliverable:** A user can type `tsc start my-blog` and see their site in the Sovereign Browser.
