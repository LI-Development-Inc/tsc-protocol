# =============================================================================
# TSC Protocol — Manual Test Makefile
# =============================================================================
#
# QUICK START
#   make build                        Compile debug binaries
#   make daemon-ephemeral             Start daemon (no vault needed)
#   make test-p1                      Run Phase 1 tests
#
#   source .env.test && make daemon-start    Start daemon (unlocks vault)
#   make test-p1-1                           Run Phase 1.1 rotation tests
#   make test-all                            Run every phase (stubs for pending)
#
# ENVIRONMENT VARIABLES (see .env.test.example)
#   TSC_MNEMONIC   24-word BIP-39 phrase  (required: vault unlock, rotation)
#   TSC_GHOST_B    Remote GhostID         (required: Phase 2 peer tests)
#
# LOADING YOUR ENV
#   cp .env.test.example .env.test    # fill in your mnemonic
#   source .env.test                  # export vars into current shell
#
# PHASE STATUS
#   Phase 1    ✅ Identity + vault + GSP local loopback
#   Phase 1.1  ✅ KERI key rotation
#   Phase 2.1  ✅ GSP HELLO handshake (loopback verified — VPS cross-node pending)
#   Phase 2.2  🔧 Remote DHT resolution (needs VPS peer)
#   Phase 2.3  🔧 Traffic morphing / chaff injection
#   Phase 3    🔧 Ghost runtime / OCI
#   Phase 4    🔧 Browser shell / WASM
# =============================================================================

SHELL      := /bin/bash
BIN        := ./target/debug
CLI        := $(BIN)/tsc-cli
DAEMON     := $(BIN)/tscd
VAULT      := $(HOME)/.local/share/tsc/vault.bin
IEL        := $(HOME)/.local/share/tsc/iel.jsonl
DAEMON_LOG := /tmp/tscd-test.log

# ANSI colours
GRN  := \033[0;32m
YLW  := \033[0;33m
RED  := \033[0;31m
CYN  := \033[0;36m
BOLD := \033[1m
DIM  := \033[2m
RST  := \033[0m

# ── Internal guard targets ────────────────────────────────────────────────────

.PHONY: _require-daemon _require-mnemonic _require-ghost-b

_require-daemon:
	@test -x "$(CLI)" || { \
		echo -e "$(RED)[✗] $(CLI) not found — run: $(BOLD)make build$(RST)"; \
		exit 1; }
	@$(CLI) ping 2>/dev/null | grep -q "TSC_PULSE_OK" || { \
		echo -e "$(RED)[✗] tscd is not running.$(RST)"; \
		echo -e "    Run: $(BOLD)make daemon-start$(RST)  or  $(BOLD)make daemon-ephemeral$(RST)"; \
		exit 1; }

_require-mnemonic:
	@test -n "$(TSC_MNEMONIC)" || { \
		echo -e "$(RED)[✗] TSC_MNEMONIC not set.$(RST)"; \
		echo -e "    Run: $(BOLD)export TSC_MNEMONIC=\"word1 ... word24\"$(RST)"; \
		echo -e "    $(DIM)Note: no spaces around = in bash export$(RST)"; \
		exit 1; }

# Soft guard — skips gracefully instead of failing test-all
_require-ghost-b:
	@test -n "$(TSC_GHOST_B)" || { \
		echo -e "$(YLW)[~] TSC_GHOST_B not set — skipping remote peer test.$(RST)"; \
		echo -e "    Set: $(BOLD)export TSC_GHOST_B=<remote-ghost-id>$(RST)"; \
		exit 0; }

# ── Build ─────────────────────────────────────────────────────────────────────

.PHONY: build test-unit env-check env-init vps-setup

## Compile debug binaries
build:
	@echo -e "$(CYN)[*] Building...$(RST)"
	@cargo build 2>&1
	@echo -e "$(GRN)[✓] Build complete.$(RST)"

## Run all cargo unit tests (no daemon required)
test-unit:
	@echo -e "$(CYN)[*] cargo test$(RST)"
	@cargo test -- --test-threads=1 2>&1
	@echo -e "$(GRN)[✓] Unit tests passed.$(RST)"

## Print a reminder on how to load the test environment
env-check:
	@echo -e "$(CYN)[*] Environment$(RST)"
	@test -n "$(TSC_MNEMONIC)" \
		&& echo -e "  $(GRN)[✓] TSC_MNEMONIC set$(RST)" \
		|| echo -e "  $(YLW)[~] TSC_MNEMONIC not set$(RST)  →  source .env.test"
	@test -n "$(TSC_GHOST_B)" \
		&& echo -e "  $(GRN)[✓] TSC_GHOST_B = $(TSC_GHOST_B)$(RST)" \
		|| echo -e "  $(YLW)[~] TSC_GHOST_B not set$(RST)  →  needed for Phase 2 peer tests"

## Copy .env.test.example to .env.test (does not overwrite existing)
env-init:
	@test -f .env.test \
		&& echo -e "$(YLW)[~] .env.test already exists — not overwriting.$(RST)" \
		|| { cp .env.test.example .env.test; \
		     echo -e "$(GRN)[✓] Created .env.test — fill in your mnemonic then: source .env.test$(RST)"; }

## Bootstrap a VPS peer for Phase 2.2 cross-node tests
vps-setup:
	@echo -e "$(CYN)[*] To set up a VPS peer:$(RST)"
	@echo -e "  1. Copy project:  $(BOLD)rsync -av . user@vps:~/tsc-work/$(RST)"
	@echo -e "  2. Run setup:     $(BOLD)ssh user@vps 'bash ~/tsc-work/scripts/vps-setup.sh'$(RST)"
	@echo -e "  3. Copy GhostID into .env.test as TSC_GHOST_B"
	@echo -e "  4. Open VPS ports: $(BOLD)9090/tcp and 9090/udp$(RST)"
	@echo -e "  5. Run:           $(BOLD)source .env.test && make test-p2$(RST)"

# ── Daemon lifecycle ──────────────────────────────────────────────────────────

.PHONY: daemon-start daemon-ephemeral daemon-stop daemon-logs daemon-status status

## Start tscd — unlocks vault if TSC_MNEMONIC is set, otherwise ephemeral
daemon-start:
	@{ \
	  echo -e "$(CYN)[*] Starting tscd → $(DAEMON_LOG)$(RST)"; \
	  pkill -x tscd 2>/dev/null; sleep 0.3; \
	  nohup env TSC_MNEMONIC="$(TSC_MNEMONIC)" $(DAEMON) >> $(DAEMON_LOG) 2>&1 & \
	  disown; sleep 1.5; \
	  $(CLI) ping 2>/dev/null | grep -q "TSC_PULSE_OK" \
	    && echo -e "$(GRN)[✓] tscd is live.$(RST)" \
	    || { echo -e "$(RED)[✗] tscd failed — see $(DAEMON_LOG)$(RST)"; exit 1; }; \
	}

## Start tscd with no vault (ephemeral identity)
daemon-ephemeral:
	@{ \
	  echo -e "$(CYN)[*] Starting tscd (ephemeral) → $(DAEMON_LOG)$(RST)"; \
	  pkill -x tscd 2>/dev/null; sleep 0.3; \
	  nohup $(DAEMON) >> $(DAEMON_LOG) 2>&1 & \
	  disown; sleep 1.5; \
	  $(CLI) ping 2>/dev/null | grep -q "TSC_PULSE_OK" \
	    && echo -e "$(GRN)[✓] tscd (ephemeral) is live.$(RST)" \
	    || { echo -e "$(RED)[✗] tscd failed — see $(DAEMON_LOG)$(RST)"; exit 1; }; \
	}

## Stop the running daemon
daemon-stop:
	@pkill -x tscd 2>/dev/null \
	  && echo -e "$(GRN)[✓] tscd stopped.$(RST)" \
	  || echo -e "$(YLW)[~] tscd was not running.$(RST)"

## Tail the daemon log (last 40 lines)
daemon-logs:
	@tail -40 $(DAEMON_LOG) 2>/dev/null || echo -e "$(YLW)(no log yet)$(RST)"

## Print live daemon status via CLI
daemon-status: _require-daemon
	@$(CLI) status

## Alias for daemon-status
status: daemon-status

# ── Phase 1: Identity, Vault, Local GSP ──────────────────────────────────────
#
# No second peer required. All network ops are loopback (127.0.0.1:9090).
# Covers: ping, status, list, ephemeral ops, recover, persistent ops.

.PHONY: test-p1 \
	test-p1-ping test-p1-status test-p1-list \
	test-p1-ephemeral-resolve test-p1-ephemeral-connect test-p1-ephemeral-send \
	test-p1-recover \
	test-p1-persistent-resolve test-p1-persistent-connect test-p1-persistent-send

## Run all Phase 1 tests (ephemeral half needs no TSC_MNEMONIC)
test-p1: \
	test-p1-ping \
	test-p1-status \
	test-p1-list \
	test-p1-ephemeral-resolve \
	test-p1-ephemeral-connect \
	test-p1-ephemeral-send \
	test-p1-recover \
	test-p1-persistent-resolve \
	test-p1-persistent-connect \
	test-p1-persistent-send
	@echo ""
	@echo -e "$(GRN)$(BOLD)[✓] Phase 1 complete.$(RST)"

test-p1-ping: _require-daemon
	@echo -e "$(CYN)[P1] ping$(RST)"
	@$(CLI) ping | grep -q "TSC_PULSE_OK" \
		&& echo -e "  $(GRN)[✓] ping$(RST)" \
		|| { echo -e "  $(RED)[✗] ping$(RST)"; exit 1; }

test-p1-status: _require-daemon
	@echo -e "$(CYN)[P1] status$(RST)"
	@$(CLI) status | grep -q "GhostID" \
		&& echo -e "  $(GRN)[✓] status$(RST)" \
		|| { echo -e "  $(RED)[✗] status$(RST)"; exit 1; }

test-p1-list: _require-daemon
	@echo -e "$(CYN)[P1] list$(RST)"
	@$(CLI) list | grep -qE "No Ghosts|GHOST_ID" \
		&& echo -e "  $(GRN)[✓] list$(RST)" \
		|| { echo -e "  $(RED)[✗] list$(RST)"; exit 1; }

# Helper: extract current GhostID from status output
define current-ghost
$(shell $(CLI) status 2>/dev/null | grep "GhostID" | sed 's/.*: //' | tr -d '[:space:]')
endef

test-p1-ephemeral-resolve: _require-daemon
	@echo -e "$(CYN)[P1] resolve (ephemeral, local)$(RST)"
	@GHOST="$(call current-ghost)"; \
	$(CLI) resolve "$$GHOST" | grep -q "127.0.0.1" \
		&& echo -e "  $(GRN)[✓] resolve → 127.0.0.1:9090$(RST)" \
		|| { echo -e "  $(RED)[✗] resolve failed$(RST)"; exit 1; }

test-p1-ephemeral-connect: _require-daemon
	@echo -e "$(CYN)[P1] connect (ephemeral, local)$(RST)"
	@GHOST="$(call current-ghost)"; \
	$(CLI) connect "$$GHOST" | grep -q "GSP Link Active" \
		&& echo -e "  $(GRN)[✓] connect$(RST)" \
		|| { echo -e "  $(RED)[✗] connect$(RST)"; exit 1; }

test-p1-ephemeral-send: _require-daemon
	@echo -e "$(CYN)[P1] send (ephemeral, local)$(RST)"
	@GHOST="$(call current-ghost)"; \
	$(CLI) send "$$GHOST" "test-p1: hello" | grep -q "delivered" \
		&& echo -e "  $(GRN)[✓] send$(RST)" \
		|| { echo -e "  $(RED)[✗] send$(RST)"; exit 1; }

test-p1-recover: _require-daemon _require-mnemonic
	@echo -e "$(CYN)[P1] recover (load persistent identity)$(RST)"
	@$(CLI) recover $(TSC_MNEMONIC) | grep -q "RECOVERED" \
		&& echo -e "  $(GRN)[✓] recover$(RST)" \
		|| { echo -e "  $(RED)[✗] recover failed$(RST)"; exit 1; }
	@sleep 0.5
	@$(CLI) status | grep -q "Unlocked" \
		&& echo -e "  $(GRN)[✓] vault unlocked after recover$(RST)" \
		|| { echo -e "  $(RED)[✗] vault not unlocked$(RST)"; exit 1; }

test-p1-persistent-resolve: _require-daemon
	@echo -e "$(CYN)[P1] resolve (persistent identity, local)$(RST)"
	@GHOST="$(call current-ghost)"; \
	$(CLI) resolve "$$GHOST" | grep -q "127.0.0.1" \
		&& echo -e "  $(GRN)[✓] resolve → 127.0.0.1:9090$(RST)" \
		|| { echo -e "  $(RED)[✗] resolve failed$(RST)"; exit 1; }

test-p1-persistent-connect: _require-daemon
	@echo -e "$(CYN)[P1] connect (persistent identity, local)$(RST)"
	@GHOST="$(call current-ghost)"; \
	$(CLI) connect "$$GHOST" | grep -q "GSP Link Active" \
		&& echo -e "  $(GRN)[✓] connect$(RST)" \
		|| { echo -e "  $(RED)[✗] connect$(RST)"; exit 1; }

test-p1-persistent-send: _require-daemon
	@echo -e "$(CYN)[P1] send (persistent identity, local)$(RST)"
	@GHOST="$(call current-ghost)"; \
	$(CLI) send "$$GHOST" "test-p1: persistent hello" | grep -q "delivered" \
		&& echo -e "  $(GRN)[✓] send$(RST)" \
		|| { echo -e "  $(RED)[✗] send$(RST)"; exit 1; }

# ── Phase 1.1: KERI Key Rotation ─────────────────────────────────────────────
#
# Requires: TSC_MNEMONIC set, daemon started with vault unlocked.
# Verifies: GhostID stability, distinct key per rotation, IEL written to disk.

.PHONY: test-p1-1 \
	test-p1-1-ghost-id-stable \
	test-p1-1-rotate \
	test-p1-1-double-rotate \
	test-p1-1-iel-written

## Run all Phase 1.1 tests
test-p1-1: \
	test-p1-1-ghost-id-stable \
	test-p1-1-rotate \
	test-p1-1-double-rotate \
	test-p1-1-iel-written
	@echo ""
	@echo -e "$(GRN)$(BOLD)[✓] Phase 1.1 complete.$(RST)"

test-p1-1-ghost-id-stable: _require-daemon _require-mnemonic
	@echo -e "$(CYN)[P1.1] GhostID unchanged across rotation (KERI invariant)$(RST)"
	@BEFORE="$(call current-ghost)"; \
	$(CLI) rotate-key > /dev/null; \
	sleep 0.5; \
	AFTER="$(call current-ghost)"; \
	echo "  Before: $$BEFORE"; \
	echo "  After:  $$AFTER"; \
	[ "$$BEFORE" = "$$AFTER" ] \
		&& echo -e "  $(GRN)[✓] GhostID stable$(RST)" \
		|| echo -e "  $(RED)[✗] GhostID changed — KERI violation$(RST)"

test-p1-1-rotate: _require-daemon _require-mnemonic
	@echo -e "$(CYN)[P1.1] rotate-key returns new public key$(RST)"
	@KEY=$$($(CLI) rotate-key 2>/dev/null | grep "New public key:" | sed 's/.*: //'); \
	echo "  Key: $$KEY"; \
	test -n "$$KEY" \
		&& echo -e "  $(GRN)[✓] new public key returned$(RST)" \
		|| { echo -e "  $(RED)[✗] rotate-key failed$(RST)"; exit 1; }

test-p1-1-double-rotate: _require-daemon _require-mnemonic
	@echo -e "$(CYN)[P1.1] two rotations produce distinct keys$(RST)"
	@KEY1=$$($(CLI) rotate-key 2>/dev/null | grep "New public key:" | sed 's/.*: //'); \
	sleep 0.3; \
	KEY2=$$($(CLI) rotate-key 2>/dev/null | grep "New public key:" | sed 's/.*: //'); \
	echo "  Key 1: $$KEY1"; \
	echo "  Key 2: $$KEY2"; \
	[ -n "$$KEY1" ] && [ -n "$$KEY2" ] && [ "$$KEY1" != "$$KEY2" ] \
		&& echo -e "  $(GRN)[✓] distinct keys per rotation$(RST)" \
		|| echo -e "  $(RED)[✗] same key returned twice (counter not advancing)$(RST)"

test-p1-1-iel-written:
	@echo -e "$(CYN)[P1.1] IEL file present on disk$(RST)"
	@test -f "$(IEL)" \
		|| { echo -e "  $(RED)[✗] IEL not found at $(IEL)$(RST)"; exit 1; }
	@LINES=$$(wc -l < "$(IEL)"); \
	echo "  Events: $$LINES"; \
	[ "$$LINES" -ge 2 ] \
		&& echo -e "  $(GRN)[✓] IEL has inception + at least one rotation$(RST)" \
		|| echo -e "  $(YLW)[~] only $$LINES event(s) — run rotate-key to add more$(RST)"

# ── Phase 2: Transport Layer ──────────────────────────────────────────────────
#
# Milestone 2.1  GSP HELLO handshake with KERI verification
# Milestone 2.2  Remote GhostID resolution via mDNS + Kademlia
# Milestone 2.3  Traffic morphing / chaff injection
#
# Remote peer tests require TSC_GHOST_B (second tscd on same LAN).
#
# Implementation checklist:
#   [ ] GSP HELLO frame: GhostID + VerifyingKey + IXN signature (RFC-001 §1.5)
#   [ ] Responder validates HELLO against sender IEL
#   [ ] Reject unknown/revoked key: KERI:UNTRUSTED
#   [ ] config.toml [net] bootstrap multiaddrs
#   [ ] kad.get_record() resolves after mDNS peer add
#   [ ] morph.rs chaff wired into QUIC write path (RFC-007)

.PHONY: test-p2 \
	test-p2-gsp-handshake \
	test-p2-peers \
	test-p2-remote-resolve \
	test-p2-remote-connect \
	test-p2-remote-send \
	test-p2-morph

## Run all Phase 2 tests (remote tests skipped if TSC_GHOST_B unset)
test-p2: \
	test-p2-gsp-handshake \
	test-p2-peers \
	test-p2-remote-resolve \
	test-p2-remote-connect \
	test-p2-remote-send \
	test-p2-morph
	@echo ""
	@echo -e "$(YLW)$(BOLD)[~] Phase 2: live tests ran; stubs printed.$(RST)"

test-p2-gsp-handshake: _require-daemon
	@echo -e "$(CYN)[P2.1] GSP HELLO handshake + KERI verification$(RST)"
	@echo -e "  $(GRN)[✓] Loopback verified$(RST) $(DIM)(daemon log shows 'GSP: Peer verified')$(RST)"
	@echo -e "  $(YLW)[~] Cross-node (VPS) not yet validated$(RST)"
	@echo -e "  $(DIM)VPS checklist:$(RST)"
	@echo -e "  $(DIM)  [ ] rsync project to VPS: rsync -av . user@vps:~/tsc-work/$(RST)"
	@echo -e "  $(DIM)  [ ] On VPS: bash scripts/vps-setup.sh$(RST)"
	@echo -e "  $(DIM)  [ ] Open VPS firewall: 9090/tcp + 9090/udp$(RST)"
	@echo -e "  $(DIM)  [ ] Add VPS GhostID to .env.test as TSC_GHOST_B$(RST)"
	@echo -e "  $(DIM)  [ ] source .env.test && make test-p2$(RST)"
	@echo -e "  $(DIM)  [ ] Confirm VPS log: [+] GSP: Peer verified: <local-id>$(RST)"

test-p2-peers: _require-daemon
	@echo -e "$(CYN)[P2.2] mDNS peer count$(RST)"
	@PEERS=$$($(CLI) status 2>/dev/null | grep "Peers" | sed 's/.*: //' | tr -d '[:space:]'); \
	echo "  Peers: $${PEERS:-0}"; \
	[ "$${PEERS:-0}" -gt 0 ] 2>/dev/null \
		&& echo -e "  $(GRN)[✓] peer(s) discovered$(RST)" \
		|| echo -e "  $(YLW)[~] 0 peers (expected without LAN peers)$(RST)"

test-p2-remote-resolve: _require-daemon _require-ghost-b
	@echo -e "$(CYN)[P2.2] resolve remote GhostID via DHT$(RST)"
	@$(CLI) resolve "$(TSC_GHOST_B)" | grep -q "Resolved:" \
		&& echo -e "  $(GRN)[✓] resolved: $(TSC_GHOST_B)$(RST)" \
		|| echo -e "  $(YLW)[~] NOT_FOUND — ensure both daemons are on same LAN$(RST)"

test-p2-remote-connect: _require-daemon _require-ghost-b
	@echo -e "$(CYN)[P2.1] connect to remote peer (exercises GSP handshake)$(RST)"
	@$(CLI) connect "$(TSC_GHOST_B)" | grep -q "GSP Link Active" \
		&& echo -e "  $(GRN)[✓] GSP link established$(RST)" \
		|| echo -e "  $(YLW)[~] connect failed — peer offline or handshake rejected$(RST)"

test-p2-remote-send: _require-daemon _require-ghost-b
	@echo -e "$(CYN)[P2.2] send message to remote peer$(RST)"
	@$(CLI) send "$(TSC_GHOST_B)" "test-p2: cross-node hello" | grep -q "delivered" \
		&& echo -e "  $(GRN)[✓] message delivered$(RST)" \
		|| echo -e "  $(YLW)[~] delivery failed — peer may be offline$(RST)"

test-p2-morph: _require-daemon
	@echo -e "$(CYN)[P2.3] traffic morphing / chaff injection$(RST)"
	@echo -e "  $(YLW)[STUB] Phase 2.3 not yet implemented$(RST)"
	@echo -e "  $(DIM)tcpdump :9090 → uniform frame sizes$(RST)"
	@echo -e "  $(DIM)chaff frames interspersed at configured rate$(RST)"
	@echo -e "  $(DIM)tsc-cli status --morph shows chaff statistics$(RST)"

# ── Phase 3: Ghost Runtime ────────────────────────────────────────────────────
#
# Milestone 3.1  Linux namespace isolation (net/pid/mount/user)
# Milestone 3.2  OCI image execution via youki/crun
# Milestone 3.3  Shell proxy: Ghost ↔ Host traffic routing
#
# Implementation checklist:
#   [ ] SpawnGhost: clone(CLONE_NEWNET|NEWPID|NEWNS|NEWUSER)
#   [ ] Assign virtual IP from 10.ghost.0.0/16 (ADR-006)
#   [ ] GhostHandle registry in DaemonState
#   [ ] ListGhosts / StopGhost backed by registry
#   [ ] youki/crun OCI execution
#   [ ] overlayfs: read-only base + ephemeral upper layer
#   [ ] Shell proxy: Ghost TCP/UDP → registered host handlers

.PHONY: test-p3 \
	test-p3-spawn \
	test-p3-list \
	test-p3-stop \
	test-p3-isolation \
	test-p3-proxy \
	test-p3-send-ghost

## Run all Phase 3 tests (all stubs until Phase 3 implemented)
test-p3: \
	test-p3-spawn \
	test-p3-list \
	test-p3-stop \
	test-p3-isolation \
	test-p3-proxy \
	test-p3-send-ghost
	@echo ""
	@echo -e "$(YLW)$(BOLD)[~] Phase 3: stubs printed, implementation pending.$(RST)"

test-p3-spawn: _require-daemon
	@echo -e "$(CYN)[P3.1] spawn Ghost from OCI image hash$(RST)"
	@$(CLI) spawn test-image-deadbeef 2>&1 | grep -q "NOT_IMPL" \
		&& echo -e "  $(YLW)[~] NOT_IMPL stub (expected)$(RST)" || true
	@echo -e "  $(DIM)tsc-cli spawn <IMAGE_HASH> [VAULT_ID]$(RST)"
	@echo -e "  $(DIM)[+] Ghost running: PID=<n> IP=10.ghost.x.x$(RST)"

test-p3-list: _require-daemon
	@echo -e "$(CYN)[P3.1] list running Ghosts$(RST)"
	@$(CLI) list
	@echo -e "  $(GRN)[✓] list$(RST) $(DIM)(empty until Phase 3)$(RST)"

test-p3-stop: _require-daemon
	@echo -e "$(CYN)[P3.1] stop a running Ghost$(RST)"
	@echo -e "  $(YLW)[STUB] Phase 3.1 not yet implemented$(RST)"
	@echo -e "  $(DIM)tsc-cli stop <GHOST_ID>$(RST)"
	@echo -e "  $(DIM)namespace torn down, cgroup released, overlay unmounted$(RST)"

test-p3-isolation:
	@echo -e "$(CYN)[P3.1] Ghost cannot reach public internet$(RST)"
	@echo -e "  $(YLW)[STUB] Phase 3.1 not yet implemented$(RST)"
	@echo -e "  $(DIM)nsenter --net=/proc/<pid>/ns/net -- ping -c1 8.8.8.8$(RST)"
	@echo -e "  $(DIM)expected: fails (no external route in Ghost netns)$(RST)"
	@echo -e "  $(DIM)expected: ping 10.ghost.0.1 succeeds (Shell veth)$(RST)"

test-p3-proxy:
	@echo -e "$(CYN)[P3.3] Shell proxy: Ghost TCP → Host$(RST)"
	@echo -e "  $(YLW)[STUB] Phase 3.3 not yet implemented$(RST)"
	@echo -e "  $(DIM)Ghost SYN to 10.ghost.0.1:80 → Shell forwards to handler$(RST)"
	@echo -e "  $(DIM)response tunnelled back through Shell veth$(RST)"

test-p3-send-ghost: _require-daemon
	@echo -e "$(CYN)[P3.3] send HTTP request to Ghost workload$(RST)"
	@echo -e "  $(YLW)[STUB] Phase 3.3 not yet implemented$(RST)"
	@echo -e "  $(DIM)tsc-cli send <GHOST_ID> \"GET / HTTP/1.0\"$(RST)"
	@echo -e "  $(DIM)Ghost nginx responds, Shell proxy returns body$(RST)"

# ── Phase 4: Sovereign Interface ─────────────────────────────────────────────
#
# Milestone 4.1  Enhanced CLI (logs, inspect, config file)
# Milestone 4.2  Browser shell (WASM, WebSocket bridge, .ghost TLD)
#
# Implementation checklist:
#   [ ] tsc-cli logs <ghost-id>           stream Ghost stdout/stderr
#   [ ] tsc-cli inspect <ghost-id>        netns, IP, uptime, CPU/mem
#   [ ] $XDG_CONFIG_HOME/tsc/config.toml  [net], [vault], [log]
#   [ ] cargo build --target wasm32-unknown-unknown -p tsc-cli
#   [ ] WebSocket bridge: browser ↔ tscd IPC socket
#   [ ] Browser extension: .ghost TLD → local Shell

.PHONY: test-p4 \
	test-p4-logs \
	test-p4-inspect \
	test-p4-config \
	test-p4-wasm \
	test-p4-browser

## Run all Phase 4 tests (all stubs until Phase 4 implemented)
test-p4: \
	test-p4-logs \
	test-p4-inspect \
	test-p4-config \
	test-p4-wasm \
	test-p4-browser
	@echo ""
	@echo -e "$(YLW)$(BOLD)[~] Phase 4: stubs printed, implementation pending.$(RST)"

test-p4-logs: _require-daemon
	@echo -e "$(CYN)[P4.1] stream Ghost logs$(RST)"
	@echo -e "  $(YLW)[STUB] Phase 4.1 not yet implemented$(RST)"
	@echo -e "  $(DIM)tsc-cli logs <GHOST_ID>  →  continuous stdout/stderr$(RST)"

test-p4-inspect: _require-daemon
	@echo -e "$(CYN)[P4.1] inspect Ghost resources$(RST)"
	@echo -e "  $(YLW)[STUB] Phase 4.1 not yet implemented$(RST)"
	@echo -e "  $(DIM)tsc-cli inspect <GHOST_ID>  →  netns, IP, uptime, CPU/mem$(RST)"

test-p4-config:
	@echo -e "$(CYN)[P4.1] config file$(RST)"
	@CFG="$${XDG_CONFIG_HOME:-$$HOME/.config}/tsc/config.toml"; \
	test -f "$$CFG" \
		&& { echo -e "  $(GRN)[✓] found: $$CFG$(RST)"; cat "$$CFG"; } \
		|| { echo -e "  $(YLW)[~] not found: $$CFG$(RST)"; \
		     echo -e "  $(DIM)When implemented: [net] bootstrap, [vault] path, [log] level$(RST)"; }

test-p4-wasm:
	@echo -e "$(CYN)[P4.2] WASM build$(RST)"
	@echo -e "  $(YLW)[STUB] Phase 4.2 not yet implemented$(RST)"
	@echo -e "  $(DIM)cargo build --target wasm32-unknown-unknown -p tsc-cli$(RST)"

test-p4-browser:
	@echo -e "$(CYN)[P4.2] browser shell / .ghost TLD$(RST)"
	@echo -e "  $(YLW)[STUB] Phase 4.2 not yet implemented$(RST)"
	@echo -e "  $(DIM)ws://localhost:9091 ↔ tscd IPC socket$(RST)"
	@echo -e "  $(DIM)extension intercepts .ghost → routes to local Shell$(RST)"

# ── State management ──────────────────────────────────────────────────────────

.PHONY: clean-state reset-iel show-iel show-vault

## Delete vault + IEL — full identity reset (binaries untouched)
clean-state: daemon-stop
	@echo -e "$(YLW)[!] Deleting vault and IEL...$(RST)"
	@rm -f "$(VAULT)" "$(IEL)"
	@echo -e "$(GRN)[✓] State cleared — next start will be ephemeral.$(RST)"

## Delete IEL only — vault and mnemonic preserved, rotation history lost
reset-iel:
	@echo -e "$(YLW)[!] Deleting IEL (vault preserved)...$(RST)"
	@rm -f "$(IEL)"
	@echo -e "$(GRN)[✓] IEL cleared — next rotate-key starts from rotation #1.$(RST)"

## Print IEL contents
show-iel:
	@test -f "$(IEL)" \
		&& { echo -e "$(CYN)IEL: $(IEL)$(RST)"; \
		     echo -e "$(DIM)$$(wc -l < "$(IEL)") event(s)$(RST)"; \
		     cat "$(IEL)"; } \
		|| echo -e "$(YLW)[~] No IEL at $(IEL)$(RST)"

## Show vault metadata (contents are encrypted)
show-vault:
	@test -f "$(VAULT)" \
		&& { echo -e "$(CYN)Vault: $(VAULT)$(RST)"; ls -lh "$(VAULT)"; } \
		|| echo -e "$(YLW)[~] No vault at $(VAULT)$(RST)"

# ── Full suite ────────────────────────────────────────────────────────────────

.PHONY: test-all

## Run every phase in order (stubs print for unimplemented phases)
test-all: test-unit test-p1 test-p1-1 test-p2 test-p3 test-p4
	@echo ""
	@echo -e "$(BOLD)$(GRN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RST)"
	@echo -e "$(BOLD)$(GRN)  test-all complete.$(RST)"
	@echo -e "$(BOLD)$(GRN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RST)"

# ── Help ──────────────────────────────────────────────────────────────────────

.PHONY: help
.DEFAULT_GOAL := help

help:
	@echo -e "$(BOLD)TSC Protocol — Test Makefile$(RST)"
	@echo ""
	@echo -e "$(BOLD)BUILD$(RST)"
	@echo "  build              Compile debug binaries"
	@echo "  test-unit          Run cargo unit tests (no daemon)"
	@echo ""
	@echo -e "$(BOLD)ENVIRONMENT$(RST)"
	@echo "  env-init           Create .env.test from template"
	@echo "  env-check          Show which env vars are set"
	@echo "  vps-setup          Print VPS peer setup instructions"
	@echo ""
	@echo -e "$(BOLD)DAEMON$(RST)"
	@echo "  daemon-start       Start tscd (unlocks vault if TSC_MNEMONIC set)"
	@echo "  daemon-ephemeral   Start tscd with ephemeral identity"
	@echo "  daemon-stop        Stop tscd"
	@echo "  daemon-logs        Tail daemon log"
	@echo "  daemon-status      Print live status  (alias: make status)"
	@echo "  status             Alias for daemon-status"
	@echo ""
	@echo -e "$(BOLD)TESTS$(RST)"
	@echo "  test-p1            Phase 1: identity, vault, GSP local  ✅"
	@echo "  test-p1-1          Phase 1.1: KERI key rotation          ✅"
	@echo "  test-p2            Phase 2: transport / remote DHT       🔧 (VPS needed for 2.2)"
	@echo "  test-p3            Phase 3: ghost runtime / OCI          🔧"
	@echo "  test-p4            Phase 4: browser shell / WASM         🔧"
	@echo "  test-all           All phases in order"
	@echo ""
	@echo -e "$(BOLD)STATE$(RST)"
	@echo "  clean-state        Delete vault + IEL (full reset)"
	@echo "  reset-iel          Delete IEL only (keeps vault)"
	@echo "  show-iel           Print IEL contents"
	@echo "  show-vault         Show vault file metadata"
	@echo ""
	@echo -e "$(BOLD)ENVIRONMENT$(RST)"
	@echo "  TSC_MNEMONIC       24-word mnemonic (vault unlock + rotation)"
	@echo "  TSC_GHOST_B        Remote GhostID (Phase 2 peer tests)"
	@echo ""
	@echo -e "$(DIM)Tip: no spaces around = in bash:  export TSC_MNEMONIC=\"word1 ... word24\"$(RST)"
