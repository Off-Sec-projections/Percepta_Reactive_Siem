# ─────────────────────────────────────────────────────────────────────
#  Percepta SIEM — Developer Makefile
# ─────────────────────────────────────────────────────────────────────
.PHONY: check build build-release run test test-server test-agent \
	clippy fmt rules-lint rules-lint-baseline clean help \
	geoip setup-cross build-agent-linux build-agent-windows \
	build-installer-linux build-installer-windows \
	dist dist-server _assemble_dist deploy-pack deploy-pack-fast \
	push push-dashboard push-binary push-config push-rollback push-agents remote-status remote-logs

# ── Build ────────────────────────────────────────────────────────────

check: ## Cargo check (entire workspace)
	cargo check --workspace

build: ## Debug build (server + agent)
	cargo build --workspace

build-server: ## Debug build (server only)
	cargo build -p percepta-server

build-agent: ## Debug build (agent only)
	cargo build -p percepta-agent

build-release: ## Optimised release build (server)
	cargo build --release -p percepta-server

# ── Run ──────────────────────────────────────────────────────────────

run: ## Run the SIEM server (dev mode, self-signed TLS)
	cargo run -p percepta-server

run-proxy: ## Run in proxy mode (HTTP, put Nginx in front)
	PERCEPTA_BEHIND_PROXY=1 PERCEPTA_WEB_BIND=127.0.0.1:8080 cargo run -p percepta-server

# ── Test ─────────────────────────────────────────────────────────────

test: test-server test-agent ## Run all tests

test-server: ## Server unit + integration tests
	cargo test -p percepta-server

test-agent: ## Agent integration tests
	cargo test -p percepta-agent --test integration -- --nocapture

# ── Lint / Format ────────────────────────────────────────────────────

clippy: ## Run clippy on workspace
	cargo clippy --workspace -- -W clippy::all

fmt: ## Auto-format all Rust code
	cargo fmt --all

fmt-check: ## Check formatting without modifying
	cargo fmt --all -- --check

rules-lint: ## Validate detection rules quality (IDs, metadata, regex) with baseline ratchet
	cargo run -p fake-agent --bin rules-lint -- server/rules.yaml --require-metadata --deny-warnings --baseline tools/rules-lint-baseline.txt

rules-lint-baseline: ## Regenerate rules lint baseline from current findings
	cargo run -p fake-agent --bin rules-lint -- server/rules.yaml --require-metadata --write-baseline tools/rules-lint-baseline.txt

# ── Offline bundle (nginx debs + acme.sh) ────────────────────────────

bundle-nginx: ## Download nginx debs + acme.sh for offline deployment (no internet on target server)
	@echo "Preparing offline deployment bundle..."
	@mkdir -p deploy/bundle
	@# Download nginx .deb files (for offline apt install)
	@echo "  Downloading nginx packages..."
	@cd deploy/bundle && apt-get download nginx nginx-common 2>/dev/null \
		&& echo "  ✓ nginx debs downloaded" \
		|| echo "  ✗ Could not download nginx debs (apt-get download failed — check apt repos)"
	@# Download acme.sh — pure-shell ACME client, replaces certbot, zero dependencies
	@if [ ! -f deploy/bundle/acme.sh ]; then \
		echo "  Downloading acme.sh (pure-shell SSL cert tool)..."; \
		curl -sSL "https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh" \
			-o deploy/bundle/acme.sh 2>/dev/null \
			&& chmod +x deploy/bundle/acme.sh \
			&& echo "  ✓ acme.sh downloaded" \
			|| echo "  ✗ Could not download acme.sh (check internet)"; \
	else \
		echo "  ✓ acme.sh already present"; \
	fi
	@echo "  Bundle contents:"
	@ls -lh deploy/bundle/ 2>/dev/null || true
	@echo ""
	@echo "✅ Offline bundle ready in deploy/bundle/"
	@echo "   The dist package will include this bundle — nginx installs from local debs,"
	@echo "   no apt-get needed on the target server."

# ── GeoIP ────────────────────────────────────────────────────────────

geoip: ## Download DB-IP City Lite mmdb (free, no account/key needed)
	@bash tools/install_geolite2_city_mmdb.sh

geoip-maxmind: ## Download MaxMind GeoLite2 (requires MAXMIND_LICENSE_KEY env var)
	@MAXMIND_LICENSE_KEY="$${MAXMIND_LICENSE_KEY:?Set MAXMIND_LICENSE_KEY}" \
		bash tools/install_geolite2_city_mmdb.sh

# ── Cross-compilation ─────────────────────────────────────────────────

setup-cross: ## Install cross-compilation toolchains for Linux musl + Windows
	@echo "Installing mingw-w64 (Windows cross-compiler)..."
	@sudo apt-get install -y mingw-w64 musl-tools 2>/dev/null || true
	rustup target add x86_64-pc-windows-gnu 2>/dev/null || true
	rustup target add x86_64-unknown-linux-musl 2>/dev/null || true
	@echo "Cross-compilation toolchains ready."

build-agent-linux: ## Build agent for Linux (musl static binary — runs on any Linux distro)
	cargo build --release -p percepta-agent --target x86_64-unknown-linux-musl

build-agent-windows: build-agent-windows-gnu ## Build the Windows GNU fallback artifact

build-agent-windows-gnu: ## Cross-compile agent for Windows GNU fallback (requires mingw-w64)
	CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
		cargo build --release -p percepta-agent --target x86_64-pc-windows-gnu

build-agent-windows-msvc: ## Build the preferred Windows MSVC artifact (run on Windows or CI with MSVC)
	cargo build --release -p percepta-agent --target x86_64-pc-windows-msvc

build-installer-linux: ## Build the native GUI installer for Linux
	cargo build --release -p percepta-agent --bin percepta-installer

build-installer-windows: ## Cross-compile the GUI installer for Windows (requires mingw-w64)
	CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
		cargo build --release -p percepta-agent --bin percepta-installer \
		--target x86_64-pc-windows-gnu

# ── Distribution package ──────────────────────────────────────────────

# Shared assembly logic (called by dist and dist-server)
_assemble_dist:
	@echo "Assembling distribution package..."
	@mkdir -p dist/percepta-siem/agent_builds dist/percepta-siem/geoip \
		dist/percepta-siem/deploy dist/percepta-siem/bundle
	@# Server binary
	@cp target/release/percepta-server dist/percepta-siem/ \
		&& echo "  ✓ percepta-server ($(du -h target/release/percepta-server | cut -f1))" \
		|| { echo "  ✗ FATAL: percepta-server binary missing"; exit 1; }
	@# Agent binaries — prefer glibc (GUI needs dlopen), fall back to musl-static
	@if [ -f target/release/percepta-agent ]; then \
		cp target/release/percepta-agent dist/percepta-siem/agent_builds/percepta-agent-linux && \
		cp target/release/percepta-agent dist/percepta-siem/agent_builds/percepta-agent && \
		echo "  ✓ Linux agent (glibc)"; \
	elif [ -f target/x86_64-unknown-linux-musl/release/percepta-agent ]; then \
		cp target/x86_64-unknown-linux-musl/release/percepta-agent dist/percepta-siem/agent_builds/percepta-agent-linux && \
		cp target/x86_64-unknown-linux-musl/release/percepta-agent dist/percepta-siem/agent_builds/percepta-agent && \
		echo "  ✓ Linux agent (musl-static)"; \
	else \
		echo "  ⊘ Linux agent (not built — use 'make dist' to include)"; \
	fi
	@if [ -f target/x86_64-pc-windows-msvc/release/percepta-agent.exe ]; then \
		cp target/x86_64-pc-windows-msvc/release/percepta-agent.exe dist/percepta-siem/agent_builds/percepta-agent-windows.exe && \
		cp target/x86_64-pc-windows-msvc/release/percepta-agent.exe dist/percepta-siem/agent_builds/percepta-agent.exe && \
		echo "  ✓ Windows agent (msvc)"; \
	elif [ -f target/x86_64-pc-windows-gnu/release/percepta-agent.exe ]; then \
		cp target/x86_64-pc-windows-gnu/release/percepta-agent.exe dist/percepta-siem/agent_builds/percepta-agent-windows.exe && \
		cp target/x86_64-pc-windows-gnu/release/percepta-agent.exe dist/percepta-siem/agent_builds/percepta-agent.exe && \
		echo "  ✓ Windows agent (gnu fallback)"; \
	else \
		echo "  ⊘ Windows agent (not built — use 'make dist' to include)"; \
	fi
	@# Or use existing from VPS agent_builds/ if we have them locally
	@if [ -z "$$(ls dist/percepta-siem/agent_builds/ 2>/dev/null)" ] && [ -d server/agent_builds ] && [ "$$(ls server/agent_builds/ 2>/dev/null)" ]; then \
		cp server/agent_builds/* dist/percepta-siem/agent_builds/ 2>/dev/null; \
		echo "  ✓ Agent builds (from server/agent_builds/)"; \
	fi
	@# GeoIP database
	@cp server/geoip/GeoLite2-City.mmdb dist/percepta-siem/geoip/ 2>/dev/null && \
		echo "  ✓ GeoIP database" || echo "  ⊘ GeoIP db missing (run: make geoip)"
	@# Deploy scripts
	@cp deploy/setup-nginx.sh deploy/deploy.sh deploy/push.sh \
		deploy/percepta-server.service dist/percepta-siem/deploy/
	@cp deploy/.env.deploy dist/percepta-siem/deploy/ 2>/dev/null || true
	@chmod +x dist/percepta-siem/deploy/*.sh
	@echo "  ✓ Deploy scripts"
	@# Offline bundle (nginx debs + acme.sh)
	@if [ -d deploy/bundle ]; then cp -rn deploy/bundle/. dist/percepta-siem/bundle/ 2>/dev/null || true; fi
	@ls dist/percepta-siem/bundle/*.deb >/dev/null 2>&1 && echo "  ✓ Offline nginx bundle" || echo "  ⊘ Offline bundle missing (run: make bundle-nginx)"
	@# Server runtime assets
	@cp -r server/dashboard dist/percepta-siem/ && echo "  ✓ Dashboard" || echo "  ✗ Dashboard missing"
	@cp server/rules.yaml dist/percepta-siem/ 2>/dev/null && echo "  ✓ rules.yaml" || echo "  ⊘ rules.yaml missing"
	@cp server/parsers.yaml dist/percepta-siem/ 2>/dev/null && echo "  ✓ parsers.yaml" || echo "  ⊘ parsers.yaml missing"
	@cp server/event_knowledge.json dist/percepta-siem/ 2>/dev/null && echo "  ✓ event_knowledge.json" || echo "  ⊘ event_knowledge.json missing"
	@cp -r server/compliance_mappings dist/percepta-siem/ 2>/dev/null && echo "  ✓ compliance_mappings" || true
	@cp -r server/config dist/percepta-siem/ 2>/dev/null && echo "  ✓ config" || true
	@cp -r server/Logo dist/percepta-siem/ 2>/dev/null && echo "  ✓ Logo" || true
	@cp -r server/static dist/percepta-siem/ 2>/dev/null && echo "  ✓ static" || true
	@# Readme
	@printf "# Percepta SIEM — Quick Start\n\n" > dist/percepta-siem/README.txt
	@printf "## Fresh Server Install\n" >> dist/percepta-siem/README.txt
	@printf "  cd /opt && tar xzf percepta-siem.tar.gz\n" >> dist/percepta-siem/README.txt
	@printf "  bash /opt/percepta-siem/deploy/deploy.sh cloud <domain> <admin-email>\n\n" >> dist/percepta-siem/README.txt
	@printf "## Update Existing Server\n" >> dist/percepta-siem/README.txt
	@printf "  cd /opt && tar xzf percepta-siem.tar.gz\n" >> dist/percepta-siem/README.txt
	@printf "  bash /opt/percepta-siem/deploy/deploy.sh update\n\n" >> dist/percepta-siem/README.txt
	@printf "## From Dev Machine (fast incremental push)\n" >> dist/percepta-siem/README.txt
	@printf "  make push              # build + deploy everything\n" >> dist/percepta-siem/README.txt
	@printf "  make push-dashboard    # deploy just JS/CSS/HTML\n" >> dist/percepta-siem/README.txt
	@printf "  make push-binary       # build + deploy binary only\n" >> dist/percepta-siem/README.txt
	@printf "  make push-rollback     # revert to previous binary\n" >> dist/percepta-siem/README.txt
	@echo ""
	@echo "✅ Distribution package: dist/percepta-siem/"
	@ls -lh dist/percepta-siem/ 2>/dev/null
	@echo ""
	@ls -lh dist/percepta-siem/agent_builds/ 2>/dev/null || true

dist: build-release build-agent-linux build-agent-windows build-installer-linux build-installer-windows bundle-nginx _assemble_dist ## Full distribution package (server + agents + installers — slow)

dist-server: build-release _assemble_dist ## Server-only dist (no agent cross-compile — fast)

deploy-pack: dist ## Create a tar.gz for upload — full (server + agents)
	tar -czf dist/percepta-siem.tar.gz -C dist percepta-siem/
	@echo ""
	@echo "✅ Package ready: dist/percepta-siem.tar.gz ($(du -h dist/percepta-siem.tar.gz | cut -f1))"
	@echo ""
	@echo "Fresh server:"
	@echo "  scp dist/percepta-siem.tar.gz root@YOUR_VPS_IP:/opt/"
	@echo "  ssh root@YOUR_VPS_IP 'cd /opt && tar xzf percepta-siem.tar.gz && bash percepta-siem/deploy/deploy.sh cloud YOUR_DOMAIN YOUR_EMAIL'"
	@echo ""
	@echo "Update existing:"
	@echo "  scp dist/percepta-siem.tar.gz root@YOUR_VPS_IP:/opt/"
	@echo "  ssh root@YOUR_VPS_IP 'cd /opt && tar xzf percepta-siem.tar.gz && bash percepta-siem/deploy/deploy.sh update'"

deploy-pack-fast: dist-server ## Create a tar.gz — server only (no agent cross-compile — much faster)
	tar -czf dist/percepta-siem.tar.gz -C dist percepta-siem/
	@echo ""
	@echo "✅ Package ready: dist/percepta-siem.tar.gz ($(du -h dist/percepta-siem.tar.gz | cut -f1))"
	@echo "   (server-only — agent binaries on VPS are preserved during update)"

# ── Push Deploy (incremental) ────────────────────────────────────────

push: build-release ## Build + deploy to VPS (fast incremental push)
	@bash deploy/push.sh

push-dashboard: ## Deploy only dashboard files (no build)
	@bash deploy/push.sh --dashboard-only

push-binary: build-release ## Build + deploy only the server binary
	@bash deploy/push.sh --binary-only

push-config: ## Deploy only rules/parsers/config
	@bash deploy/push.sh --config-only

push-agents: build-agent-linux build-agent-windows build-installer-linux build-installer-windows ## Build + deploy agent binaries and installers
	@bash deploy/push.sh --agents-only

push-rollback: ## Roll back to the previous binary on VPS
	@bash deploy/push.sh --rollback

remote-status: ## Show remote service status + memory + uptime
	@bash deploy/push.sh --status

remote-logs: ## Show last 50 log lines from the remote service
	@bash deploy/push.sh --logs 50

# ── Housekeeping ─────────────────────────────────────────────────────

clean: ## Remove build artefacts
	cargo clean

clean-dist: ## Remove dist folder
	rm -rf dist/

# ── Help ─────────────────────────────────────────────────────────────

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
