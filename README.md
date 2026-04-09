# Percepta Reactive SIEM

Custom Reactive SIEM for cybersecurity student FYP.

Percepta is a lightweight SIEM-style platform focused on **real-time ingestion**, **rule-based detection**, and **reactive automation**. It supports an agent/server architecture with mTLS (RSA-2048) and includes components for parsing/normalization, correlation, alerting, and operational dashboards.

## Key Features

- **Agent + Server** architecture (Rust)
- **mTLS** enrollment/identity flow (RSA-2048)
- **Ingestion + normalization** pipeline
- **Detection & correlation** (rule-driven)
- **Alerts / cases / response workflows**
- **Playbooks / reactive automation** (where configured)
- **Docker-first** local deployment via `docker-compose.yml`

## Repository Structure

- `agent/` — endpoint agent
- `server/` — backend services + APIs + dashboard assets
- `shared/` — shared crates/proto/contracts
- `docs/` — documentation and final-year report sources
- `deploy/` — deployment scripts and service units
- `tools/` — helper utilities/scripts

## Quick Start (Local)

Prerequisites:

- Rust toolchain
- Docker + Docker Compose

Common entry points:

- Docker: `docker-compose up -d`
- Rust server (example): `cd server && cargo run`
- Rust agent (example): `cd agent && cargo run`

> The exact runtime wiring (ports, env vars, services) is documented under `docs/`.

## Security Notes

- This repository may include certificates and local deployment helpers intended for development.
- Review and rotate any secrets before using in production environments.

## Documentation

Start here:

- `docs/` (architecture, pipeline, RBAC/security model, deployment/runbooks, etc.)
