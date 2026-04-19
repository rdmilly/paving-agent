# Paving Agent — PRD

The canonical PRD lives in Helix Working KB at:

    projects/watchtower/paving-agent-prd.md

Rendered copy published at: https://dash.millyweb.com/paving-agent/

---

## Scope of This Repository

This repo implements the agent binary itself — the Go program that discovers
a node, generates a `NodeScan`, runs the intake dialogue, installs probes,
and registers the node with Helix. It does NOT contain:

- The Helix node registration endpoint (lives in `rdmilly/helix` / Cortex).
- The Watchtower aggregator or dashboard (lives in `rdmilly/watchtower-mesh`).
- The per-service sidecar probes (separate tiny Go programs, future repo).

## Build Phases (recap)

- **Phase 1** — Proof of concept on a fresh node. Scanner, packet trace,
  intake dialogue, probe installer, local MCP provisioner (port 9201),
  Helix registration, MemBrain handoff, one-command installer.
- **Phase 2** — Retrofit VPS1, VPS2, Clair. CLI chat mode.
- **Phase 3** — Self-healing, Intent Model confidence updates.
- **Phase 4** — Product packaging: multi-tenant, hosted dashboard, public installer.

Current focus: **Phase 1.1 — Discovery Scanner**. See `internal/scanner/`.

## Spec Deltas from Working KB PRD

- Local MCP provisioner port: **9201** (PRD says 9200, moved to avoid
  collision with ElasticSearch when a node also hosts Postiz).
- Tool count: PRD heading says 8 tools, body lists 11. Treat 11 as
  authoritative: status, containers, restart, logs, exec, connections,
  emit_state, health_check, connection_policy, approve_connection,
  block_connection.

Any further divergences from the canonical PRD will be logged here.
