# Paving Agent

> One command discovers everything running on a node, maps its connections, installs watchtower coverage, and opens a pre-loaded AI conversation with full system context.

```bash
curl -sSL https://agent.millyweb.com/install | bash
```

No config files. No account required for local mode. One command, ~60 seconds, node appears on topology map.

---

## Status

**v0.1.0 — in development**. Phase 1 of a 4-phase roadmap. See [docs/PRD.md](docs/PRD.md).

## What It Does

1. **Discovery Scan** — reads open ports, processes, Docker containers, systemd services, live TCP connections. Ground truth, not documentation.
2. **60s Packet Trace** — `tcpdump` captures actual traffic. Reveals real connections vs declared ones. Generates `connection_policy.json` baseline for zero trust.
3. **Intake Dialogue** — streaming Claude API in the terminal. 3-5 targeted questions. Plain English answers. LLM produces an Intent Model JSON.
4. **Probe Installation** — Ring 1/2/3 emitters, sidecar probes for third-party services, per-node MCP provisioner (11 tools), health contracts auto-generated.
5. **Helix Registration + Conversation Handoff** — registers `NodeDefinition` + `IntentModel`. Prints handoff URL. AI arrives pre-loaded.

## Architecture

- Single Go binary, no runtime dependencies, cross-platform (Linux + Windows).
- Discovery-first: reads reality, doesn't trust config files.
- Per-node MCP provisioner: 11 tools (status, containers, restart, logs, exec, connections, emit_state, health_check, connection_policy, approve_connection, block_connection), port 9201.
- Integrates with [Watchtower Mesh](https://github.com/rdmilly/watchtower-mesh) and [Helix Cortex](https://helix.millyweb.com).

## License

MIT. See [LICENSE](LICENSE).
