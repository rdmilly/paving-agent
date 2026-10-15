# PRD Addendum — Script Registry & Manifest System

**Status:** Draft (deferred build)
**Authored:** 2026-05-08, during Clair Explorer-hang incident
**Parent PRD:** [PRD.md](./PRD.md)
**Sync status:** Written direct via SSH; **needs backfill into Helix Forge KB when Helix is restored** (Helix was down at time of writing).

---

## Why this exists

While diagnosing why Clair's File Explorer hung tonight, we found that:

- A custom Python service (`frame_receiver.py`) was leaking TCP sockets due to an HTTP/1.0 default in `BaseHTTPRequestHandler`. 1,478 sockets in TIME_WAIT exhausted ephemeral ports → cascading failures (Steam service timeout, OpenSSH crash, Explorer windows unable to render).
- **Two scheduled tasks (`MillyPipeline` and `MillyFrameReceiver`) were both auto-launching `frame_receiver.py` on logon.** They raced for port 8765; one always lost and died silently. This had been happening on every boot for an unknown length of time with no visibility.
- There is currently **no central inventory** of which custom scripts run on Clair, what ports they bind, what their dependencies are, or how they auto-start. Discovery required walking Task Scheduler, Startup folder, services, and `Get-CimInstance Win32_Process`.

The Paving Agent is the right home for solving this, because each node should have a single declarative source of truth for "what runs here."

---

## Scope addition

The Paving Agent shall include a **Script Registry** subsystem that:

1. Reads per-node manifests describing every custom script/service running on the node
2. Enforces lifecycle (start, stop, restart, dependency ordering) per manifest declaration
3. Performs health checks and applies restart policies on failure
4. Reports status to Helix as the source-of-truth aggregator (Atrium can render)
5. Accepts deploys via `helix_file_write` to manifest-declared deploy paths (atomic-replace + restart + health-gate)

This is the **process-lifecycle parallel** of how the MCP Provisioner handles MCP server lifecycle — same shape, different domain.

---

## Manifest schema (proposed, JSON)

Location on node: `C:\manifests\*.json` (Windows) or `/etc/paving/manifests/*.json` (Linux).

```json
{
  "id": "milly.frame-receiver",
  "version": "2.7.1",
  "owner": { "project": "content-pipeline", "person": "ryan" },
  "runtime": {
    "type": "python",
    "interpreter": "C:\\Users\\Rdmil\\AppData\\Local\\Programs\\Python\\Python313\\python.exe"
  },
  "entrypoint": "C:\\Projects\\Millyweb\\content-pipeline\\recorder\\frame_receiver.py",
  "lifecycle": {
    "autostart": true,
    "trigger": "logon",
    "restart_policy": "on-failure",
    "stop_signal": "SIGTERM",
    "stop_grace_seconds": 10
  },
  "health": {
    "type": "http",
    "url": "http://localhost:8765/health",
    "interval_seconds": 30,
    "failure_threshold": 3
  },
  "network": {
    "binds": [{ "port": 8765, "protocol": "tcp" }],
    "depends_on_ports": [8766]
  },
  "depends_on": ["milly.orchestrator"],
  "logs": { "path": "C:\\Projects\\Millyweb\\content-pipeline\\recv_trace_8765.log" },
  "deploy": {
    "source": "helix:projects/content-pipeline/recorder/frame_receiver.py",
    "checksum_algo": "sha256"
  },
  "tags": ["pipeline", "recorder", "membrain"]
}
```

### Field intent

| Field | Purpose |
|-------|---------|
| `id` | Globally unique reverse-DNS-style identifier; how Helix and Atrium refer to this script. |
| `runtime` | What interpreter/runtime is needed. Lets agent verify presence before start. |
| `lifecycle.autostart` + `trigger` | Replaces direct Task Scheduler / Startup folder entries. Agent installs the platform-native hook on its own. |
| `lifecycle.restart_policy` | One of `never`, `on-failure`, `always`. Mirrors systemd semantics. |
| `health` | How the agent confirms the script is alive. HTTP for servers; `process` (PID exists) or `file` (mtime within window) for non-HTTP services. |
| `network.binds` | Declared ports prevent the kind of duplicate-registration race we hit tonight. Agent rejects start if port already bound by a different manifest. |
| `depends_on` | Topological start ordering. If `milly.frame-receiver` depends on `milly.orchestrator`, the orchestrator starts first and must be healthy before frame-receiver starts. |
| `deploy.source` | Where Helix stores the canonical version. Enables `helix_file_write` → atomic deploy. |

---

## Agent behaviors

### On boot
1. Read all manifests from local manifest dir
2. Validate schema, reject malformed
3. Topological sort by `depends_on`
4. For each: install autostart hook (platform-native: Task Scheduler on Windows, systemd on Linux), start, register health check
5. Push manifest inventory to Helix (sync, write-through; tolerates Helix being down via local queue)

### Continuous
- Run health checks per manifest
- On failure: apply `restart_policy`, log to Helix, alert via Atrium
- Publish status snapshot to Helix at fixed interval

### On deploy event (Helix → agent)
1. Pull new artifact at `deploy.source`, verify checksum
2. Atomic-replace target file
3. Stop process per `stop_signal` + `stop_grace_seconds`
4. Start
5. Health-gate before marking healthy; if check fails N times, rollback and alert

### Conflict detection
- Two manifests claiming the same `network.binds` port → reject second, alert
- Manifest declaring autostart + existing native autostart entry not registered to a manifest → flag for adoption or removal

---

## Migration path (non-breaking)

**Phase 1 (zero-behavior-change documentation):**
Author manifests for every existing script. Manifests sit on disk and describe reality. No agent enforcement yet. Value: discoverability, single source of truth.

**Phase 2 (read-only enforcement):**
Agent reads manifests, runs health checks, reports to Helix/Atrium. Does NOT yet manage lifecycle. Value: visibility.

**Phase 3 (managed lifecycle):**
Agent takes over autostart hook installation, restarts, deploys. Native Task Scheduler / systemd entries get retired one at a time as the agent proves itself per service.

---

## Non-goals (explicitly out of scope)

- Container orchestration (Docker/k8s already handle this; manifests describe non-containerized scripts)
- Cron-style time-based jobs (separate concern; could be a later extension via `lifecycle.trigger: "cron"`)
- Cross-node orchestration (manifests are per-node; cross-node coordination is a separate Helix concern)

---

## Worked example: tonight's bug solved by this design

Had this system existed:

1. Both `MillyPipeline` and `MillyFrameReceiver` declaring `binds: [8765]` → second manifest **rejected at validation time**, agent alerts: "Port 8765 already claimed by milly.frame-receiver in milly-pipeline.manifest"
2. `frame_receiver.py` health check failing as TIME_WAITs piled up → agent restarts per `on-failure` policy, logs to Helix, alert in Atrium
3. Pattern visible across multiple restarts → upgrade alert: "milly.frame-receiver restart rate exceeds threshold; investigate"
4. Atrium dashboard would show: "Clair: 4 services declared, 4 healthy. Last incident: milly.frame-receiver TIME_WAIT cascade, 21:09."

Instead, the failure was completely invisible until it propagated to Explorer hangs.

---

## Open questions for build phase

- Storage: per-node JSON files vs. a single SQLite manifest registry? (Lean toward JSON files — easier to diff, edit, version-control.)
- Helix sync model: push from agent vs. pull from Helix? (Lean push: agent is source of truth for its node's reality, Helix aggregates.)
- Manifest authoring UX: hand-edit JSON vs. CLI scaffolder vs. Atrium UI? (All three eventually; CLI scaffolder first.)
- Schema versioning strategy as fields evolve.

---

## References

- Tonight's incident: socket leak in `frame_receiver.py` (HTTP/1.0 default), root-caused 2026-05-08 ~21:00 PT
- Provisioner pattern: `/opt/projects/mcp-provisioner` (model for lifecycle management)
- Existing PRD: `./PRD.md`
