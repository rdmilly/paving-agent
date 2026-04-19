// Package scanner reads ground-truth system state from a node: open ports,
// processes, Docker containers, systemd services, and live TCP connections.
//
// Discovery-first: it does NOT trust config files, declared services, or
// infrastructure-as-code manifests. It reads what is actually running,
// right now, via standard Linux tools (ss, ps, docker, systemctl, ip).
//
// Output is a NodeScan JSON document. See types.go for the schema.
package scanner

import (
	"context"
	"encoding/json"
	"io"
	"time"
)

// Version of the NodeScan schema. Bump on breaking changes.
const SchemaVersion = "1"

// Scan collects ground-truth state from the local node and returns a NodeScan.
// Context is accepted for cancellation but current implementation does not
// use it; subcommands like `ss` and `docker ps` run to completion quickly.
func Scan(ctx context.Context) (*NodeScan, error) {
	start := time.Now()

	scan := &NodeScan{
		SchemaVersion: SchemaVersion,
		CapturedAt:    start.UTC().Format(time.RFC3339),
	}

	// TODO(phase-1.1): Populate each section.
	//   - Host (hostname, kernel, distro, uptime, resources)
	//   - Ports (ss -tlnp: listening TCP sockets + owning process)
	//   - Processes (ps: pid, cmd, user, memory)
	//   - Containers (docker ps --format JSON)
	//   - Services (systemctl list-units --type=service --state=running)
	//   - Connections (ss -tnp: established outbound connections)
	//   - Routes (ip route: default interface, gateway)
	//
	// Each collector must:
	//   - Fail soft: missing binary (e.g., no docker) produces empty section + warning, not fatal.
	//   - Be idempotent and side-effect free.
	//   - Complete in under a second on a typical node.

	scan.DurationMS = time.Since(start).Milliseconds()
	return scan, nil
}

// WriteJSON serializes a NodeScan to the given writer as indented JSON.
func WriteJSON(w io.Writer, s *NodeScan) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}
