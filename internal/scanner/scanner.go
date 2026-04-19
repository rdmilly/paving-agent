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

// SchemaVersion of the NodeScan document. Bump on breaking changes.
const SchemaVersion = "1"

// Scan collects ground-truth state from the local node and returns a NodeScan.
//
// Collectors run sequentially. They're all fast (<1s each on a typical node),
// and the ordering is deliberate: Host first (fails fast if /proc is broken),
// Processes before Ports (so we have PIDs to cross-reference), Containers
// after Ports (so we've already noticed a listening 2375 before we ask docker
// itself). Each collector fails soft — a missing binary or permission denial
// adds a warning to the NodeScan but never aborts the whole scan.
func Scan(ctx context.Context) (*NodeScan, error) {
	start := time.Now()
	scan := &NodeScan{
		SchemaVersion: SchemaVersion,
		CapturedAt:    start.UTC().Format(time.RFC3339),
	}

	host, warnings := CollectHost(ctx)
	scan.Host = host
	scan.Warnings = append(scan.Warnings, warnings...)

	procs, tree, w := CollectProcesses(ctx)
	scan.Processes = procs
	scan.ProcessTree = tree
	scan.Warnings = append(scan.Warnings, w...)

	ports, w := CollectPorts(ctx)
	scan.Ports = ports
	scan.Warnings = append(scan.Warnings, w...)

	conns, w := CollectConnections(ctx)
	scan.Connections = conns
	scan.Warnings = append(scan.Warnings, w...)

	containers, w := CollectContainers(ctx)
	scan.Containers = containers
	scan.Warnings = append(scan.Warnings, w...)

	services, w := CollectServices(ctx)
	scan.Services = services
	scan.Warnings = append(scan.Warnings, w...)

	routes, w := CollectRoutes(ctx)
	scan.Routes = routes
	scan.Warnings = append(scan.Warnings, w...)

	scan.DurationMS = time.Since(start).Milliseconds()
	return scan, nil
}

// WriteJSON serializes a NodeScan to the given writer as indented JSON.
func WriteJSON(w io.Writer, s *NodeScan) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}
