// Package main is the entry point for paving-agent.
//
// Paving Agent discovers everything running on a node, maps its connections,
// installs watchtower coverage at every discovered service, and opens a
// pre-loaded AI conversation with full system context.
//
// See docs/PRD.md for the full specification.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/rdmilly/paving-agent/internal/scanner"
)

const version = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	ctx := context.Background()
	cmd := os.Args[1]

	switch cmd {
	case "scan":
		runScan(ctx)
	case "version", "--version", "-v":
		fmt.Printf("paving-agent %s\n", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(2)
	}
}

func runScan(ctx context.Context) {
	result, err := scanner.Scan(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
		os.Exit(1)
	}
	if err := scanner.WriteJSON(os.Stdout, result); err != nil {
		fmt.Fprintf(os.Stderr, "write failed: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `paving-agent %s

usage: paving-agent <command>

commands:
  scan       Discover services, processes, containers, connections on this node.
             Outputs NodeScan JSON to stdout.
  version    Print version.
  help       Show this help.

planned (not yet implemented):
  trace      60s passive packet trace; generates connection_policy.json.
  intake     Streaming LLM dialogue; generates IntentModel JSON.
  probe      Install health-check probes for discovered services.
  register   POST NodeDefinition + IntentModel to Helix.
  chat       Local CLI chat with Claude, pre-loaded with node context.
`, version)
}
