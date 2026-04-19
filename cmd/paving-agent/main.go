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
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/rdmilly/paving-agent/internal/scanner"
	"github.com/rdmilly/paving-agent/internal/trace"
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
	case "trace":
		runTrace(ctx, os.Args[2:])
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

func runTrace(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("trace", flag.ExitOnError)
	iface := fs.String("iface", "", "interface to capture on (default: auto-detect from routes)")
	duration := fs.Duration("duration", 60*time.Second, "capture duration (e.g., 60s, 5s for testing)")
	_ = fs.Parse(args)

	// Auto-detect default interface if not provided.
	selectedIface := *iface
	if selectedIface == "" {
		scan, err := scanner.Scan(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "iface auto-detect: %v\n", err)
			os.Exit(1)
		}
		for _, r := range scan.Routes {
			if r.IsDefault && r.Interface != "" {
				selectedIface = r.Interface
				break
			}
		}
		if selectedIface == "" {
			fmt.Fprintln(os.Stderr, "no default route found; specify --iface explicitly")
			os.Exit(1)
		}
	}

	fmt.Fprintf(os.Stderr, "capturing on %s for %s... (needs root/CAP_NET_RAW)\n", selectedIface, *duration)
	policy, err := trace.Capture(ctx, selectedIface, *duration)
	if err != nil {
		fmt.Fprintf(os.Stderr, "trace failed: %v\n", err)
		os.Exit(1)
	}
	if err := trace.WriteJSON(os.Stdout, policy); err != nil {
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
  trace      Passive packet trace; generates connection_policy.json baseline.
             Flags: --iface <name>  (default: auto-detect from routes)
                    --duration <D>  (default: 60s)
  version    Print version.
  help       Show this help.

planned (not yet implemented):
  intake     Streaming LLM dialogue; generates IntentModel JSON.
  probe      Install health-check probes for discovered services.
  register   POST NodeDefinition + IntentModel to Helix.
  chat       Local CLI chat with Claude, pre-loaded with node context.
`, version)
}
