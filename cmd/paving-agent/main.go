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
	iface := fs.String("interface", "", "interface to capture on (default: auto-detect from scanner's default route)")
	durationSec := fs.Int("duration", 60, "capture duration in seconds")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	// Auto-detect interface from the scanner's route collector when not specified.
	// Keeps trace and scan consistent without user having to eyeball `ip route`.
	if *iface == "" {
		resolved, err := detectDefaultInterface(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "auto-detect interface failed: %v\nspecify --interface explicitly\n", err)
			os.Exit(1)
		}
		*iface = resolved
	}

	fmt.Fprintf(os.Stderr, "capturing on %s for %ds...\n", *iface, *durationSec)
	policy, err := trace.Capture(ctx, *iface, time.Duration(*durationSec)*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "capture failed: %v\n", err)
		os.Exit(1)
	}
	if err := trace.WriteJSON(os.Stdout, policy); err != nil {
		fmt.Fprintf(os.Stderr, "write failed: %v\n", err)
		os.Exit(1)
	}
}

// detectDefaultInterface asks the scanner's route collector which interface
// owns the default route. Used when `trace` is invoked without --interface.
func detectDefaultInterface(ctx context.Context) (string, error) {
	routes, warnings := scanner.CollectRoutes(ctx)
	for _, r := range routes {
		if r.IsDefault && r.Interface != "" {
			return r.Interface, nil
		}
	}
	if len(warnings) > 0 {
		return "", fmt.Errorf("%s", warnings[0])
	}
	return "", fmt.Errorf("no default route found")
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `paving-agent %s

usage: paving-agent <command> [flags]

commands:
  scan                      Discover services, processes, containers, connections.
                            Outputs NodeScan JSON to stdout.
  trace [flags]             60s passive packet capture via tcpdump.
                            Outputs ConnectionPolicy JSON to stdout.
    --interface <name>      Interface to capture on (default: auto-detect default route).
    --duration <seconds>    Capture duration (default: 60).
  version                   Print version.
  help                      Show this help.

planned (not yet implemented):
  intake     Streaming LLM dialogue; generates IntentModel JSON.
  probe      Install health-check probes for discovered services.
  register   POST NodeDefinition + IntentModel to Helix.
  chat       Local CLI chat with Claude, pre-loaded with node context.
  install    Full Phase-1 run-all: scan → trace → intake → probe → register.
`, version)
}
