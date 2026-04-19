package trace

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"time"
)

// DefaultDuration is the PRD-mandated capture window for the OBSERVE
// baseline. Keep this a constant — other tooling and documentation
// assume 60 seconds.
const DefaultDuration = 60 * time.Second

// flowKey identifies a uniquely-aggregable flow. Outbound flows key on
// (remote, remotePort, proto); inbound flows key on (remote, localPort, proto).
// Direction is encoded in the struct itself so one map serves both.
type flowKey struct {
	Direction string // "out" or "in"
	Remote    string
	PeerPort  int // dst port for out, src port's target (our port) for in
	Proto     string
}

type flowAgg struct {
	Packets   int64
	Bytes     int64
	FirstSeen time.Time
	LastSeen  time.Time
}

// Capture runs a packet trace on iface for duration, then returns a
// ConnectionPolicy. Requires CAP_NET_RAW or root; fails with a warning
// if tcpdump is missing or denies us access.
func Capture(ctx context.Context, iface string, duration time.Duration) (*ConnectionPolicy, error) {
	if iface == "" {
		return nil, fmt.Errorf("interface required")
	}
	if duration <= 0 {
		duration = DefaultDuration
	}

	policy := &ConnectionPolicy{
		SchemaVersion: SchemaVersion,
		Interface:     iface,
		DurationSec:   int(duration.Seconds()),
	}

	// Look up our own IPs before we start — cheap, no race vs kernel since
	// interface changes during a 60s window are rare enough to ignore.
	locals, flat, err := gatherLocalAddresses()
	if err != nil {
		policy.Warnings = append(policy.Warnings, fmt.Sprintf("gather local addrs: %v", err))
	}
	sort.Strings(flat)
	policy.LocalAddresses = flat

	// tcpdump inherits its own bounded lifetime via a child context.
	runCtx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()

	cmd, stdout, err := runTCPDump(runCtx, iface)
	if err != nil {
		policy.Warnings = append(policy.Warnings, fmt.Sprintf("tcpdump start: %v", err))
		return policy, nil // fail soft
	}

	policy.StartedAt = time.Now().UTC().Format(time.RFC3339)

	packets := make(chan parsedPacket, 512)
	go consumeLines(stdout, packets)

	flows := map[flowKey]*flowAgg{}
	var totalPackets, totalBytes, parsed int64

	for p := range packets {
		totalPackets++
		totalBytes += p.ByteLength
		parsed++

		key, ok := classifyFlow(p, locals)
		if !ok {
			continue
		}

		agg, exists := flows[key]
		if !exists {
			agg = &flowAgg{FirstSeen: p.Timestamp}
			flows[key] = agg
		}
		agg.Packets++
		agg.Bytes += p.ByteLength
		agg.LastSeen = p.Timestamp
	}

	_ = cmd.Wait()

	policy.EndedAt = time.Now().UTC().Format(time.RFC3339)
	policy.TotalPackets = totalPackets
	policy.TotalBytes = totalBytes
	policy.ParsedPackets = parsed
	policy.OutboundDestinations, policy.InboundSources = aggregate(flows)

	if cmd.ProcessState != nil && !cmd.ProcessState.Success() && totalPackets == 0 {
		policy.Warnings = append(policy.Warnings, fmt.Sprintf("tcpdump exited early with no packets: %s", cmd.ProcessState.String()))
	}

	return policy, nil
}

// classifyFlow decides inbound vs outbound and returns the aggregation key.
func classifyFlow(p parsedPacket, locals localAddressSet) (flowKey, bool) {
	srcLocal := locals.has(p.SrcAddr)
	dstLocal := locals.has(p.DstAddr)

	switch {
	case srcLocal && !dstLocal:
		return flowKey{Direction: "out", Remote: p.DstAddr, PeerPort: p.DstPort, Proto: p.Protocol}, true
	case !srcLocal && dstLocal:
		return flowKey{Direction: "in", Remote: p.SrcAddr, PeerPort: p.DstPort, Proto: p.Protocol}, true
	case srcLocal && dstLocal:
		// Loopback / inter-interface. Treat as outbound from src's perspective.
		return flowKey{Direction: "out", Remote: p.DstAddr, PeerPort: p.DstPort, Proto: p.Protocol}, true
	default:
		return flowKey{}, false
	}
}

// aggregate converts the in-memory flow map into sorted Destination and
// Source slices. Sort order: packet count desc, then remote addr asc —
// stable across runs so diffs are meaningful.
func aggregate(flows map[flowKey]*flowAgg) ([]Destination, []Source) {
	var outs []Destination
	var ins []Source

	for k, a := range flows {
		fs := a.FirstSeen.UTC().Format(time.RFC3339)
		ls := a.LastSeen.UTC().Format(time.RFC3339)
		if k.Direction == "out" {
			outs = append(outs, Destination{
				RemoteAddr:  k.Remote,
				RemotePort:  k.PeerPort,
				Protocol:    k.Proto,
				PacketCount: a.Packets,
				ByteCount:   a.Bytes,
				FirstSeen:   fs,
				LastSeen:    ls,
			})
		} else {
			ins = append(ins, Source{
				RemoteAddr:  k.Remote,
				LocalPort:   k.PeerPort,
				Protocol:    k.Proto,
				PacketCount: a.Packets,
				ByteCount:   a.Bytes,
				FirstSeen:   fs,
				LastSeen:    ls,
			})
		}
	}

	sort.Slice(outs, func(i, j int) bool {
		if outs[i].PacketCount != outs[j].PacketCount {
			return outs[i].PacketCount > outs[j].PacketCount
		}
		return outs[i].RemoteAddr < outs[j].RemoteAddr
	})
	sort.Slice(ins, func(i, j int) bool {
		if ins[i].PacketCount != ins[j].PacketCount {
			return ins[i].PacketCount > ins[j].PacketCount
		}
		return ins[i].RemoteAddr < ins[j].RemoteAddr
	})
	return outs, ins
}

// keep exec import used only via ProcessState reference above.
var _ = exec.ErrNotFound

// WriteJSON serializes a ConnectionPolicy to the given writer as indented JSON.
func WriteJSON(w io.Writer, p *ConnectionPolicy) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(p)
}
