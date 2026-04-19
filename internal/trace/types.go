// Package trace runs a short passive packet capture via tcpdump and
// aggregates observed traffic into a ConnectionPolicy document. That
// policy is the OBSERVE-mode baseline for the zero-trust enforcement
// ladder described in the Paving Agent PRD.
//
// The trace runs for a fixed duration (default 60s), reads line-buffered
// output from tcpdump, classifies each packet as inbound or outbound by
// comparing against the node's own IP addresses, and aggregates flows
// by (remote_addr, remote_port, protocol) for outbound and by
// (remote_addr, local_port, protocol) for inbound.
//
// This is an OBSERVE-only module. It never drops, blocks, or modifies
// packets — enforcement is a later phase.
package trace

// SchemaVersion of the ConnectionPolicy document.
const SchemaVersion = "1"

// ConnectionPolicy is the output of a single trace session. It is both
// a snapshot (what did we see in the last 60s?) and a policy candidate
// (what should we allow in OBSERVE mode going forward?).
type ConnectionPolicy struct {
	SchemaVersion string `json:"schema_version"`
	Interface     string `json:"interface"`
	DurationSec   int    `json:"duration_sec"`
	StartedAt     string `json:"started_at"` // RFC3339 UTC
	EndedAt       string `json:"ended_at"`   // RFC3339 UTC

	// Counts across the entire capture. Useful for sanity-checking
	// that the capture actually ran and the interface is right.
	TotalPackets  int64 `json:"total_packets"`
	TotalBytes    int64 `json:"total_bytes"`
	ParsedPackets int64 `json:"parsed_packets"` // subset we could parse

	// The node's own IP addresses at capture time. Used for direction
	// inference and included in output so downstream tools don't have
	// to guess.
	LocalAddresses []string `json:"local_addresses"`

	// OutboundDestinations is every (remote_addr, remote_port, proto)
	// triple we sent packets to during the capture, aggregated. This is
	// the primary zero-trust allowlist candidate.
	OutboundDestinations []Destination `json:"outbound_destinations"`

	// InboundSources is every (remote_addr, local_port, proto) triple
	// that sent packets to us, aggregated. Useful for understanding
	// which of our listening ports are actually being reached from the
	// outside, separate from what's declared in Ports.
	InboundSources []Source `json:"inbound_sources"`

	Warnings []string `json:"warnings"`
}

// Destination is an outbound flow aggregate: we sent traffic to this peer.
// A single Destination can represent many TCP connections over the capture
// window if they share peer IP, peer port, and protocol.
type Destination struct {
	RemoteAddr  string `json:"remote_addr"`
	RemotePort  int    `json:"remote_port"`
	Protocol    string `json:"protocol"` // tcp, udp
	PacketCount int64  `json:"packet_count"`
	ByteCount   int64  `json:"byte_count"`
	FirstSeen   string `json:"first_seen"` // RFC3339
	LastSeen    string `json:"last_seen"`
}

// Source is an inbound flow aggregate: this peer sent traffic to one of
// our listening ports. LocalPort is the service port they reached.
type Source struct {
	RemoteAddr  string `json:"remote_addr"`
	LocalPort   int    `json:"local_port"`
	Protocol    string `json:"protocol"`
	PacketCount int64  `json:"packet_count"`
	ByteCount   int64  `json:"byte_count"`
	FirstSeen   string `json:"first_seen"`
	LastSeen    string `json:"last_seen"`
}
