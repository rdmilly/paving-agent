package trace

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Capture runs tcpdump on `iface` for `duration` seconds and returns the
// observed flows aggregated into a ConnectionPolicy. Requires CAP_NET_RAW
// or root — the caller should check. Partial output on early exit is
// still returned (e.g., caller's ctx cancels).
func Capture(ctx context.Context, iface string, duration time.Duration) (*ConnectionPolicy, error) {
	policy := &ConnectionPolicy{
		SchemaVersion:   SchemaVersion,
		GeneratedAt:     time.Now().UTC().Format(time.RFC3339),
		Interface:       iface,
		DurationSec:     int(duration.Seconds()),
		EnforcementMode: "observe",
	}

	localAddrs, err := LocalAddrs()
	if err != nil {
		policy.Warnings = append(policy.Warnings, fmt.Sprintf("netif: %v", err))
		localAddrs = map[string]bool{}
	}

	// Bound the run with a context we control so we can cleanly stop tcpdump
	// at the duration boundary even if the OS buffers packets.
	runCtx, cancel := context.WithTimeout(ctx, duration+2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(runCtx, "tcpdump",
		"-i", iface,
		"-n",
		"-tttt",
		"-q",
		"-l",
		// Size reporting: include length byte count per packet.
		// tcpdump -q already emits it as "tcp N" / "UDP, length N".
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return policy, fmt.Errorf("tcpdump pipe: %w", err)
	}
	cmd.Stderr = nil // discard "listening on ..." banner noise
	if err := cmd.Start(); err != nil {
		return policy, fmt.Errorf("tcpdump start: %w", err)
	}

	// Stop tcpdump at exactly `duration` from now.
	go func() {
		select {
		case <-time.After(duration):
			_ = cmd.Process.Signal(syscall.SIGINT)
		case <-runCtx.Done():
		}
	}()

	agg := newAggregator(localAddrs)
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	for scanner.Scan() {
		agg.consume(scanner.Text())
	}

	// Reap the process; error on wait is expected when we signal it.
	_ = cmd.Wait()

	policy.Flows = agg.flows()
	policy.TotalPackets = agg.totalPackets
	policy.TotalBytes = agg.totalBytes
	return policy, nil
}

// packetLine matches tcpdump -tttt -q output for IP/IP6 packets.
// Examples:
//   2026-04-19 03:57:38.650267 IP  72.60.225.81.37224 > 173.212.236.74.22: tcp 0
//   2026-04-19 03:57:38.933551 IP  10.0.0.1.443 > 10.0.0.2.54321: UDP, length 50
//   2026-04-19 03:57:39.189364 IP6 2001:db8::1.443 > 2001:db8::2.54321: tcp 120
//
// Groups: 1=timestamp 2=ip6flag 3=src_addr 4=src_port 5=dst_addr 6=dst_port 7=proto_rest
var packetLine = regexp.MustCompile(
	`^(\S+ \S+) IP(6)?\s+([^ ]+?)\.(\d+|\w+(?:-\w+)*) > ([^ ]+?)\.(\d+|\w+(?:-\w+)*): (.+)$`,
)

// sizePattern pulls a byte count from tcpdump's tail. Handles both
// "tcp 123" (TCP quiet format) and "UDP, length 123" (UDP quiet format).
var sizePattern = regexp.MustCompile(`(?:tcp |length )(\d+)`)

// aggregator folds packet lines into ObservedFlow records keyed by
// (proto, direction, remote_addr, remote_port, local_port).
type aggregator struct {
	localAddrs   map[string]bool
	byKey        map[string]*ObservedFlow
	totalPackets int64
	totalBytes   int64
}

func newAggregator(localAddrs map[string]bool) *aggregator {
	return &aggregator{
		localAddrs: localAddrs,
		byKey:      map[string]*ObservedFlow{},
	}
}

func (a *aggregator) consume(line string) {
	m := packetLine.FindStringSubmatch(line)
	if len(m) != 8 {
		return
	}
	tsRaw, src, srcPortStr, dst, dstPortStr, rest := m[1], m[3], m[4], m[5], m[6], m[7]

	srcPort, srcPortOK := atoiMaybeService(srcPortStr)
	dstPort, dstPortOK := atoiMaybeService(dstPortStr)
	if !srcPortOK || !dstPortOK {
		return
	}

	proto := "tcp"
	if strings.HasPrefix(rest, "UDP") || strings.Contains(rest, " UDP") {
		proto = "udp"
	} else if !strings.HasPrefix(rest, "tcp") {
		// ICMP, ARP, etc. — skip. Zero trust is about TCP/UDP destinations.
		return
	}

	size := int64(0)
	if sm := sizePattern.FindStringSubmatch(rest); len(sm) == 2 {
		if n, err := strconv.ParseInt(sm[1], 10, 64); err == nil {
			size = n
		}
	}

	direction := inferDirection(src, dst, a.localAddrs)

	// Canonicalize the flow so outbound from us to X:443 aggregates with
	// the reply inbound from X:443 to us — the relationship is the same
	// destination, viewed from either side.
	var remoteAddr, localPort, remotePort = dst, srcPort, dstPort
	switch direction {
	case "inbound":
		remoteAddr = src
		localPort = dstPort
		remotePort = srcPort
	case "outbound", "internal", "loopback":
		remoteAddr = dst
		localPort = srcPort
		remotePort = dstPort
	}

	key := fmt.Sprintf("%s|%s|%s|%d|%d", proto, direction, remoteAddr, remotePort, localPort)
	tsNow := parseTcpdumpTime(tsRaw)

	f, ok := a.byKey[key]
	if !ok {
		f = &ObservedFlow{
			Proto:      proto,
			Direction:  direction,
			RemoteAddr: remoteAddr,
			RemotePort: remotePort,
			LocalPort:  localPort,
			FirstSeen:  tsNow,
		}
		a.byKey[key] = f
	}
	f.PacketCount++
	f.ByteCount += size
	f.LastSeen = tsNow

	a.totalPackets++
	a.totalBytes += size
}

func (a *aggregator) flows() []ObservedFlow {
	out := make([]ObservedFlow, 0, len(a.byKey))
	for _, f := range a.byKey {
		out = append(out, *f)
	}
	return out
}

// atoiMaybeService handles tcpdump's occasional service-name output
// (e.g., "https" instead of 443) even though we passed -n. The -n flag
// is not 100% reliable on older iproute2. When a name slips through we
// drop the packet rather than try to resolve it — the flow aggregation
// still holds because these are rare.
func atoiMaybeService(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}

// parseTcpdumpTime turns "2026-04-19 03:57:38.650267" into RFC3339 UTC.
// On parse failure returns the raw string unchanged so we don't lose data.
func parseTcpdumpTime(s string) string {
	t, err := time.Parse("2006-01-02 15:04:05.000000", s)
	if err != nil {
		return s
	}
	return t.UTC().Format(time.RFC3339)
}
