package trace

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// tcpdumpPath is the binary path. Override in tests if needed.
var tcpdumpPath = "tcpdump"

// runTCPDump starts tcpdump bound to iface, running until ctx is cancelled.
// Stdout is returned as a line-buffered reader. The caller is responsible
// for consuming until EOF and reaping the process.
//
// Flags: -i iface, -n (no DNS), -q (quick/short output), -l (line buffered),
// -p (no promiscuous mode — polite on shared NICs), -tttt (ISO-ish timestamps),
// -B 4096 (4MB kernel buffer — small headroom for bursty traffic).
func runTCPDump(ctx context.Context, iface string) (*exec.Cmd, io.ReadCloser, error) {
	cmd := exec.CommandContext(ctx, tcpdumpPath,
		"-i", iface,
		"-n",
		"-q",
		"-l",
		"-p",
		"-tttt",
		"-B", "4096",
	)

	// Cancel by SIGTERM so tcpdump flushes stats cleanly to stderr before dying.
	cmd.Cancel = func() error {
		return cmd.Process.Signal(syscall.SIGTERM)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("tcpdump stdout: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("starting tcpdump: %w", err)
	}
	return cmd, stdout, nil
}

// tcpdumpLine matches one -q -tttt -n line. Example shapes:
//
//	2026-04-18 23:55:01.123456 IP 10.0.0.2.52341 > 1.2.3.4.443: tcp 48
//	2026-04-18 23:55:01.123456 IP 1.2.3.4.53 > 10.0.0.2.39487: UDP, length 48
//	2026-04-18 23:55:01.123456 IP6 2001:db8::1.443 > 2001:db8::2.54321: tcp 0
//
// IPv6 addresses are also dot-port-separated by tcpdump — the colons in the
// address are unambiguous because ports are always the final .N after the
// last address character.
var tcpdumpLine = regexp.MustCompile(
	`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) IP6? (\S+?)\.(\d+) > (\S+?)\.(\d+): (tcp|UDP|udp)(?:,? length)? (\d+)`,
)

// parsedPacket is what one tcpdump line reduces to.
type parsedPacket struct {
	Timestamp  time.Time
	SrcAddr    string
	SrcPort    int
	DstAddr    string
	DstPort    int
	Protocol   string // "tcp" or "udp"
	ByteLength int64
}

// parseLine extracts a parsedPacket from one tcpdump output line. Returns
// ok=false on non-packet lines (headers, summaries, malformed) — parser
// caller should just skip those, never fail.
func parseLine(line string) (parsedPacket, bool) {
	m := tcpdumpLine.FindStringSubmatch(line)
	if m == nil {
		return parsedPacket{}, false
	}

	ts, err := time.Parse("2006-01-02 15:04:05.000000", m[1])
	if err != nil {
		return parsedPacket{}, false
	}
	srcPort, err := strconv.Atoi(m[3])
	if err != nil {
		return parsedPacket{}, false
	}
	dstPort, err := strconv.Atoi(m[5])
	if err != nil {
		return parsedPacket{}, false
	}
	length, err := strconv.ParseInt(m[7], 10, 64)
	if err != nil {
		return parsedPacket{}, false
	}

	return parsedPacket{
		Timestamp:  ts,
		SrcAddr:    m[2],
		SrcPort:    srcPort,
		DstAddr:    m[4],
		DstPort:    dstPort,
		Protocol:   strings.ToLower(m[6]),
		ByteLength: length,
	}, true
}

// consumeLines reads tcpdump output line by line, emitting parsedPackets
// on the out channel. Closes out when the reader hits EOF. Non-matching
// lines are silently discarded (header, summary, malformed).
func consumeLines(r io.Reader, out chan<- parsedPacket) {
	defer close(out)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)
	for scanner.Scan() {
		if p, ok := parseLine(scanner.Text()); ok {
			out <- p
		}
	}
}
