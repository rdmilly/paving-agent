package scanner

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// procPattern extracts pid and process name from ss's "process" column.
// Example: users:(("nginx",pid=1234,fd=6),("nginx",pid=1235,fd=6))
var procPattern = regexp.MustCompile(`"([^"]+)",pid=(\d+)`)

// CollectPorts returns every TCP socket in LISTEN state and the process
// that owns it. Uses `ss -tlnp` because `netstat -lntp` is deprecated on
// modern distros and often absent on minimal cloud images.
//
// Requires CAP_NET_ADMIN or root to see the process column. Without it,
// ss still lists the sockets but without pid/process info — we log a
// warning and keep going.
func CollectPorts(ctx context.Context) ([]Port, []string) {
	var warnings []string

	if !binaryExists("ss") {
		return nil, []string{"ports: ss binary not found"}
	}

	out, err := runCmd(ctx, "ss", "-tlnpH")
	if err != nil {
		return nil, []string{fmt.Sprintf("ports: %v", err)}
	}

	// ss -H emits one row per line, space-separated. We don't use -J
	// because its schema has shifted across iproute2 versions; the columnar
	// format is stable back to at least iproute2 4.x.
	//
	// Columns: State Recv-Q Send-Q LocalAddress:Port PeerAddress:Port Process
	var ports []Port
	seenProcWarning := false

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		local := fields[3]
		addr, port, ok := splitHostPort(local)
		if !ok {
			continue
		}

		proto := "tcp"
		if strings.Contains(local, "[") {
			proto = "tcp6"
		}

		p := Port{Addr: addr, Port: port, Proto: proto}

		if len(fields) >= 6 {
			procField := strings.Join(fields[5:], " ")
			if m := procPattern.FindStringSubmatch(procField); len(m) == 3 {
				p.Process = m[1]
				if pid, err := strconv.Atoi(m[2]); err == nil {
					p.PID = pid
				}
			}
		} else if !seenProcWarning {
			warnings = append(warnings, "ports: no process info (need CAP_NET_ADMIN or root)")
			seenProcWarning = true
		}

		ports = append(ports, p)
	}
	return ports, warnings
}

// splitHostPort handles both IPv4 (0.0.0.0:80) and IPv6 ([::]:80) forms
// as emitted by ss. Returns addr, port, ok.
func splitHostPort(s string) (string, int, bool) {
	// IPv6: [addr]:port
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end == -1 || end+1 >= len(s) || s[end+1] != ':' {
			return "", 0, false
		}
		addr := s[1:end]
		port, err := strconv.Atoi(s[end+2:])
		if err != nil {
			return "", 0, false
		}
		return addr, port, true
	}

	// IPv4: addr:port
	idx := strings.LastIndex(s, ":")
	if idx == -1 {
		return "", 0, false
	}
	port, err := strconv.Atoi(s[idx+1:])
	if err != nil {
		return "", 0, false
	}
	return s[:idx], port, true
}
