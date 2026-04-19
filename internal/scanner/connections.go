package scanner

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// CollectConnections returns established (ESTAB) TCP connections. This is
// the ground-truth edge set for the service graph: who actually talks to
// whom right now. The 60s packet trace (step 2) adds volume + ephemerals,
// but ESTAB alone catches long-lived service→service connections that
// the trace might miss during its window.
//
// Loopback (127.0.0.0/8 and ::1) connections are kept — they represent
// service-to-service calls within a Docker host and matter for topology.
func CollectConnections(ctx context.Context) ([]Connection, []string) {
	if !binaryExists("ss") {
		return nil, []string{"connections: ss binary not found"}
	}

	out, err := runCmd(ctx, "ss", "-tnpH", "state", "established")
	if err != nil {
		return nil, []string{fmt.Sprintf("connections: %v", err)}
	}

	var conns []Connection
	seenProcWarning := false
	var warnings []string

	// Columns without -H header: Recv-Q Send-Q LocalAddress:Port PeerAddress:Port Process
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		local, peer := fields[2], fields[3]
		lAddr, lPort, ok1 := splitHostPort(local)
		rAddr, rPort, ok2 := splitHostPort(peer)
		if !ok1 || !ok2 {
			continue
		}

		c := Connection{
			LocalAddr:  lAddr,
			LocalPort:  lPort,
			RemoteAddr: rAddr,
			RemotePort: rPort,
			State:      "ESTAB",
		}

		if len(fields) >= 5 {
			procField := strings.Join(fields[4:], " ")
			if m := procPattern.FindStringSubmatch(procField); len(m) == 3 {
				c.Process = m[1]
				if pid, err := strconv.Atoi(m[2]); err == nil {
					c.PID = pid
				}
			}
		} else if !seenProcWarning {
			warnings = append(warnings, "connections: no process info (need CAP_NET_ADMIN or root)")
			seenProcWarning = true
		}

		conns = append(conns, c)
	}
	return conns, warnings
}
