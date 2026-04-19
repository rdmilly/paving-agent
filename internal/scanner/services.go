package scanner

import (
	"context"
	"fmt"
	"strings"
)

// CollectServices lists every systemd unit of type=service that is currently
// loaded. We keep failed units too — a service that failed five minutes
// ago is relevant context for Claude, not noise. State filtering happens
// in the classifier, not here.
//
// Fails soft: no systemd (containers, non-systemd distros) returns empty +
// a warning. Docker-based nodes often show this pattern.
func CollectServices(ctx context.Context) ([]Service, []string) {
	if !binaryExists("systemctl") {
		return nil, []string{"services: systemctl binary not found"}
	}

	// --plain drops the legend/footer. --no-pager prevents blocking.
	// --no-legend drops the column header. We ask for running AND failed.
	out, err := runCmd(ctx, "systemctl",
		"list-units",
		"--type=service",
		"--state=running,failed",
		"--no-pager",
		"--no-legend",
		"--plain",
	)
	if err != nil {
		return nil, []string{fmt.Sprintf("services: %v", err)}
	}

	var services []Service
	// Columns: UNIT LOAD ACTIVE SUB DESCRIPTION
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		desc := ""
		if len(fields) >= 5 {
			desc = strings.Join(fields[4:], " ")
		}
		services = append(services, Service{
			Name:        fields[0],
			LoadState:   fields[1],
			ActiveState: fields[2],
			SubState:    fields[3],
			Description: desc,
		})
	}
	return services, nil
}
