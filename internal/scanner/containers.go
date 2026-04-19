package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// dockerPsRow is the shape docker emits with --format '{{json .}}'.
// Fields we don't use are omitted; unknown fields are ignored by
// encoding/json so omitting them is safe across Docker versions.
type dockerPsRow struct {
	ID      string `json:"ID"`
	Names   string `json:"Names"` // Single string or comma-separated
	Image   string `json:"Image"`
	Status  string `json:"Status"`
	State   string `json:"State"`
	Ports   string `json:"Ports"`
	Network string `json:"Networks"`
	Labels  string `json:"Labels"` // "k1=v1,k2=v2" from docker
}

// CollectContainers returns all Docker containers in any state (running,
// exited, paused). A dead container whose anonymous volume is still
// referenced by docker-compose is topology-relevant even if State=exited.
//
// Fails soft: if docker isn't installed or the socket is inaccessible,
// returns nil + a warning. Many nodes (databases-only, minimal cloud
// images) will legitimately have no docker.
func CollectContainers(ctx context.Context) ([]Container, []string) {
	if !binaryExists("docker") {
		return nil, []string{"containers: docker binary not found"}
	}

	// --all to include stopped, --no-trunc for full IDs/labels,
	// --format json emits one JSON object per line.
	out, err := runCmd(ctx, "docker", "ps", "--all", "--no-trunc", "--format", "{{json .}}")
	if err != nil {
		return nil, []string{fmt.Sprintf("containers: %v", err)}
	}

	var containers []Container
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		var row dockerPsRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue // skip malformed row, don't fail whole collection
		}
		containers = append(containers, Container{
			ID:      row.ID,
			Names:   splitAndTrim(row.Names, ","),
			Image:   row.Image,
			Status:  row.Status,
			State:   row.State,
			Ports:   splitAndTrim(row.Ports, ","),
			Network: row.Network,
			Labels:  parseLabelsKV(row.Labels),
		})
	}
	return containers, nil
}

func splitAndTrim(s, sep string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseLabelsKV turns "k1=v1,k2=v2" into a map. Malformed entries without
// an '=' are skipped silently.
func parseLabelsKV(s string) map[string]string {
	if s == "" {
		return nil
	}
	out := map[string]string{}
	for _, pair := range strings.Split(s, ",") {
		eq := strings.Index(pair, "=")
		if eq <= 0 {
			continue
		}
		out[strings.TrimSpace(pair[:eq])] = strings.TrimSpace(pair[eq+1:])
	}
	return out
}
