package scanner

import (
	"context"
	"encoding/json"
	"fmt"
)

// ipRouteRow matches `ip -j route`. Real iproute2 JSON has more fields
// (scope, prefsrc, metric, etc.) — we only keep what drives packet-trace
// selection.
type ipRouteRow struct {
	Dst     string `json:"dst"`     // "default" or CIDR like "10.0.0.0/24"
	Dev     string `json:"dev"`
	Gateway string `json:"gateway"`
}

// CollectRoutes captures the routing table, flagging the default route.
// The default route's interface is what the 60s packet trace (step 2)
// should bind to — this collector's output feeds that decision.
func CollectRoutes(ctx context.Context) ([]Route, []string) {
	if !binaryExists("ip") {
		return nil, []string{"routes: ip binary not found"}
	}

	out, err := runCmd(ctx, "ip", "-j", "route")
	if err != nil {
		return nil, []string{fmt.Sprintf("routes: %v", err)}
	}

	var rows []ipRouteRow
	if err := json.Unmarshal(out, &rows); err != nil {
		return nil, []string{fmt.Sprintf("routes: parse: %v", err)}
	}

	out2 := make([]Route, 0, len(rows))
	for _, r := range rows {
		out2 = append(out2, Route{
			Destination: r.Dst,
			Gateway:     r.Gateway,
			Interface:   r.Dev,
			IsDefault:   r.Dst == "default",
		})
	}
	return out2, nil
}
