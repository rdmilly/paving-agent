package trace

import (
	"encoding/json"
	"io"
	"sort"
)

// WriteJSON serializes a ConnectionPolicy as indented JSON. Flows are
// sorted for stable output across runs — critical because this file is
// the baseline that subsequent traces diff against.
func WriteJSON(w io.Writer, p *ConnectionPolicy) error {
	sort.Slice(p.Flows, func(i, j int) bool {
		a, b := p.Flows[i], p.Flows[j]
		if a.Direction != b.Direction {
			return a.Direction < b.Direction
		}
		if a.RemoteAddr != b.RemoteAddr {
			return a.RemoteAddr < b.RemoteAddr
		}
		if a.RemotePort != b.RemotePort {
			return a.RemotePort < b.RemotePort
		}
		return a.LocalPort < b.LocalPort
	})
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(p)
}
