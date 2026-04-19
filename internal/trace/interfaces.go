package trace

import (
	"fmt"
	"net"
)

// localAddressSet is a fast-lookup bag of IP strings. We build it once
// from net.InterfaceAddrs() at the start of a capture and consult it
// for every parsed packet to decide inbound vs outbound.
type localAddressSet map[string]struct{}

// has reports whether addr is one of this node's own IPs.
func (s localAddressSet) has(addr string) bool {
	_, ok := s[addr]
	return ok
}

// gatherLocalAddresses returns every IP the kernel considers assigned to
// this host, as a set of strings suitable for tcpdump-output comparison.
// Both IPv4 and IPv6 are included. The loopback addresses 127.0.0.1 and
// ::1 are intentionally kept — they're real for direction inference even
// though most callers will want to filter loopback flows out later.
func gatherLocalAddresses() (localAddressSet, []string, error) {
	set := localAddressSet{}
	var flat []string

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, nil, fmt.Errorf("enumerating interface addresses: %w", err)
	}

	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		default:
			continue
		}
		if ip == nil || ip.IsUnspecified() {
			continue
		}
		s := ip.String()
		if _, exists := set[s]; exists {
			continue
		}
		set[s] = struct{}{}
		flat = append(flat, s)
	}
	return set, flat, nil
}
