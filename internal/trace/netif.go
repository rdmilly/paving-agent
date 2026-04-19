package trace

import (
	"net"
	"strings"
)

// LocalAddrs returns every non-loopback IP address bound to any interface
// on this host. Used by the direction inference: a packet whose src IP is
// one of ours is outbound, a packet whose dst IP is one of ours is inbound.
//
// Loopback addresses (127.x, ::1) are excluded here because they are
// handled as a distinct "loopback" direction elsewhere — container-to-
// container traffic on a Docker host legitimately loops via 127.x, and
// conflating that with outbound would pollute the policy.
func LocalAddrs() (map[string]bool, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	addrs := make(map[string]bool)
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		ips, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range ips {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			addrs[ip.String()] = true
		}
	}
	return addrs, nil
}

// isLoopback reports whether addr is a loopback IP (v4 127.x or v6 ::1).
func isLoopback(addr string) bool {
	if strings.HasPrefix(addr, "127.") {
		return true
	}
	if addr == "::1" {
		return true
	}
	ip := net.ParseIP(addr)
	return ip != nil && ip.IsLoopback()
}

// isPrivate reports whether addr is in an RFC1918 or RFC4193 private
// range. Used to split "internal" (overlay / LAN) from "outbound" (public).
func isPrivate(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	return ip.IsPrivate()
}

// inferDirection classifies a single packet given the two endpoints and
// the set of IPs that belong to this host. See ObservedFlow.Direction for
// the taxonomy.
func inferDirection(srcAddr, dstAddr string, localAddrs map[string]bool) string {
	srcLocal := localAddrs[srcAddr]
	dstLocal := localAddrs[dstAddr]

	switch {
	case isLoopback(srcAddr) && isLoopback(dstAddr):
		return "loopback"
	case srcLocal && dstLocal:
		// Same host, both our IPs — treat as loopback-equivalent.
		return "loopback"
	case srcLocal && isPrivate(dstAddr):
		return "internal"
	case srcLocal:
		return "outbound"
	case dstLocal && isPrivate(srcAddr):
		return "internal"
	case dstLocal:
		return "inbound"
	default:
		// Neither endpoint is "us" — most likely a bridged container
		// packet the kernel let us see. Classify by private-ness.
		if isPrivate(srcAddr) || isPrivate(dstAddr) {
			return "internal"
		}
		return "outbound"
	}
}
