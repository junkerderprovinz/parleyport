package group

import (
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/junkerderprovinz/parleyport/kit/lan"
)

// nearby is addr cut to scheme, host and port when it may be dialed: a
// private IPv4 address or the loopback on a port of the group, so whoever
// names an address cannot point this instance at a host or a service of
// their choosing.
func (g *Group) nearby(addr string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(addr))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return "", false
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil {
		return "", false
	}
	ip = ip.Unmap()
	if !lan.PrivateIPv4(ip) && !ip.IsLoopback() {
		return "", false
	}
	port := portOf(u)
	if !slices.Contains(g.ports, port) {
		own, err := url.Parse(g.directURL())
		if err != nil || own.Host == "" || portOf(own) != port {
			return "", false
		}
	}
	return u.Scheme + "://" + net.JoinHostPort(ip.String(), port), true
}

func portOf(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "http" {
		return "80"
	}
	return "443"
}

func portNames(ports []int) []string {
	out := make([]string, len(ports))
	for i, p := range ports {
		out[i] = strconv.Itoa(p)
	}
	return out
}
