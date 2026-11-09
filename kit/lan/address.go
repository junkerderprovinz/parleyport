package lan

import (
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// PrivateIPv4 reports whether ip is in 10/8, 172.16/12 or 192.168/16. A sweep
// never leaves these, so an own address outside them yields no neighbours.
func PrivateIPv4(ip netip.Addr) bool {
	return ip.Is4() && ip.IsPrivate()
}

// LocalIPv4 is the first IPv4 address on a local interface that is neither
// loopback nor link-local, since a 169.254 address is what a network card
// gives itself when DHCP fails and nothing else can reach it.
func LocalIPv4() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() || ipnet.IP.IsLinkLocalUnicast() {
			continue
		}
		if ip4 := ipnet.IP.To4(); ip4 != nil {
			return ip4.String()
		}
	}
	return ""
}

// AddressOf is the scheme, host and port a browser used to reach r, as its
// address bar shows them, or "" when the host only means this machine to
// itself. It is meant for requests of a signed-in user: from inside a
// container nothing else can tell the address the host is reached at.
func AddressOf(r *http.Request) string {
	host := strings.TrimSpace(r.Host)
	if host == "" || isLocalHost(host) {
		return ""
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if fp := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); fp != "" {
		fp, _, _ = strings.Cut(fp, ",")
		if fp = strings.TrimSpace(fp); fp == "http" || fp == "https" {
			scheme = fp
		}
	}
	return scheme + "://" + host
}

func isLocalHost(host string) bool {
	h := host
	if hh, _, err := net.SplitHostPort(host); err == nil {
		h = hh
	}
	h = strings.Trim(h, "[]")
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(h)
	return err == nil && (ip.IsLoopback() || ip.IsLinkLocalUnicast())
}

// Neighbours lists every other host of own's /24 on own's port and on every
// port of the Config, with own's scheme, or nothing when own is not a private
// IPv4 address. Sweeping a public network, or one the instance only reaches
// through a reverse proxy, is what a sweep must never do, so an address that
// does not plainly name the own network gives no guess.
func (s *Service) Neighbours(own string) []string {
	u, err := url.Parse(own)
	if err != nil || u.Hostname() == "" {
		return nil
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || !PrivateIPv4(ip) {
		return nil
	}
	scheme := u.Scheme
	if scheme != "http" {
		scheme = "https"
	}
	ownPort := u.Port()
	if ownPort == "" {
		ownPort = map[string]string{"http": "80", "https": "443"}[scheme]
	}
	ports := []string{ownPort}
	for _, p := range s.cfg.Ports {
		if p := strconv.Itoa(p); p != ownPort {
			ports = append(ports, p)
		}
	}
	base := ip.As4()
	out := make([]string, 0, 254*len(ports))
	for host := 1; host <= 254; host++ {
		addr := netip.AddrFrom4([4]byte{base[0], base[1], base[2], byte(host)}).String()
		for _, port := range ports {
			// A second instance on this same machine listens on another port.
			if byte(host) == base[3] && port == ownPort {
				continue
			}
			out = append(out, scheme+"://"+addr+":"+port)
		}
	}
	return out
}
