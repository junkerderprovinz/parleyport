package lan

import (
	"crypto/tls"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"
)

func TestPrivateIPv4(t *testing.T) {
	for addr, want := range map[string]bool{
		"10.0.0.1":     true,
		"172.16.0.1":   true,
		"172.31.255.1": true,
		"172.32.0.1":   false,
		"192.168.1.1":  true,
		"192.169.1.1":  false,
		"8.8.8.8":      false,
		"127.0.0.1":    false,
		"fd00::1":      false,
	} {
		if got := PrivateIPv4(netip.MustParseAddr(addr)); got != want {
			t.Errorf("PrivateIPv4(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestNeighboursSweepTheOwnNetworkOnEveryPort(t *testing.T) {
	s := New(Config{Ports: []int{3443}})
	got := s.Neighbours("https://192.168.1.10:8443")
	if len(got) != 2*254-1 {
		t.Fatalf("%d candidates, want every other host on both ports and this host on the other port", len(got))
	}
	for _, want := range []string{"https://192.168.1.1:3443", "https://192.168.1.1:8443", "https://192.168.1.254:8443", "https://192.168.1.10:3443"} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %s", want)
		}
	}
	if slices.Contains(got, "https://192.168.1.10:8443") {
		t.Error("the sweep calls this instance itself")
	}
}

func TestNeighboursUseTheSchemesDefaultPort(t *testing.T) {
	got := New(Config{}).Neighbours("http://10.1.2.3")
	if len(got) != 253 || !slices.Contains(got, "http://10.1.2.1:80") || slices.Contains(got, "http://10.1.2.3:80") {
		t.Errorf("got %d candidates: %v", len(got), got[:3])
	}
}

func TestNoSweepOutsideAPrivateNetwork(t *testing.T) {
	s := New(Config{Ports: []int{3443}})
	for _, own := range []string{"", "https://8.8.8.8:3443", "https://backup.example.org", "https://[fd00::1]:3443", "::"} {
		if got := s.Neighbours(own); len(got) != 0 {
			t.Errorf("Neighbours(%q) = %d candidates, want none", own, len(got))
		}
	}
}

func TestAddressOfARequest(t *testing.T) {
	cases := []struct {
		name, host, proto string
		tls               bool
		want              string
	}{
		{"plain", "192.168.1.10:8080", "", false, "http://192.168.1.10:8080"},
		{"tls", "tower.lan:3443", "", true, "https://tower.lan:3443"},
		{"behind a proxy", "backup.example.org", "https, http", false, "https://backup.example.org"},
		{"unknown proto", "tower.lan", "gopher", false, "http://tower.lan"},
		{"localhost", "localhost:3443", "", true, ""},
		{"loopback", "127.0.0.1:3443", "", true, ""},
		{"ipv6 loopback", "[::1]:3443", "", true, ""},
		{"link-local", "169.254.3.4", "", false, ""},
		{"empty", "", "", false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.Host = c.host
			if c.proto != "" {
				r.Header.Set("X-Forwarded-Proto", c.proto)
			}
			if c.tls {
				r.TLS = &tls.ConnectionState{}
			} else {
				r.TLS = nil
			}
			if got := AddressOf(r); got != c.want {
				t.Errorf("AddressOf = %q, want %q", got, c.want)
			}
		})
	}
}
