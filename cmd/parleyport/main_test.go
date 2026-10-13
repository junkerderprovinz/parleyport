package main

import (
	"bytes"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/junkerderprovinz/parleyport/internal/buildinfo"
)

func TestVersionFlagPrintsVersionAndCommit(t *testing.T) {
	defer func(v, c string) { buildinfo.Version, buildinfo.Commit = v, c }(buildinfo.Version, buildinfo.Commit)
	buildinfo.Version, buildinfo.Commit = "v1.2.3", "0123abcd"

	var out, errOut bytes.Buffer
	versionOnly, err := parseArgs([]string{"-version"}, &out, &errOut)
	if err != nil || !versionOnly {
		t.Fatalf("parseArgs(-version) = %v, %v; want true, nil", versionOnly, err)
	}
	if got := strings.TrimSpace(out.String()); got != "parleyport v1.2.3 (commit 0123abcd)" {
		t.Fatalf("printed %q", got)
	}
}

func TestNoArgumentsStartsTheRelay(t *testing.T) {
	var out, errOut bytes.Buffer
	versionOnly, err := parseArgs(nil, &out, &errOut)
	if err != nil || versionOnly {
		t.Fatalf("parseArgs() = %v, %v; want false, nil", versionOnly, err)
	}
	if out.Len() > 0 {
		t.Fatalf("printed %q", out.String())
	}
}

func TestUnknownFlagOrArgumentIsRefused(t *testing.T) {
	for _, args := range [][]string{{"-verison"}, {"--port", "80"}, {"serve"}} {
		var out, errOut bytes.Buffer
		if _, err := parseArgs(args, &out, &errOut); err == nil {
			t.Errorf("parseArgs(%q) accepted it", args)
		}
		if !strings.Contains(errOut.String(), "-version") {
			t.Errorf("parseArgs(%q) printed no usage: %q", args, errOut.String())
		}
	}
}

func TestSettingPrefersTheNewNameAndFallsBackToTheOldOne(t *testing.T) {
	t.Setenv("KL_RELAY_DOMAIN", "relay.example.org")
	if got := setting("DOMAIN", ""); got != "relay.example.org" {
		t.Fatalf("with only KL_RELAY_DOMAIN set, got %q", got)
	}
	t.Setenv("PARLEYPORT_DOMAIN", "parley.example.org")
	if got := setting("DOMAIN", ""); got != "parley.example.org" {
		t.Fatalf("with both set, got %q", got)
	}
	if got := setting("CERT_DIR", "/fallback"); got != "/fallback" {
		t.Fatalf("with neither set, got %q", got)
	}
}

func TestTrustedProxiesReadsAddressesAndRanges(t *testing.T) {
	got, err := trustedProxies(" 172.17.0.1, 10.10.0.0/28 ,::1")
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("172.17.0.1/32"),
		netip.MustParsePrefix("10.10.0.0/28"),
		netip.MustParsePrefix("::1/128"),
	}
	if !slices.Equal(got, want) {
		t.Errorf("trustedProxies = %v, want %v", got, want)
	}
	if got, _ := trustedProxies("none"); got != nil {
		t.Errorf(`trustedProxies("none") = %v, want none`, got)
	}
	unset, _ := trustedProxies("")
	for _, addr := range []string{"127.0.0.1", "::1"} {
		if !slices.ContainsFunc(unset, func(p netip.Prefix) bool { return p.Contains(netip.MustParseAddr(addr)) }) {
			t.Errorf("unset does not trust %s on the relay's own host", addr)
		}
	}
	for _, addr := range []string{"10.0.0.7", "172.17.0.2", "192.168.1.20", "fd00::7"} {
		if slices.ContainsFunc(unset, func(p netip.Prefix) bool { return p.Contains(netip.MustParseAddr(addr)) }) {
			t.Errorf("unset trusts %s, so any machine on that network picks the address the throttle counts", addr)
		}
	}
	if _, err := trustedProxies("proxy.lan"); err == nil {
		t.Error("a host name was taken for a trusted proxy")
	}
}

// TestATrustedRangeHoldsProxiesNotVisitors: anybody inside a trusted range
// names their own bucket in X-Forwarded-For, so a range as wide as a network
// of callers keeps the relay from starting.
func TestATrustedRangeHoldsProxiesNotVisitors(t *testing.T) {
	for _, c := range []struct {
		entry string
		ok    bool
	}{
		{"10.10.0.0/28", true},
		{"10.10.0.0/27", false},
		{"192.168.1.0/24", false},
		{"172.17.0.0/16", false},
		{"10.0.0.0/8", false},
		{"0.0.0.0/0", false},
		{"192.168.1.10/32", true},
		{"2001:db8:1::/124", true},
		{"2001:db8:1::/123", false},
		{"2001:db8:1::/48", false},
		{"::/0", false},
		{"::ffff:10.10.0.0/124", true},
		{"::ffff:10.10.0.0/120", false},
		{"192.0.2.10", true},
		{"2001:db8::1", true},
	} {
		_, err := trustedProxies(c.entry)
		if c.ok && err != nil {
			t.Errorf("%s was refused: %v", c.entry, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s was taken for a trusted range", c.entry)
		}
	}
	got, err := trustedProxies("::ffff:10.10.0.0/124")
	if err != nil || len(got) != 1 || !got[0].Contains(netip.MustParseAddr("10.10.0.5")) {
		t.Errorf("an IPv4 range in IPv6 form reads as %v (%v), want it to hold 10.10.0.5", got, err)
	}
}

func TestTheRelayGoesByItsPublicAddressAndItsDomains(t *testing.T) {
	got, err := relayNames(" https://Relay.Example.com/relay/connect, wss://old.example.com:8443 ", []string{"relay.example.org"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"relay.example.com", "old.example.com", "relay.example.org"}; !slices.Equal(got, want) {
		t.Errorf("relayNames = %v, want %v", got, want)
	}
	if got, _ := relayNames("", nil); len(got) != 0 {
		t.Errorf("with nothing set the relay goes by %v, want the Host header", got)
	}
	if _, err := relayNames("https://", nil); err == nil {
		t.Error("an address without a host was taken")
	}
}
