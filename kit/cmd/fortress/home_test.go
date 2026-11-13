package main

import (
	"context"
	"crypto/sha256"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/fortress"
	"github.com/junkerderprovinz/parleyport/kit/group"
	"github.com/junkerderprovinz/parleyport/kit/lan"
	"github.com/junkerderprovinz/parleyport/kit/member"
	"github.com/junkerderprovinz/parleyport/kit/phrase"
)

// testNetwork points the fortress's announces at a group of the test's own,
// or skips the test on a host that cannot join one.
func testNetwork(t *testing.T) {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := c.LocalAddr().(*net.UDPAddr).AddrPort().Port()
	_ = c.Close()
	addr := netip.AddrPortFrom(netip.MustParseAddr("239.255.77.251"), port)
	m, err := net.ListenMulticastUDP("udp4", nil, net.UDPAddrFromAddrPort(addr))
	if err != nil {
		t.Skipf("this host cannot join a multicast group: %v", err)
	}
	_ = m.Close()
	was := fortress.Multicast
	fortress.Multicast = addr
	t.Cleanup(func() { fortress.Multicast = was })
}

// openHomeApp opens alpha-1 without a relay, answering direct calls on this
// network, and records who ran files.drop.
func openHomeApp(t *testing.T) *app {
	t.Helper()
	seed := sha256.Sum256([]byte("alpha-1"))
	id, err := member.FromSeed(member.KindInstance, seed[:])
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	l := lan.New(lan.Config{Group: fortress.Multicast})
	l.Start()
	t.Cleanup(func() { _ = l.Close() })
	a := &app{id: id.ID(), store: &memStore{}}
	f, err := fortress.Open(fortress.Config{
		App: fortress.App{ID: "alpha", Name: "Alpha", Version: "2.0.0"}, Secret: secret, Identity: id,
		Self:  group.Self{Name: "tower", Deployment: "container", DirectURL: srv.URL},
		Relay: group.RelayOff, LAN: l, Store: a.store,
		Actions: []fortress.Action{{Name: "files.drop", Run: func(_ context.Context, from fortress.Caller, body []byte) ([]byte, error) {
			a.mu.Lock()
			defer a.mu.Unlock()
			a.drops = append(a.drops, from.App+":"+string(body))
			return []byte(`{"ok":true}`), nil
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	mux.Handle(group.DirectPath, f.DirectHandler())
	a.f = f
	return a
}

func TestAPluginWithoutARelayActsOnAMemberOnThisNetwork(t *testing.T) {
	testNetwork(t)
	a := openHomeApp(t)
	dir := t.TempDir()
	words, err := phrase.Encode(secret)
	if err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := cli(t, words+"\n", "join", "-dir", dir, "-app", "watcher", "-name", "tower", "-relay", "off", "-lan", "-uses", "files.drop"); code != 0 {
		t.Fatalf("join: %d %s", code, stderr)
	}
	code, out, stderr := cli(t, "", "act", "-dir", dir, "-wait", "8s", "alpha", "files.drop", `"report.pdf"`)
	if code != 0 || strings.TrimSpace(out) != `{"ok":true}` {
		t.Fatalf("act: %d %q %s", code, out, stderr)
	}
	if got := a.dropped(); !slices.Equal(got, []string{`watcher:"report.pdf"`}) {
		t.Errorf("the app ran %v", got)
	}
}
