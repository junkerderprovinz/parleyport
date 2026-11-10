package group

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/lan"
)

// seenOnTheNetwork opens alpha the way a desktop app runs, without a listener,
// and lets it call bravo once at the address bravo announces. With onBravosPort
// alpha's group takes direct calls on bravo's port, which makes that address
// one to keep.
func seenOnTheNetwork(t *testing.T, onBravosPort bool) (a, b *node, ports []int) {
	t.Helper()
	b = open(t, "bravo", setup{})
	if onBravosPort {
		ports = []int{testPort(t, b.srv.URL)}
	}
	la := lan.New(lan.Config{})
	t.Cleanup(func() { _ = la.Close() })
	a = open(t, "alpha", setup{lan: la, noListener: true, ports: ports})
	la.Observe(tagged(a.g, lan.Peer{ID: b.id, Name: "bravo", URL: b.srv.URL}))
	_, _, _ = call(t, a, b, http.MethodGet, "/api/whoami", nil)
	if m, _ := memberOf(a.g, b.id); m.State != StatePending {
		t.Fatalf("alpha lists %+v, want bravo pinned", m)
	}
	// The first answer pins bravo only after its address was noted, so the
	// second is the one that keeps it.
	_, _, _ = call(t, a, b, http.MethodGet, "/api/whoami", nil)
	if err := a.g.Close(); err != nil {
		t.Fatal(err)
	}
	return a, b, ports
}

func TestAnInstanceWithoutAListenerFindsAMemberWhereItLastAnswered(t *testing.T) {
	a, b, ports := seenOnTheNetwork(t, true)
	a.g = openGroup(t, a, setup{noListener: true, store: a.store, ports: ports})
	waitFor(t, "alpha to find bravo again where it last answered", func() bool { m, _ := memberOf(a.g, b.id); return m.Direct })
	if err := a.g.Approve(b.id); err != nil {
		t.Fatal(err)
	}
	_, _, _ = call(t, a, b, http.MethodGet, "/api/whoami", nil)
	if err := b.g.Approve(a.id); err != nil {
		t.Fatal(err)
	}
	if id := whoami(t, a, b); id != a.id {
		t.Errorf("after a restart bravo's app saw %q, want alpha", id)
	}
}

func TestOnlyANearbyAddressIsKeptForAMember(t *testing.T) {
	a, b, _ := seenOnTheNetwork(t, false)
	if bytes.Contains(a.store.data, []byte(b.srv.URL)) {
		t.Error("alpha kept an address off the group's ports, which the next start would dial")
	}
}

func TestAStoredAddressOffTheGroupPortsIsNotDialed(t *testing.T) {
	a, b, _ := seenOnTheNetwork(t, true)
	if !bytes.Contains(a.store.data, []byte(b.srv.URL)) {
		t.Fatal("alpha did not keep where bravo answered on a port of the group")
	}
	a.g = openGroup(t, a, setup{noListener: true, store: a.store})
	a.g.mu.Lock()
	kept := a.g.addrs[b.id]
	a.g.mu.Unlock()
	if kept != nil {
		t.Errorf("alpha dials %s, where bravo answered on a port the group no longer has", kept.url)
	}
}
