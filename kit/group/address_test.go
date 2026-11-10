package group

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strconv"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/lan"
)

func TestProbeSaysWhoAnswersAtAnAddress(t *testing.T) {
	b := open(t, "bravo", setup{})
	c := open(t, "charlie", setup{secret: []byte("another phrase..")})
	dead := httpDeadAddress(t)
	a := open(t, "alpha", setup{noListener: true, ports: []int{testPort(t, b.srv.URL), testPort(t, c.srv.URL), testPort(t, dead)}})
	ctx := context.Background()

	m, err := a.g.Probe(ctx, b.srv.URL+"/some/page")
	if err != nil || m.ID != b.id || m.Name != "bravo" || !m.Direct || m.State != StatePending || !bytes.Equal(m.Key, identity(t, "bravo").Public()) {
		t.Errorf("probing bravo = %+v %v, want bravo on the network, waiting for approval here", m, err)
	}
	for _, c := range []struct {
		name, addr string
		want       error
	}{
		{"nobody", dead, ErrUnreachable},
		{"another group", c.srv.URL, ErrStranger},
		{"a public address", "http://203.0.113.7:" + strconv.Itoa(testPort(t, b.srv.URL)), ErrNotNearby},
		{"a name", "http://localhost:" + strconv.Itoa(testPort(t, b.srv.URL)), ErrNotNearby},
		{"another port", "http://127.0.0.1:1", ErrNotNearby},
	} {
		if _, err := a.g.Probe(ctx, c.addr); !errors.Is(err, c.want) {
			t.Errorf("probing %s = %v, want %v", c.name, err, c.want)
		}
	}
	self := open(t, "delta", setup{})
	if _, err := self.g.Probe(ctx, self.srv.URL); !errors.Is(err, ErrSelf) {
		t.Errorf("probing itself = %v, want ErrSelf", err)
	}
}

func TestAnInstanceWithoutAListenerPairsByAddress(t *testing.T) {
	b := open(t, "bravo", setup{})
	a := open(t, "alpha", setup{noListener: true, ports: []int{testPort(t, b.srv.URL)}})
	if _, err := a.g.Probe(context.Background(), b.srv.URL); err != nil {
		t.Fatal(err)
	}
	if err := a.g.Approve(b.id); err != nil {
		t.Fatalf("alpha approves bravo, which only answered a probe: %v", err)
	}
	_, _, _ = call(t, a, b, http.MethodGet, "/api/whoami", nil)
	if err := b.g.Approve(a.id); err != nil {
		t.Fatal(err)
	}
	if id := whoami(t, a, b); id != a.id {
		t.Errorf("bravo's app saw %q, want alpha", id)
	}

	if err := a.g.Close(); err != nil {
		t.Fatal(err)
	}
	a.g = openGroup(t, a, setup{noListener: true, store: a.store, ports: []int{testPort(t, b.srv.URL)}})
	waitFor(t, "alpha to find bravo again where it last answered", func() bool { m, _ := memberOf(a.g, b.id); return m.Direct })
	if id := whoami(t, a, b); id != a.id {
		t.Errorf("after a restart bravo's app saw %q, want alpha", id)
	}
}

func TestOnlyANearbyAddressIsKeptForAMember(t *testing.T) {
	la := lan.New(lan.Config{})
	t.Cleanup(func() { _ = la.Close() })
	a := open(t, "alpha", setup{lan: la, noListener: true})
	b := open(t, "bravo", setup{})
	la.Observe(tagged(a.g, lan.Peer{ID: b.id, Name: "bravo", URL: b.srv.URL}))
	_, _, _ = call(t, a, b, http.MethodGet, "/api/whoami", nil)
	if m, _ := memberOf(a.g, b.id); m.State != StatePending {
		t.Fatalf("alpha lists %+v, want bravo pinned", m)
	}
	if err := a.g.Close(); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(a.store.data, []byte(b.srv.URL)) {
		t.Error("alpha kept an address off the group's ports, which the next start would dial")
	}
}

func TestKnownAddressesAreKeptAndProbed(t *testing.T) {
	b := open(t, "bravo", setup{})
	ports := []int{testPort(t, b.srv.URL)}
	a := open(t, "alpha", setup{noListener: true, ports: ports})
	if err := a.g.SetAddresses([]string{b.srv.URL + "/"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "alpha to probe bravo's address", func() bool { m, _ := memberOf(a.g, b.id); return m.Direct && m.State == StatePending })
	if got := a.g.Addresses(); len(got) != 1 || got[0] != b.srv.URL {
		t.Errorf("addresses = %v, want bravo's", got)
	}
	if err := a.g.SetAddresses([]string{b.srv.URL, "http://203.0.113.7:80"}); !errors.Is(err, ErrNotNearby) {
		t.Errorf("setting a public address = %v, want ErrNotNearby", err)
	}
	if got := a.g.Addresses(); len(got) != 1 {
		t.Errorf("addresses = %v after a refused change, want them as they were", got)
	}

	if err := a.g.Close(); err != nil {
		t.Fatal(err)
	}
	a.g = openGroup(t, a, setup{noListener: true, store: a.store, ports: ports})
	if got := a.g.Addresses(); len(got) != 1 || got[0] != b.srv.URL {
		t.Errorf("addresses after a restart = %v, want bravo's", got)
	}
}
