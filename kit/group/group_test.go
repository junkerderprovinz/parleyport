package group

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/keys"
	"github.com/junkerderprovinz/parleyport/kit/lan"
	"github.com/junkerderprovinz/parleyport/kit/member"
	"github.com/junkerderprovinz/parleyport/kit/relay"
)

func TestOpenRefusesAnIncompleteConfig(t *testing.T) {
	phone, err := member.NewIdentity(member.KindMobile)
	if err != nil {
		t.Fatal(err)
	}
	good := func() Config {
		return Config{Domain: testDomain, Secret: testSecret, Identity: identity(t, "alpha"), Store: &memStore{}, Relay: RelayOff}
	}
	for name, change := range map[string]func(*Config){
		"no domain":      func(c *Config) { c.Domain = "" },
		"no secret":      func(c *Config) { c.Secret = nil },
		"half the keys":  func(c *Config) { c.Secret, c.Keys = nil, keys.Set{Group: testDomain.GroupKey(testSecret)} },
		"no identity":    func(c *Config) { c.Identity = member.Identity{} },
		"a phone":        func(c *Config) { c.Identity = phone },
		"no store":       func(c *Config) { c.Store = nil },
		"unknown relay":  func(c *Config) { c.Relay = "elsewhere" },
		"own relay, bad": func(c *Config) { c.Relay, c.RelayURL = RelayOwn, "ftp://relay" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := good()
			change(&cfg)
			if g, err := Open(cfg, appRoutes()); err == nil {
				_ = g.Close()
				t.Fatal("Open took it")
			}
		})
	}
	g, err := Open(good(), appRoutes())
	if err != nil {
		t.Fatalf("a complete config: %v", err)
	}
	_ = g.Close()
}

func TestADamagedStoreIsAnError(t *testing.T) {
	cfg := Config{Domain: testDomain, Secret: testSecret, Identity: identity(t, "alpha"), Relay: RelayOff,
		Store: &memStore{data: []byte("{not json")}}
	if g, err := Open(cfg, appRoutes()); err == nil {
		_ = g.Close()
		t.Fatal("Open started over on a store it could not read, which forgets every removal")
	}
}

// multicast skips a test on a host that cannot join a multicast group.
func multicast(t *testing.T) {
	t.Helper()
	c, err := net.ListenMulticastUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(239, 255, 77, 251), Port: int(freePort(t))})
	if err != nil {
		t.Skipf("this host cannot join a multicast group: %v", err)
	}
	_ = c.Close()
}

func TestTwoInstancesOnOneNetworkFindEachOther(t *testing.T) {
	multicast(t)
	port := freePort(t)
	la, lb := lanService(t, port), lanService(t, port)
	la.Start()
	lb.Start()
	a := open(t, "alpha", setup{lan: la})
	b := open(t, "bravo", setup{lan: lb})

	waitFor(t, "both to see each other on the network", func() bool {
		ma, okA := memberOf(a.g, b.id)
		mb, okB := memberOf(b.g, a.id)
		return okA && okB && ma.Direct && mb.Direct
	})
	got, _ := memberOf(a.g, b.id)
	if got.Name != "bravo" || got.Relay || got.Kind != member.KindInstance || got.Deployment != "container" {
		t.Errorf("alpha lists %+v, want bravo on the network only", got)
	}

	meet(t, a, b)
	if id := whoami(t, a, b); id != a.id {
		t.Errorf("bravo's app saw caller %q, want alpha", id)
	}
	if id := whoami(t, b, a); id != b.id {
		t.Errorf("alpha's app saw caller %q, want bravo", id)
	}
}

func TestInstancesMeetOverTheRelay(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", setup{relay: url})
	b := open(t, "bravo", setup{relay: url})

	waitFor(t, "both on the relay", func() bool {
		_, okA := memberOf(a.g, b.id)
		_, okB := memberOf(b.g, a.id)
		return okA && okB && a.g.RelayConnected()
	})
	got, _ := memberOf(a.g, b.id)
	if !got.Relay || got.Direct || got.Name != "bravo" {
		t.Errorf("alpha lists %+v, want bravo on the relay only", got)
	}
	meet(t, a, b)
	if id := whoami(t, a, b); id != a.id {
		t.Errorf("bravo's app saw caller %q, want alpha", id)
	}
}

func TestACallFallsBackToTheRelay(t *testing.T) {
	url := relayServer(t)
	la := lan.New(lan.Config{})
	t.Cleanup(func() { _ = la.Close() })
	a := open(t, "alpha", setup{relay: url, lan: la})
	b := open(t, "bravo", setup{relay: url})
	waitFor(t, "alpha to see bravo on the relay", func() bool { _, ok := memberOf(a.g, b.id); return ok })
	meet(t, a, b)

	// bravo announces an address on alpha's network that nothing answers on.
	dead := httpDeadAddress(t)
	la.Observe(tagged(a.g, lan.Peer{ID: b.id, Name: "bravo", URL: dead}))
	if m, _ := memberOf(a.g, b.id); !m.Direct {
		t.Fatalf("alpha lists %+v, want bravo on the network before the first call", m)
	}

	if id := whoami(t, a, b); id != a.id {
		t.Errorf("bravo's app saw caller %q, want alpha", id)
	}
	if m, _ := memberOf(a.g, b.id); m.Direct || !m.Relay {
		t.Errorf("alpha lists %+v after the direct call failed, want bravo on the relay only", m)
	}
}

func TestACallToNobodyFails(t *testing.T) {
	a := open(t, "alpha", setup{})
	_, _, err := a.g.Call(context.Background(), identity(t, "nobody").ID(), http.MethodGet, "/api/whoami", nil)
	if !errors.Is(err, ErrUnreachable) {
		t.Errorf("err = %v, want ErrUnreachable", err)
	}
}

func TestACallTooLargeIsRefusedBeforeItLeaves(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", setup{relay: url})
	b := open(t, "bravo", setup{relay: url})
	waitFor(t, "alpha to see bravo", func() bool { _, ok := memberOf(a.g, b.id); return ok })
	_, _, err := call(t, a, b, http.MethodPost, "/api/echo", make([]byte, MaxCallBytes+1))
	if err == nil {
		t.Fatal("a call over MaxCallBytes went out")
	}
}

func TestTheAppsAnswerTravelsBack(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", setup{relay: url})
	b := open(t, "bravo", setup{relay: url})
	waitFor(t, "alpha to see bravo", func() bool { _, ok := memberOf(a.g, b.id); return ok })
	meet(t, a, b)

	status, body, err := call(t, a, b, http.MethodPost, "/api/echo", []byte(`{"x":1}`))
	if err != nil || status != http.StatusOK || string(body) != `{"x":1}` {
		t.Errorf("echo = %d %q %v", status, body, err)
	}
	status, _, err = call(t, a, b, http.MethodGet, "/api/missing", nil)
	if err != nil || status != http.StatusNotFound {
		t.Errorf("a missing route = %d %v, want the app's 404", status, err)
	}
	status, _, err = call(t, a, b, http.MethodGet, "/api/panic", nil)
	if err != nil || status != http.StatusInternalServerError {
		t.Errorf("a panicking route = %d %v, want 500", status, err)
	}
	status, body, err = call(t, a, b, http.MethodGet, "/api/big", nil)
	if err != nil || status != http.StatusInternalServerError || !strings.Contains(string(body), "answerTooLarge") {
		t.Errorf("an answer too large for the relay = %d %.80q %v, want a refusal", status, body, err)
	}
	status, _, err = call(t, a, b, http.MethodGet, "//elsewhere/api/whoami", nil)
	if err != nil || status != http.StatusBadRequest {
		t.Errorf("a path naming a host = %d %v, want 400", status, err)
	}
}

func TestAnAnswerFromAMemberNotApprovedHereDoesNotCount(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", setup{relay: url})
	b := open(t, "bravo", setup{relay: url})
	waitFor(t, "alpha to see bravo", func() bool { _, ok := memberOf(a.g, b.id); return ok })
	_, _, _ = call(t, a, b, http.MethodGet, "/api/whoami", nil)
	if err := b.g.Approve(a.id); err != nil {
		t.Fatal(err)
	}

	// bravo serves alpha now, but alpha never approved bravo.
	_, _, err := call(t, a, b, http.MethodGet, "/api/whoami", nil)
	var untrusted *relay.UntrustedAnswer
	if !errors.As(err, &untrusted) || untrusted.Status != http.StatusOK {
		t.Errorf("err = %v, want an UntrustedAnswer carrying bravo's 200", err)
	}
}

func TestAGroupOpensOnItsKeysAlone(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", setup{relay: url})
	b := open(t, "bravo", setup{relay: url, keysOnly: true})
	waitFor(t, "both on the relay", func() bool {
		_, okA := memberOf(a.g, b.id)
		_, okB := memberOf(b.g, a.id)
		return okA && okB
	})
	meet(t, a, b)
	if id := whoami(t, b, a); id != b.id {
		t.Errorf("alpha's app saw caller %q, want bravo", id)
	}
}
