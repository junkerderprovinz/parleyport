package fortress

import (
	"net/http"
	"net/netip"
	"slices"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/group"
	"github.com/junkerderprovinz/parleyport/kit/keys"
	"github.com/junkerderprovinz/parleyport/kit/lan"
)

func TestOpenRefusesAnIncompleteConfig(t *testing.T) {
	good := func() Config {
		return config(t, &node{name: "alpha-1", app: "alpha", store: &memStore{}, pairStore: &memStore{}}, setup{})
	}
	noop := good().Actions[0].Run
	for name, change := range map[string]func(*Config){
		"no app":                 func(c *Config) { c.App.ID = "" },
		"an app id with a slash": func(c *Config) { c.App.ID = "alpha/beta" },
		"the fortress's domain":  func(c *Config) { c.App.ID = string(Domain) },
		"no secret":              func(c *Config) { c.Secret = nil },
		"no store":               func(c *Config) { c.Store = nil },
		"an action without name": func(c *Config) { c.Actions = []Action{{Run: noop}} },
		"an action named badly":  func(c *Config) { c.Actions = []Action{{Name: "Drop Files", Run: noop}} },
		"an action twice":        func(c *Config) { c.Actions = append(c.Actions, c.Actions[0]) },
		"an action that no-one runs": func(c *Config) {
			c.Actions = []Action{{Name: "files.drop"}}
		},
		"a use named badly":       func(c *Config) { c.Uses = []string{"run"} },
		"a pairing with no store": func(c *Config) { c.Pairing.Store = nil },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := good()
			change(&cfg)
			if f, err := Open(cfg); err == nil {
				_ = f.Close()
				t.Fatal("Open took it")
			}
		})
	}
	f, err := Open(good())
	if err != nil {
		t.Fatalf("a complete config: %v", err)
	}
	_ = f.Close()
}

func TestMembersOfTwoAppsSeeEachOther(t *testing.T) {
	n := inRelay(t, "alpha", "alpha-1", "bravo", "bravo-1")
	a, b := n[0], n[1]
	meet(t, a, b)

	got, _ := memberOf(a.f, b.id)
	want := App{ID: "bravo", Name: "App bravo", Version: "1.0.0"}
	if got.App != want || got.Device != "bravo-1" || got.Deployment != "container" || !got.Relay ||
		got.State != group.StateApproved || !slices.Equal(got.Actions, []string{"files.drop"}) {
		t.Errorf("alpha lists %+v, want bravo-1 of %+v on the relay", got, want)
	}
	if _, paired := pairedWith(a.f.Pairing(), b.id); paired {
		t.Error("alpha's own pairing lists an instance of another app")
	}
}

func TestAMemberWaitsForApproval(t *testing.T) {
	n := inRelay(t, "alpha", "alpha-1", "bravo", "bravo-1")
	a, b := n[0], n[1]
	waitFor(t, "bravo to wait at alpha", func() bool { m, _ := memberOf(a.f, b.id); return m.State == group.StatePending })

	if _, err := b.f.Status(ctx(t), a.id, ""); err == nil {
		t.Error("bravo read alpha's status before anybody approved it")
	}
	if _, err := b.f.Act(ctx(t), a.id, "files.drop", []byte(`"x"`)); err == nil || len(a.drops()) > 0 {
		t.Errorf("bravo acted at alpha before anybody approved it: %v %v", err, a.drops())
	}
}

func TestJoiningPairsTheInstancesOfOneApp(t *testing.T) {
	n := inRelay(t, "alpha", "alpha-1", "alpha", "alpha-2")
	a, b := n[0], n[1]
	meet(t, a, b)

	waitFor(t, "the pairing to follow the fortress", func() bool {
		ma, _ := pairedWith(a.f.Pairing(), b.id)
		mb, _ := pairedWith(b.f.Pairing(), a.id)
		return ma.State == group.StateApproved && mb.State == group.StateApproved
	})
	status, body, err := a.f.Pairing().Call(ctx(t), b.id, http.MethodGet, "/api/whoami", nil)
	if err != nil || status != http.StatusOK || string(body) != a.id {
		t.Errorf("alpha-1 calls its sibling: %d %s %v", status, body, err)
	}
}

func TestThePairingDerivesItsKeysUnderTheAppsDomain(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	// An instance outside any fortress that was given the same phrase for the
	// app alone meets alpha-1 in the pairing, not in the fortress.
	plain, err := group.Open(group.Config{
		Domain: keys.Domain("alpha"), Secret: testSecret, Identity: identity(t, "alpha-9"),
		Self: group.Self{Name: "alpha-9"}, Relay: group.RelayOwn, RelayURL: url, Store: &memStore{},
	}, appRoutes())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = plain.Close() })
	waitFor(t, "alpha-1 to see alpha-9 in the pairing", func() bool {
		_, ok := pairedWith(a.f.Pairing(), identity(t, "alpha-9").ID())
		return ok
	})
	if _, ok := memberOf(a.f, identity(t, "alpha-9").ID()); ok {
		t.Error("an instance that only paired its app shows up in the fortress")
	}
	if keys.Domain("alpha").GroupKey(testSecret) == Domain.GroupKey(testSecret) {
		t.Error("the fortress and the app share a group key")
	}
}

func TestDirectCallsReachTheFortressAndThePairing(t *testing.T) {
	multicast(t)
	fortressPort, pairPort := freePort(t), freePort(t)
	service := func(port uint16) *lan.Service {
		s := lan.New(lan.Config{Group: netip.AddrPortFrom(netip.MustParseAddr("239.255.77.251"), port)})
		s.Start()
		t.Cleanup(func() { _ = s.Close() })
		return s
	}
	a := open(t, "alpha", "alpha-1", setup{lan: service(fortressPort), pairLAN: service(pairPort)})
	b := open(t, "alpha", "alpha-2", setup{lan: service(fortressPort), pairLAN: service(pairPort)})
	waitFor(t, "both to see each other on the network", func() bool {
		for _, pair := range [][2]*node{{a, b}, {b, a}} {
			m, _ := memberOf(pair[0].f, pair[1].id)
			p, _ := pairedWith(pair[0].f.Pairing(), pair[1].id)
			if !m.Direct || !p.Direct {
				return false
			}
		}
		return true
	})
	meet(t, a, b)
	waitFor(t, "the pairing to follow the fortress", func() bool {
		pa, _ := pairedWith(a.f.Pairing(), b.id)
		pb, _ := pairedWith(b.f.Pairing(), a.id)
		return pa.State == group.StateApproved && pb.State == group.StateApproved
	})
	if _, err := a.f.Status(ctx(t), b.id, "en"); err != nil {
		t.Errorf("a direct fortress call: %v", err)
	}
	if status, body, err := a.f.Pairing().Call(ctx(t), b.id, http.MethodGet, "/api/whoami", nil); err != nil || string(body) != a.id {
		t.Errorf("a direct pairing call: %d %s %v", status, body, err)
	}
}

func TestTheFortressRemembersAcrossARestart(t *testing.T) {
	n := inRelay(t, "alpha", "alpha-1", "bravo", "bravo-1")
	a, b := n[0], n[1]
	meet(t, a, b)
	if err := a.f.SetPermission("bravo", "alpha", "files.drop", false); err != nil {
		t.Fatal(err)
	}
	if err := a.f.Close(); err != nil {
		t.Fatal(err)
	}
	a.f = reopen(t, a, setup{})
	m, _ := memberOf(a.f, b.id)
	if m.App.ID != "bravo" || m.State != group.StateApproved || m.Online() {
		t.Errorf("alpha lists %+v after a restart, want bravo approved and away", m)
	}
	if on(a.f.Permissions(), "bravo", "alpha", "files.drop") {
		t.Error("the switched off permission is on again after a restart")
	}
}

func TestANewPhraseStartsTheFortressOver(t *testing.T) {
	n := inRelay(t, "alpha", "alpha-1", "bravo", "bravo-1")
	a, b := n[0], n[1]
	meet(t, a, b)
	if err := a.f.SetPermission("bravo", "alpha", "files.drop", false); err != nil {
		t.Fatal(err)
	}
	if err := a.f.Close(); err != nil {
		t.Fatal(err)
	}
	a.f = reopen(t, a, setup{secret: []byte("another phrase..")})
	if _, ok := memberOf(a.f, b.id); ok {
		t.Error("alpha still lists bravo under a phrase bravo never entered")
	}
	if len(a.f.permissionList()) != 0 {
		t.Error("alpha kept the permissions of the fortress it left")
	}
}
