package lan

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// idOf is an id of the shape members go by, made from name.
func idOf(name string) string {
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:20])
}

// testConfig is a multicast group no app uses, on a port free right now, so
// tests neither meet real instances nor each other.
func testConfig(t *testing.T) Config {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := c.LocalAddr().(*net.UDPAddr).AddrPort().Port()
	_ = c.Close()
	return Config{Group: netip.AddrPortFrom(netip.MustParseAddr("239.255.77.250"), port)}
}

// tagged is a membership check for tests: an announce counts when its tag is
// "ok".
func tagged(p Peer) bool { return p.Tag == "ok" }

func sign(Peer) string { return "ok" }

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func started(t *testing.T, s *Service) {
	t.Helper()
	s.Start()
	t.Cleanup(func() { _ = s.Close() })
	if !s.listening() {
		t.Skip("this host cannot join a multicast group")
	}
}

func TestTwoMembersOnOneNetworkFindEachOther(t *testing.T) {
	cfg := testConfig(t)
	a, b := New(cfg), New(cfg)
	a.SetAccept(tagged)
	b.SetAccept(tagged)
	a.SetSelf(Peer{ID: idOf("a"), Name: "Cellar", URL: "https://192.168.1.10:3443", Deployment: "container", Address: "https://cellar.example"}, sign)
	b.SetSelf(Peer{ID: idOf("b"), Name: "Attic", URL: "https://192.168.1.11:3443", Deployment: "desktop"}, sign)
	started(t, a)
	started(t, b)

	waitFor(t, "both to see each other", func() bool { return len(a.Members()) == 1 && len(b.Members()) == 1 })
	got := b.Members()[0]
	if got.ID != idOf("a") || got.Name != "Cellar" || got.URL != "https://192.168.1.10:3443" ||
		got.Deployment != "container" || got.Address != "https://cellar.example" {
		t.Errorf("b sees %+v, want a as it announced itself", got)
	}
	if len(a.Strangers()) != 0 || len(b.Strangers()) != 0 {
		t.Errorf("a member is listed as a stranger too: %+v, %+v", a.Strangers(), b.Strangers())
	}
}

func TestANewSelfGoesOutAtOnce(t *testing.T) {
	cfg := testConfig(t)
	a, b := New(cfg), New(cfg)
	b.SetAccept(tagged)
	b.SetSelf(Peer{ID: idOf("b"), URL: "https://192.168.1.11:3443"}, sign)
	started(t, a)
	started(t, b)

	// a started with nothing to announce, so only the change can reach b
	// before the next tick.
	a.SetSelf(Peer{ID: idOf("a"), Name: "Renamed", URL: "https://192.168.1.10:3443"}, sign)
	deadline := time.Now().Add(announceEvery / 2)
	for time.Now().Before(deadline) {
		if m := b.Members(); len(m) == 1 && m[0].Name == "Renamed" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("b still sees %+v, want the new announce well before the next tick", b.Members())
}

func TestAMemberNeverSeesItself(t *testing.T) {
	cfg := testConfig(t)
	s := New(cfg)
	s.SetAccept(tagged)
	s.SetSelf(Peer{ID: idOf("solo"), URL: "https://192.168.1.12:3443"}, sign)
	started(t, s)
	time.Sleep(500 * time.Millisecond)
	if len(s.Members()) != 0 || len(s.Strangers()) != 0 {
		t.Errorf("got %+v and %+v, want nothing: an instance is not its own peer", s.Members(), s.Strangers())
	}
}

func TestAnAnnounceWithoutTheTagIsAStranger(t *testing.T) {
	s := New(Config{})
	s.SetAccept(tagged)
	s.Observe(Peer{ID: idOf("x"), Name: "Next door", URL: "https://192.168.1.20:3443", Address: "https://next.example", Tag: "forged"})

	if len(s.Members()) != 0 {
		t.Fatalf("members = %+v, want none", s.Members())
	}
	got := s.Strangers()
	if len(got) != 1 || got[0].Name != "Next door" {
		t.Fatalf("strangers = %+v, want the announce", got)
	}
	if got[0].Address != "" {
		t.Errorf("a stranger keeps the address %q; only a member's is kept", got[0].Address)
	}
}

func TestAStrangerCannotTakeAMembersPlace(t *testing.T) {
	s := New(Config{})
	s.SetAccept(tagged)
	s.Observe(Peer{ID: idOf("m"), URL: "https://192.168.1.30:3443", Tag: "ok", Sent: 10})
	s.Observe(Peer{ID: idOf("m"), URL: "https://192.168.1.66:3443", Tag: "forged", Sent: 11})

	m := s.Members()
	if len(m) != 1 || m[0].URL != "https://192.168.1.30:3443" {
		t.Errorf("members = %+v, want the member at its own address", m)
	}
}

func TestAnOlderAnnounceDoesNotReplaceANewerOne(t *testing.T) {
	s := New(Config{})
	s.SetAccept(tagged)
	s.Observe(Peer{ID: idOf("m"), URL: "https://192.168.1.31:3443", Tag: "ok", Sent: 20})
	s.Observe(Peer{ID: idOf("m"), URL: "https://192.168.1.30:3443", Tag: "ok", Sent: 19})

	if m := s.Members(); len(m) != 1 || m[0].URL != "https://192.168.1.31:3443" {
		t.Errorf("members = %+v, want the newer address", m)
	}
}

func TestAnnouncesOfTheWrongShapeAreDropped(t *testing.T) {
	long := strings.Repeat("x", fieldLimit+1)
	for name, p := range map[string]Peer{
		"no url":         {ID: idOf("a")},
		"short id":       {ID: "abc", URL: "https://192.168.1.2:1"},
		"upper-case id":  {ID: strings.ToUpper(idOf("a")), URL: "https://192.168.1.2:1"},
		"long name":      {ID: idOf("a"), URL: "https://192.168.1.2:1", Name: long},
		"long url":       {ID: idOf("a"), URL: "https://" + long},
		"long tag":       {ID: idOf("a"), URL: "https://192.168.1.2:1", Tag: long},
		"long address":   {ID: idOf("a"), URL: "https://192.168.1.2:1", Address: long, Tag: "ok"},
		"long deploymnt": {ID: idOf("a"), URL: "https://192.168.1.2:1", Deployment: long},
	} {
		t.Run(name, func(t *testing.T) {
			s := New(Config{})
			s.SetAccept(tagged)
			s.Observe(p)
			if len(s.Members())+len(s.Strangers()) != 0 {
				t.Errorf("kept %+v / %+v", s.Members(), s.Strangers())
			}
		})
	}
}

func TestAPeerExpires(t *testing.T) {
	s := New(Config{})
	s.SetAccept(tagged)
	s.Observe(Peer{ID: idOf("gone"), URL: "https://192.168.1.40:3443", Tag: "ok"})
	s.Observe(Peer{ID: idOf("here"), URL: "https://192.168.1.41:3443", Tag: "ok"})
	s.mu.Lock()
	p := s.members[idOf("gone")]
	p.LastSeen = time.Now().Add(-peerTTL - time.Second)
	s.members[idOf("gone")] = p
	s.mu.Unlock()

	if m := s.Members(); len(m) != 1 || m[0].ID != idOf("here") {
		t.Errorf("members = %+v, want only the one still announcing", m)
	}
}

func TestTheListsStayBounded(t *testing.T) {
	s := New(Config{})
	s.SetAccept(tagged)
	for i := range maxPeers + 10 {
		s.Observe(Peer{ID: idOf(string(rune(i)) + "s"), URL: "https://192.168.1.2:1"})
		s.Observe(Peer{ID: idOf(string(rune(i)) + "m"), URL: "https://192.168.1.2:1", Tag: "ok"})
	}
	if len(s.Strangers()) != maxPeers || len(s.Members()) != maxPeers {
		t.Errorf("%d strangers and %d members, want %d of each", len(s.Strangers()), len(s.Members()), maxPeers)
	}
}

func TestANewMembershipCheckForgetsTheMembers(t *testing.T) {
	s := New(Config{})
	s.SetAccept(tagged)
	s.Observe(Peer{ID: idOf("m"), URL: "https://192.168.1.30:3443", Tag: "ok"})
	s.SetAccept(nil)
	if len(s.Members()) != 0 {
		t.Errorf("members = %+v after leaving, want none", s.Members())
	}
}

func TestMembersAreSortedByName(t *testing.T) {
	s := New(Config{})
	s.SetAccept(tagged)
	for _, n := range []string{"Cellar", "Attic", "Barn"} {
		s.Observe(Peer{ID: idOf(n), Name: n, URL: "https://192.168.1.2:1", Tag: "ok"})
	}
	var names []string
	for _, p := range s.Members() {
		names = append(names, p.Name)
	}
	if strings.Join(names, ",") != "Attic,Barn,Cellar" {
		t.Errorf("order = %v", names)
	}
}

func TestCloseWithoutStartReturns(t *testing.T) {
	s := New(Config{})
	done := make(chan struct{})
	go func() {
		_ = s.Close()
		_ = s.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close on a Service that never started did not return")
	}
	s.Start()
	if s.listening() {
		t.Error("Start after Close opened a socket nothing will close")
	}
}
