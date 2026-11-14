package group

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/lan"
	"github.com/junkerderprovinz/parleyport/kit/member"
)

var movedSecret = []byte("the fortress one")

func TestAMemberCarriedOverToANewPhraseIsMetAgainOnlyOnceItSigns(t *testing.T) {
	url := relayServer(t)
	a, b := open(t, "alpha", setup{relay: url}), open(t, "bravo", setup{relay: url})
	waitFor(t, "alpha to see bravo", func() bool { m, _ := memberOf(a.g, b.id); return m.Relay })
	meet(t, a, b)
	if m, _ := memberOf(a.g, b.id); m.Met.IsZero() {
		t.Error("alpha never met bravo, which called it")
	}

	for _, n := range []*node{a, b} {
		if err := n.g.Close(); err != nil {
			t.Fatal(err)
		}
	}
	a.g = openGroup(t, a, setup{relay: url, store: a.store, secret: movedSecret, previous: testSecret})
	if m, _ := memberOf(a.g, b.id); m.State != StateApproved || !m.Met.IsZero() {
		t.Errorf("alpha lists bravo as %q, met %v, before bravo moved", m.State, m.Met)
	}

	b.g = openGroup(t, b, setup{relay: url, store: b.store, secret: movedSecret, previous: testSecret})
	waitFor(t, "alpha to see bravo under the new phrase", func() bool { m, _ := memberOf(a.g, b.id); return m.Relay })
	whoami(t, b, a)
	met, _ := memberOf(a.g, b.id)
	if met.Met.IsZero() {
		t.Fatal("alpha has not met bravo, which called it under the new phrase")
	}
	if m, _ := memberOf(b.g, a.id); m.Met.IsZero() {
		t.Error("bravo has not met alpha, which answered it under the new phrase")
	}

	if err := a.g.Close(); err != nil {
		t.Fatal(err)
	}
	a.g = openGroup(t, a, setup{store: a.store, secret: movedSecret})
	if m, _ := memberOf(a.g, b.id); !m.Met.Equal(met.Met) {
		t.Errorf("after a restart alpha met bravo at %v, want %v", m.Met, met.Met)
	}
}

func TestOneDirectRouteServesTheOldAndTheNewGroupOfAnApp(t *testing.T) {
	// alpha keeps its group on the old phrase open next to the one it moved
	// to; both go by the same domain, so their calls carry the same headers.
	var uploaded atomic.Int64
	took := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			w.WriteHeader(http.StatusConflict)
			return
		}
		uploaded.Store(n)
	})
	var route atomic.Pointer[http.Handler]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		(*route.Load()).ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	before := &node{name: "alpha", id: identity(t, "alpha").ID(), srv: srv, store: &memStore{}}
	after := &node{name: "alpha", id: before.id, srv: srv, store: &memStore{}}
	before.g = openGroup(t, before, setup{byPhrase: true, upload: took})
	after.g = openGroup(t, after, setup{byPhrase: true, secret: movedSecret})
	h := Direct(after.g, before.g)
	route.Store(&h)

	lb, lc := lan.New(lan.Config{}), lan.New(lan.Config{})
	t.Cleanup(func() { _ = lb.Close(); _ = lc.Close() })
	b := open(t, "bravo", setup{lan: lb, byPhrase: true})
	c := open(t, "charlie", setup{lan: lc, byPhrase: true, secret: movedSecret})
	alpha := lan.Peer{ID: before.id, Name: "alpha", URL: srv.URL, Deployment: "container"}
	lb.Observe(tagged(b.g, alpha))
	lc.Observe(tagged(c.g, alpha))

	if id := whoami(t, b, before); id != b.id {
		t.Errorf("the old group saw %q, want bravo", id)
	}
	if id := whoami(t, c, after); id != c.id {
		t.Errorf("the new group saw %q, want charlie", id)
	}
	if _, ok := memberOf(before.g, b.id); !ok {
		t.Error("bravo's call did not reach the group on the old phrase")
	}
	if _, ok := memberOf(after.g, b.id); ok {
		t.Error("bravo, on the old phrase, reached the new group")
	}
	if _, ok := memberOf(before.g, c.id); ok {
		t.Error("charlie, on the new phrase, reached the old group")
	}

	data := bytes.Repeat([]byte("x"), 300<<10)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if status, _, err := b.g.Upload(ctx, before.id, "/restore", bytes.NewReader(data), int64(len(data))); err != nil || status != http.StatusOK || uploaded.Load() != int64(len(data)) {
		t.Errorf("an upload to the old group = %d %v, took %d bytes", status, err, uploaded.Load())
	}
}

func TestADirectRouteOverSeveralGroupsRefusesAStranger(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	before := &node{name: "alpha", id: identity(t, "alpha").ID(), srv: srv, store: &memStore{}}
	after := &node{name: "alpha", id: before.id, srv: srv, store: &memStore{}}
	before.g = openGroup(t, before, setup{byPhrase: true})
	after.g = openGroup(t, after, setup{byPhrase: true, secret: movedSecret})

	eve := &node{name: "eve", id: identity(t, "eve").ID(), srv: srv, store: &memStore{}}
	eve.g = openGroup(t, eve, setup{byPhrase: true, secret: []byte("another phrase..")})
	req, body := direct(t, eve, before, "/api/whoami")
	r := httptest.NewRequest(req.Method, DirectPath, bytes.NewReader(body))
	r.Header = req.Header.Clone()
	w := httptest.NewRecorder()
	Direct(after.g, before.g).ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("a call under another phrase = %d %s, want 403", w.Code, w.Body)
	}
}

func TestAnInstanceVouchedForIsLetInOnItsFirstCall(t *testing.T) {
	url := relayServer(t)
	vouchFor := func(who member.Identity) func(string, ed25519.PublicKey) bool {
		return func(id string, key ed25519.PublicKey) bool { return id == who.ID() && bytes.Equal(key, who.Public()) }
	}
	a := open(t, "alpha", setup{relay: url, vouch: vouchFor(identity(t, "bravo"))})
	b := open(t, "bravo", setup{relay: url, vouch: vouchFor(identity(t, "alpha"))})
	c := open(t, "charlie", setup{relay: url})
	waitFor(t, "bravo and charlie to see alpha", func() bool {
		mb, _ := memberOf(b.g, a.id)
		mc, _ := memberOf(c.g, a.id)
		return mb.Relay && mc.Relay
	})

	if status, body, err := call(t, b, a, http.MethodGet, "/api/whoami", nil); err != nil || status != http.StatusOK {
		t.Errorf("bravo's first call = %d %s %v, want it served", status, body, err)
	}
	if m, _ := memberOf(a.g, b.id); m.State != StateApproved {
		t.Errorf("alpha lists bravo as %q", m.State)
	}
	_, _, _ = call(t, c, a, http.MethodGet, "/api/whoami", nil)
	if m, _ := memberOf(a.g, c.id); m.State != StatePending {
		t.Errorf("alpha lists charlie, whom nobody vouched for, as %q, want pending", m.State)
	}

	if err := a.g.Remove(b.id); err != nil {
		t.Fatal(err)
	}
	if status, _, _ := call(t, b, a, http.MethodGet, "/api/whoami", nil); status == http.StatusOK {
		t.Error("bravo, taken out, is served because it is vouched for")
	}
	if m, ok := memberOf(a.g, b.id); ok {
		t.Errorf("alpha lists bravo, taken out, as %q", m.State)
	}
}

func TestAnAnswerFromAnInstanceVouchedForCounts(t *testing.T) {
	url := relayServer(t)
	bravo := identity(t, "bravo")
	a := open(t, "alpha", setup{relay: url, vouch: func(id string, key ed25519.PublicKey) bool {
		return id == bravo.ID() && bytes.Equal(key, bravo.Public())
	}})
	b := open(t, "bravo", setup{relay: url, byPhrase: true})
	waitFor(t, "alpha to see bravo", func() bool { m, _ := memberOf(a.g, b.id); return m.Relay })
	if status, body, err := call(t, a, b, http.MethodGet, "/api/whoami", nil); err != nil || status != http.StatusOK {
		t.Errorf("alpha calls bravo = %d %s %v, want its answer to count", status, body, err)
	}
}

func TestAGroupKeepsWhenItWasRetiredUntilItMovesOn(t *testing.T) {
	a := open(t, "alpha", setup{})
	first := a.g.Retire()
	if first.IsZero() || time.Since(first) > time.Minute {
		t.Fatalf("retired at %v", first)
	}
	if again := a.g.Retire(); !again.Equal(first) {
		t.Errorf("retired again at %v, want %v", again, first)
	}

	if err := a.g.Close(); err != nil {
		t.Fatal(err)
	}
	a.g = openGroup(t, a, setup{store: a.store})
	if after := a.g.Retire(); !after.Equal(first) {
		t.Errorf("after a restart retired at %v, want %v", after, first)
	}

	if err := a.g.Close(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	a.g = openGroup(t, a, setup{store: a.store, secret: movedSecret, previous: testSecret})
	if moved := a.g.Retire(); !moved.After(first) {
		t.Errorf("the group on the new phrase was retired at %v, as the one it moved from", moved)
	}
}

func TestAGroupForTheVouchedAloneShowsAStrangerNothing(t *testing.T) {
	url := relayServer(t)
	bravo := identity(t, "bravo")
	a := open(t, "alpha", setup{relay: url, vouchedOnly: true, vouch: func(id string, key ed25519.PublicKey) bool {
		return id == bravo.ID() && bytes.Equal(key, bravo.Public())
	}})
	b := open(t, "bravo", setup{relay: url, byPhrase: true})
	waitFor(t, "bravo to see alpha", func() bool { m, _ := memberOf(b.g, a.id); return m.Relay })

	if status, body, err := call(t, b, a, http.MethodGet, "/api/whoami", nil); err != nil || status != http.StatusOK {
		t.Errorf("bravo, vouched for, calls alpha = %d %s %v, want it served", status, body, err)
	}
	if m, ok := memberOf(b.g, a.id); !ok || !m.Relay {
		t.Errorf("bravo lists alpha as %+v, want it reachable", m)
	}
	// Bravo passes on whom it knows, alpha too, which is not alpha showing
	// itself, so charlie meets alpha alone.
	if err := b.g.Close(); err != nil {
		t.Fatal(err)
	}
	c := open(t, "charlie", setup{relay: url, byPhrase: true})
	var status int
	var body []byte
	waitFor(t, "alpha to answer charlie", func() bool {
		status, body, _ = call(t, c, a, http.MethodGet, "/api/whoami", nil)
		return status != 0
	})
	if status != http.StatusForbidden || !bytes.Contains(body, []byte(`"groupClosed"`)) {
		t.Errorf("charlie, a stranger, calls alpha = %d %s, want 403 groupClosed", status, body)
	}
	if m, _ := memberOf(a.g, c.id); m.State != StateUnknown {
		t.Errorf("alpha lists charlie as %q, want its key not pinned", m.State)
	}
	waitFor(t, "charlie to list alpha no more", func() bool { _, ok := memberOf(c.g, a.id); return !ok })
	if err := c.g.Close(); err != nil {
		t.Fatal(err)
	}
	if raw, _ := c.store.Load(); bytes.Contains(raw, []byte(a.id)) {
		t.Errorf("charlie keeps alpha in its store: %s", raw)
	}
}

func TestAGroupClosedToNewcomersServesOnlyWhoItMetBefore(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", setup{relay: url, byPhrase: true})
	b := open(t, "bravo", setup{relay: url, byPhrase: true})
	waitFor(t, "bravo to see alpha", func() bool { m, _ := memberOf(b.g, a.id); return m.Relay })
	if status, _, err := call(t, b, a, http.MethodGet, "/api/whoami", nil); err != nil || status != http.StatusOK {
		t.Fatalf("bravo calls alpha = %d %v", status, err)
	}
	since := time.Now()
	c := open(t, "charlie", setup{relay: url, byPhrase: true})
	waitFor(t, "charlie to see alpha", func() bool { m, _ := memberOf(c.g, a.id); return m.Relay })
	if status, _, err := call(t, c, a, http.MethodGet, "/api/whoami", nil); err != nil || status != http.StatusOK {
		t.Fatalf("charlie calls alpha before it closes = %d %v", status, err)
	}

	a.g.CloseToNew(since)
	d := open(t, "delta", setup{relay: url, byPhrase: true})
	waitFor(t, "alpha to answer delta", func() bool { status, _, _ := call(t, d, a, http.MethodGet, "/api/whoami", nil); return status != 0 })
	for _, n := range []*node{c, d} {
		status, body, _ := call(t, n, a, http.MethodGet, "/api/whoami", nil)
		if status != http.StatusForbidden || !bytes.Contains(body, []byte(`"groupClosed"`)) {
			t.Errorf("%s, met after alpha closed, calls it = %d %s, want 403 groupClosed", n.name, status, body)
		}
	}
	if status, _, err := call(t, b, a, http.MethodGet, "/api/whoami", nil); err != nil || status != http.StatusOK {
		t.Errorf("bravo, met before, calls alpha = %d %v, want it served", status, err)
	}
	if status, body, err := call(t, b, a, http.MethodGet, rosterPath, nil); err != nil || status != http.StatusOK || bytes.Contains(body, []byte(c.id)) {
		t.Errorf("alpha hands bravo the roster %d %s %v, want it without charlie", status, body, err)
	}
	for _, id := range []string{c.id, d.id} {
		if m, _ := memberOf(a.g, id); m.State != StateUnknown {
			t.Errorf("alpha lists %s as %q, want its key not pinned", id, m.State)
		}
	}
	if err := a.g.Import(Roster{Members: []Member{{ID: d.id, Kind: member.KindInstance, Key: identity(t, "delta").Public(), State: StateApproved}}}); err != nil {
		t.Fatal(err)
	}
	if m, _ := memberOf(a.g, d.id); m.State != StateUnknown {
		t.Errorf("alpha took delta from a roster as %q after it closed", m.State)
	}
}

func TestAGroupAsksBeforeItTakesInANewcomerByThePhrase(t *testing.T) {
	url := relayServer(t)
	charlie := identity(t, "charlie")
	var mu sync.Mutex
	asked := map[string]int{}
	a := open(t, "alpha", setup{relay: url, byPhrase: true, mayJoin: func(_ context.Context, id string) bool {
		mu.Lock()
		defer mu.Unlock()
		asked[id]++
		return id != charlie.ID()
	}})
	b := open(t, "bravo", setup{relay: url, byPhrase: true})
	c := open(t, "charlie", setup{relay: url, byPhrase: true})
	waitFor(t, "alpha to answer charlie", func() bool { status, _, _ := call(t, c, a, http.MethodGet, "/api/whoami", nil); return status != 0 })

	for range 2 {
		if status, _, err := call(t, b, a, http.MethodGet, "/api/whoami", nil); err != nil || status != http.StatusOK {
			t.Fatalf("bravo calls alpha = %d %v", status, err)
		}
	}
	status, body, _ := call(t, c, a, http.MethodGet, "/api/whoami", nil)
	if status != http.StatusForbidden || !bytes.Contains(body, []byte(`"groupClosed"`)) {
		t.Errorf("charlie, turned down, calls alpha = %d %s, want 403 groupClosed", status, body)
	}
	if m, _ := memberOf(a.g, c.id); !m.Met.IsZero() {
		t.Errorf("alpha met charlie at %v, want never", m.Met)
	}
	mu.Lock()
	defer mu.Unlock()
	if asked[b.id] != 1 {
		t.Errorf("alpha asked about bravo %d times, want once, before it first met it", asked[b.id])
	}
}

func TestAGroupForTheVouchedAloneAsksOnEveryCallAndTakesNoDecisions(t *testing.T) {
	url := relayServer(t)
	bravo := identity(t, "bravo")
	var vouched atomic.Bool
	vouched.Store(true)
	a := open(t, "alpha", setup{relay: url, vouchedOnly: true, vouch: func(id string, key ed25519.PublicKey) bool {
		return vouched.Load() && id == bravo.ID() && bytes.Equal(key, bravo.Public())
	}})
	b := open(t, "bravo", setup{relay: url, byPhrase: true})
	c := open(t, "charlie", setup{relay: url, byPhrase: true})
	waitFor(t, "bravo to see alpha", func() bool { m, _ := memberOf(b.g, a.id); return m.Relay })
	if status, body, err := call(t, b, a, http.MethodGet, "/api/whoami", nil); err != nil || status != http.StatusOK {
		t.Fatalf("bravo, vouched for, calls alpha = %d %s %v", status, body, err)
	}

	// Who is in the group is decided elsewhere, so alpha neither takes
	// decisions nor hands out whom it knows.
	body, _ := json.Marshal(decision{Op: opRemove, ID: c.id})
	if status, _, err := call(t, b, a, http.MethodPost, decisionPath, body); err == nil && status == http.StatusNoContent {
		t.Error("alpha took a removal from bravo")
	}
	if _, gone := a.g.Roster().Removed[c.id]; gone {
		t.Error("alpha took charlie out on bravo's word")
	}
	if status, raw, err := call(t, b, a, http.MethodGet, rosterPath, nil); err == nil && status == http.StatusOK {
		t.Errorf("alpha handed bravo its roster %s", raw)
	}

	vouched.Store(false)
	if status, raw, err := call(t, b, a, http.MethodGet, "/api/whoami", nil); err == nil && status == http.StatusOK {
		t.Errorf("bravo, turned down by Vouch, calls alpha = %d %s, want it refused", status, raw)
	}
}
