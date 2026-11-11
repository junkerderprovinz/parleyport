package group

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"io"
	"net/http"
	"net/http/httptest"
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
