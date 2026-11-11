package fortress

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/group"
	"github.com/junkerderprovinz/parleyport/kit/keys"
	"github.com/junkerderprovinz/parleyport/kit/lan"
	"github.com/junkerderprovinz/parleyport/kit/member"
	"github.com/junkerderprovinz/parleyport/kit/relay"
)

var alpha = keys.Domain("alpha")

// moveIn opens the fortress for p, whose pairing moves in from the app's own
// phrase. p's group stays open for the members that have not followed.
func moveIn(t *testing.T, url string, p *paired, srv *httptest.Server) *node {
	t.Helper()
	held, _ := p.store.Load()
	n := &node{name: p.name, app: "alpha", id: p.id, store: &memStore{}, pairStore: &memStore{data: held}, srv: srv}
	n.f = reopen(t, n, setup{relay: url, previous: oldSecret})
	p.in.Store(n.f)
	return n
}

// device connects a member of kind called name to the relay with set, the
// keys of a group of alpha.
func device(t *testing.T, url string, kind member.Kind, name string, set keys.Set) (*relay.Client, member.Identity) {
	t.Helper()
	seed := sha256.Sum256([]byte(name))
	id, err := member.FromSeed(kind, seed[:])
	if err != nil {
		t.Fatal(err)
	}
	c, err := relay.NewClient(relay.ClientOptions{
		URL: url, Key: set.Group, FrameKey: set.Frame, Signing: alpha.Signing(),
		Self:     relay.Announce{Name: name, Deployment: string(kind), Client: true, Member: id.ID()},
		Identity: &id,
	})
	if err != nil {
		t.Fatal(err)
	}
	c.Start()
	t.Cleanup(func() { _ = c.Close() })
	waitFor(t, name+" on the relay", func() bool { return c.Connected() && len(c.Siblings()) > 0 })
	return c, id
}

// approvePhone has the phone called name sign in at p on the app's own
// phrase, and p approve it.
func approvePhone(t *testing.T, url string, p *paired, name string) (*relay.Client, member.Identity) {
	t.Helper()
	c, id := device(t, url, member.KindMobile, name, alpha.Keys(oldSecret))
	_, _, _ = c.Proxy(ctx(t), p.id, http.MethodGet, "/api/whoami", nil)
	if err := p.g.Approve(id.ID()); err != nil {
		t.Fatal(err)
	}
	return c, id
}

func leftOf(n *node, p *paired) []string {
	var ids []string
	for _, m := range n.f.Left(p.g) {
		ids = append(ids, m.ID)
	}
	slices.Sort(ids)
	return ids
}

func TestAPhoneFollowsTheMoveWithTheKeysAlone(t *testing.T) {
	url := relayServer(t)
	a, b := openPaired(t, url, "alpha-1"), openPaired(t, url, "alpha-2")
	pairUp(t, a, b)
	phone, pid := approvePhone(t, url, a, "phone")
	stranger, _ := device(t, url, member.KindMobile, "stranger", alpha.Keys(oldSecret))

	if _, status, _ := phone.Proxy(ctx(t), a.id, http.MethodGet, movedPath, nil); status != http.StatusNotFound {
		t.Errorf("before the move the phone is answered %d, want 404", status)
	}
	n := moveIn(t, url, a, nil)

	set, err := MovedKeys(ctx(t), phone, a.id)
	if err != nil {
		t.Fatal(err)
	}
	want := alpha.Keys(testSecret)
	if set.Group != want.Group || !bytes.Equal(set.Frame, want.Frame) || !bytes.Equal(set.PeerAuth, want.PeerAuth) {
		t.Errorf("the phone got %+v, want the keys of the pairing in the fortress", set)
	}
	raw, _, _ := phone.Proxy(ctx(t), a.id, http.MethodGet, movedPath, nil)
	for _, form := range [][]byte{testSecret, []byte(base64.StdEncoding.EncodeToString(testSecret)), []byte(hex.EncodeToString(testSecret))} {
		if bytes.Contains(raw, form) {
			t.Errorf("the phone was handed the fortress secret: %s", raw)
		}
	}
	for _, k := range []keys.Domain{Domain, alpha} {
		if bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(k.FrameKey(oldSecret)))) || bytes.Contains(raw, []byte(Domain.GroupKey(testSecret))) {
			t.Errorf("the phone was handed keys besides the pairing's: %s", raw)
		}
	}

	if _, err := MovedKeys(ctx(t), stranger, a.id); err == nil {
		t.Error("a phone nobody approved got the keys")
	}
	if status, _, err := b.g.Call(ctx(t), a.id, http.MethodGet, movedPath, nil); err != nil || status != http.StatusForbidden {
		t.Errorf("an instance asks for the keys = %d %v, want 403, since it follows with the phrase", status, err)
	}

	// With those keys the phone is in the pairing, approved as before.
	moved, _ := device(t, url, member.KindMobile, "phone", set)
	body, status, err := moved.Proxy(ctx(t), n.id, http.MethodGet, "/api/whoami", nil)
	if err != nil || status != http.StatusOK || string(body) != pid.ID() {
		t.Errorf("the phone calls the pairing = %d %s %v", status, body, err)
	}
}

func TestTheOldGroupKnowsWhoMovedAcrossARestart(t *testing.T) {
	url := relayServer(t)
	a, b := openPaired(t, url, "alpha-1"), openPaired(t, url, "alpha-2")
	pairUp(t, a, b)
	phone, pid := approvePhone(t, url, a, "phone")
	n := moveIn(t, url, a, nil)
	if got, want := leftOf(n, a), sorted(b.id, pid.ID()); !slices.Equal(got, want) {
		t.Fatalf("left after the move = %v, want %v", got, want)
	}

	set, err := MovedKeys(ctx(t), phone, a.id)
	if err != nil {
		t.Fatal(err)
	}
	moved, _ := device(t, url, member.KindMobile, "phone", set)
	if _, status, err := moved.Proxy(ctx(t), n.id, http.MethodGet, "/api/whoami", nil); err != nil || status != http.StatusOK {
		t.Fatalf("the phone in the pairing = %d %v", status, err)
	}
	if got := leftOf(n, a); !slices.Equal(got, []string{b.id}) {
		t.Errorf("left once the phone followed = %v, want alpha-2", got)
	}

	if err := n.f.Close(); err != nil {
		t.Fatal(err)
	}
	n.f = reopen(t, n, setup{relay: url, previous: oldSecret})
	a.in.Store(n.f)
	if got := leftOf(n, a); !slices.Equal(got, []string{b.id}) {
		t.Errorf("left after a restart = %v, want alpha-2 alone", got)
	}

	if took := Move(ctx(t), a.g, testSecret); !slices.Equal(took, []string{b.id}) {
		t.Fatalf("Move reached %v", took)
	}
	if err := b.g.Close(); err != nil {
		t.Fatal(err)
	}
	moveIn(t, url, b, nil)
	waitFor(t, "alpha-2 to follow", func() bool { return len(leftOf(n, a)) == 0 })
}

func sorted(ids ...string) []string {
	slices.Sort(ids)
	return ids
}

// taggedOld is p as a member of alpha's own group announces it now.
func taggedOld(p lan.Peer) lan.Peer {
	p.Sent = time.Now().Unix()
	mac := hmac.New(sha256.New, alpha.Keys(oldSecret).PeerAuth)
	mac.Write([]byte("announce\x00" + p.ID + "\x00" + p.URL + "\x00" + p.Name + "\x00" + p.Deployment + "\x00" + p.Address + "\x00" + strconv.FormatInt(p.Sent, 10)))
	p.Tag = hex.EncodeToString(mac.Sum(nil))
	return p
}

func TestAnInstanceNotMovedYetReachesAMovedOneDirectly(t *testing.T) {
	url := relayServer(t)
	lb := lan.New(lan.Config{})
	t.Cleanup(func() { _ = lb.Close() })
	a, b := openPaired(t, url, "alpha-1"), openPairedOn(t, url, "alpha-2", lb)
	pairUp(t, a, b)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f := a.in.Load(); f != nil && r.URL.Path == group.DirectPath {
			f.DirectHandler(a.g).ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	moveIn(t, url, a, srv)
	lb.Observe(taggedOld(lan.Peer{ID: a.id, Name: a.name, URL: srv.URL, Deployment: "container"}))

	status, body, err := b.g.Call(ctx(t), a.id, http.MethodGet, "/api/whoami", nil)
	if err != nil || status != http.StatusOK || string(body) != b.id {
		t.Fatalf("alpha-2 calls alpha-1 on the old phrase = %d %s %v", status, body, err)
	}
	if m, _ := pairedWith(b.g, a.id); !m.Direct {
		t.Errorf("alpha-2 reached alpha-1 as %+v, not directly", m)
	}
}

func TestAnInstanceThatJoinedTheFortressIsPairedOnItsFirstCall(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	fresh := open(t, "alpha", "alpha-2", setup{relay: url})
	meet(t, a, fresh)

	status, body, err := fresh.f.Pairing().Call(ctx(t), a.id, http.MethodGet, "/api/whoami", nil)
	if err != nil || status != http.StatusOK || string(body) != fresh.id {
		t.Errorf("the fresh instance's first call in the pairing = %d %s %v", status, body, err)
	}
	if m, _ := pairedWith(a.f.Pairing(), fresh.id); m.State != group.StateApproved {
		t.Errorf("alpha-1 lists the fresh instance as %q in the pairing", m.State)
	}
}

func TestAnInstanceThatCalledThePairingEarlyIsLeftWaitingNowhere(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	fresh := open(t, "alpha", "alpha-2", setup{relay: url})
	// The fresh instance calls the pairing before the fortress knows it, and
	// is told it waits for approval there.
	waitFor(t, "alpha-2 to see alpha-1 in the pairing", func() bool { m, _ := pairedWith(fresh.f.Pairing(), a.id); return m.Relay })
	_, _, _ = fresh.f.Pairing().Call(ctx(t), a.id, http.MethodGet, "/api/whoami", nil)
	meet(t, a, fresh)
	waitFor(t, "the two paired, neither waiting for the other", func() bool {
		pa, _ := pairedWith(a.f.Pairing(), fresh.id)
		pf, _ := pairedWith(fresh.f.Pairing(), a.id)
		return pa.State == group.StateApproved && pf.State == group.StateApproved && !pa.Awaiting && !pf.Awaiting
	})
}

func TestOnlyAFortressMemberOfTheAppIsPairedUnasked(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	other := open(t, "beta", "beta-1", setup{relay: url})
	meet(t, a, other)

	// beta-1 holds the phrase, so it can derive alpha's pairing keys, and a
	// phone that followed a move holds them too; neither runs alpha in the
	// fortress.
	pose := func(name string, cfg group.Config) {
		t.Helper()
		cfg.Domain, cfg.Identity, cfg.Store = alpha, identity(t, name), &memStore{}
		cfg.Self, cfg.Relay, cfg.RelayURL = group.Self{Name: name}, group.RelayOwn, url
		g, err := group.Open(cfg, appRoutes())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = g.Close() })
		waitFor(t, name+" to see alpha-1", func() bool { m, _ := pairedWith(g, a.id); return m.Relay })
		_, _, _ = g.Call(ctx(t), a.id, http.MethodGet, "/api/whoami", nil)
		waitFor(t, "alpha-1 to pin "+name, func() bool { m, _ := pairedWith(a.f.Pairing(), identity(t, name).ID()); return m.State != "" })
		time.Sleep(2 * tickEvery)
		if m, _ := pairedWith(a.f.Pairing(), identity(t, name).ID()); m.State != group.StatePending {
			t.Errorf("alpha-1 lists %s as %q in its pairing, want pending", name, m.State)
		}
	}
	pose("beta-1", group.Config{Secret: testSecret})
	pose("mallory", group.Config{Keys: alpha.Keys(testSecret)})
}
