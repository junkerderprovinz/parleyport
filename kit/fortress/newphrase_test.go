package fortress

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/relay"
)

// asker is n's member key on the relay under the phrase before the change,
// in a client that takes every answer, as one running whatever code it likes
// could.
func asker(t *testing.T, url string, n *node) *relay.Client {
	t.Helper()
	return listen(t, url, n, nil)
}

// listen is asker answering the calls it gets with serve.
func listen(t *testing.T, url string, n *node, serve relay.ProxyHandler) *relay.Client {
	t.Helper()
	id := identity(t, n.name)
	old := Domain.Keys(testSecret)
	c, err := relay.NewClient(relay.ClientOptions{
		URL: url, Key: old.Group, FrameKey: old.Frame, Signing: Domain.Signing(),
		Self:     relay.Announce{Name: n.name, Deployment: "container"},
		Identity: &id,
		Serve:    serve,
	})
	if err != nil {
		t.Fatal(err)
	}
	c.Start()
	t.Cleanup(func() { _ = c.Close() })
	waitFor(t, n.name+" on the relay", func() bool { return c.Connected() && len(c.Siblings()) > 0 })
	return c
}

// askFor asks member to through c for the phrase the fortress changed to,
// with a key of its own, and returns the key, the status and the answer.
func askFor(t *testing.T, c *relay.Client, to *node) (*ecdh.PrivateKey, int, []byte) {
	t.Helper()
	own, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(newPhraseAsk{Key: own.PublicKey().Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	raw, status, _ := c.Proxy(ctx(t), to.id, http.MethodPost, newPhrasePath, body)
	return own, status, raw
}

// handsNothing fails t when n, open on the phrase before the change, is
// handed the new one by itself, or when any of to hands it to n's key asking.
func handsNothing(t *testing.T, url string, n *node, to ...*node) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if n.lastKept() != nil {
			t.Fatalf("%s was handed the new phrase", n.name)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := n.f.Close(); err != nil {
		t.Fatal(err)
	}
	c := asker(t, url, n)
	for _, m := range to {
		waitFor(t, m.name+" to answer "+n.name, func() bool {
			_, status, _ := askFor(t, c, m)
			return status != 0
		})
		if _, status, raw := askFor(t, c, m); status == http.StatusOK {
			t.Errorf("%s handed %s %s", m.name, n.name, raw)
		}
	}
}

func TestAnInstanceAwayDuringAChangeFollowsOnItsOwn(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	d := open(t, "delta", "delta-1", setup{relay: url})
	for _, n := range []*node{a, b, d} {
		waitFor(t, n.name+" to see everybody", func() bool { return len(n.f.Members()) == 2 })
	}
	meet(t, a, d)
	if err := d.f.Close(); err != nil {
		t.Fatal(err)
	}
	secret := changePhrase(t, url, a, b)

	d.f = reopen(t, d, setup{relay: url})
	waitFor(t, "delta to take the new phrase", func() bool { return bytes.Equal(d.lastKept(), secret) })
	if err := d.f.Close(); err != nil {
		t.Fatal(err)
	}
	d.f = reopen(t, d, setup{relay: url, secret: secret, moved: testSecret})
	waitFor(t, "alpha to reach delta under the new phrase", func() bool { m, _ := memberOf(a.f, d.id); return m.Online() })
	if m, _ := memberOf(a.f, d.id); m.App.ID != "delta" || len(a.f.Members()) != 2 {
		t.Errorf("alpha lists %+v, want bravo and delta as it was", a.f.Members())
	}
	if _, err := d.f.Status(ctx(t), a.id, ""); err != nil {
		t.Errorf("delta reads alpha under the new phrase: %v", err)
	}
	d.mu.Lock()
	kept := len(d.kept)
	d.mu.Unlock()
	if kept != 1 {
		t.Errorf("delta was handed the new phrase %d times", kept)
	}
}

func TestAMemberTakenOutBeforeTheChangeIsNeverHandedTheNewPhrase(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	c := open(t, "charlie", "charlie-1", setup{relay: url})
	d := open(t, "delta", "delta-1", setup{relay: url})
	for _, n := range []*node{a, b, c, d} {
		waitFor(t, n.name+" to see everybody", func() bool { return len(n.f.Members()) == 3 })
	}
	if err := a.f.Remove(c.id); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bravo to take charlie out", func() bool { _, ok := memberOf(b.f, c.id); return !ok })
	for _, n := range []*node{c, d} {
		if err := n.f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	secret := changePhrase(t, url, a, b)

	// delta, away as well but still a member, shows the handover runs.
	c.f = reopen(t, c, setup{relay: url})
	d.f = reopen(t, d, setup{relay: url})
	waitFor(t, "delta to take the new phrase", func() bool { return bytes.Equal(d.lastKept(), secret) })
	handsNothing(t, url, c, a, b)
}

func TestAMemberTakenOutWhileAwayIsNeverHandedTheNewPhrase(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	d := open(t, "delta", "delta-1", setup{relay: url})
	for _, n := range []*node{a, b, d} {
		waitFor(t, n.name+" to see everybody", func() bool { return len(n.f.Members()) == 2 })
	}
	if err := d.f.Close(); err != nil {
		t.Fatal(err)
	}
	changePhrase(t, url, a, b)
	if err := a.f.Remove(d.id); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bravo to take delta out", func() bool { _, ok := memberOf(b.f, d.id); return !ok })

	d.f = reopen(t, d, setup{relay: url})
	handsNothing(t, url, d, a, b)
}

func TestAMemberTakenOutAfterItAskedOnTheOldPhraseIsHandedNothingMore(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	d := open(t, "delta", "delta-1", setup{relay: url})
	for _, n := range []*node{a, b, d} {
		waitFor(t, n.name+" to see everybody", func() bool { return len(n.f.Members()) == 2 })
	}
	if err := d.f.Close(); err != nil {
		t.Fatal(err)
	}
	changePhrase(t, url, a, b)
	c := asker(t, url, d)
	waitFor(t, "alpha to let delta in on the old phrase", func() bool {
		_, status, _ := c.Proxy(ctx(t), a.id, http.MethodGet, aboutPath, nil)
		return status == http.StatusOK
	})
	if err := a.f.Remove(d.id); err != nil {
		t.Fatal(err)
	}
	if _, status, raw := askFor(t, c, a); status == http.StatusOK {
		t.Errorf("alpha handed delta, taken out, %s", raw)
	}
}

func TestANewcomerOnTheOldPhraseIsHandedNoNewPhrase(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	waitFor(t, "alpha to see bravo", func() bool { return len(a.f.Members()) == 1 })
	changePhrase(t, url, a, b)

	late := open(t, "charlie", "charlie-1", setup{relay: url})
	handsNothing(t, url, late, a, b)
	if _, ok := memberOf(a.f, late.id); ok {
		t.Error("alpha lists the newcomer")
	}
}

func TestTheNewPhraseOpensOnlyForTheInstanceThatAskedWithTheOldOne(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	d := open(t, "delta", "delta-1", setup{relay: url})
	p := openKeysOnly(t, url, "watcher", "watcher-1", Domain.Keys(testSecret))
	for _, n := range []*node{a, b, d, p} {
		waitFor(t, n.name+" to see everybody", func() bool { return len(n.f.Members()) == 3 })
	}
	meet(t, a, d)
	meet(t, a, p)
	if err := d.f.Close(); err != nil {
		t.Fatal(err)
	}
	secret := changePhrase(t, url, a, b)

	var own *ecdh.PrivateKey
	var raw []byte
	dc := asker(t, url, d)
	waitFor(t, "alpha to hand delta the new phrase", func() bool {
		var status int
		own, status, raw = askFor(t, dc, a)
		return status == http.StatusOK
	})
	for _, s := range [][]byte{secret, testSecret} {
		for _, form := range [][]byte{s, []byte(base64.StdEncoding.EncodeToString(s)), []byte(hex.EncodeToString(s))} {
			if bytes.Contains(raw, form) {
				t.Errorf("the answer carries a secret as it is: %s", raw)
			}
		}
	}
	if got, err := openNewPhrase(own, raw, testSecret, a.id, d.id); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("delta opens %x, %v, want the new secret", got, err)
	}
	// Whoever reads the answer under the old phrase, as one taken out could,
	// lacks the key delta asked with.
	other, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := openNewPhrase(other, raw, testSecret, a.id, d.id); err == nil {
		t.Errorf("another key opened the answer to %x", got)
	}

	// The plugin, a member that holds only keys, asks as well, and what it
	// gets opens with none of them.
	if err := p.f.Close(); err != nil {
		t.Fatal(err)
	}
	pOwn, status, pRaw := askFor(t, asker(t, url, p), a)
	if status == http.StatusOK {
		old := Domain.Keys(testSecret)
		for _, held := range [][]byte{nil, old.Frame, old.PeerAuth, []byte(old.Group)} {
			if got, err := openNewPhrase(pOwn, pRaw, held, a.id, p.id); err == nil {
				t.Errorf("the plugin opened the answer to %x", got)
			}
		}
	}
	if p.lastKept() != nil {
		t.Error("the plugin was handed the new phrase")
	}
}

func TestNoNewPhraseIsHandedThirtyDaysAfterTheChange(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	d := open(t, "delta", "delta-1", setup{relay: url})
	for _, n := range []*node{a, b, d} {
		waitFor(t, n.name+" to see everybody", func() bool { return len(n.f.Members()) == 2 })
	}
	if err := d.f.Close(); err != nil {
		t.Fatal(err)
	}
	changePhrase(t, url, a, b)
	// alpha and bravo have run since the change for longer than the window.
	for _, n := range []*node{a, b} {
		n.f.mu.Lock()
		n.f.book.Changed = time.Now().Add(-moveWindow - time.Hour)
		n.f.mu.Unlock()
	}

	d.f = reopen(t, d, setup{relay: url})
	handsNothing(t, url, d, a, b)
}
