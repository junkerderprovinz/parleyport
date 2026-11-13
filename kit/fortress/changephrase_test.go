package fortress

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"sync"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/group"
	"github.com/junkerderprovinz/parleyport/kit/member"
	"github.com/junkerderprovinz/parleyport/kit/relay"
)

// catcher stands in for a member on the phrase before the change and answers
// as an instance that holds that phrase would. It keeps every call it gets as
// it opens under that phrase, which is what whoever holds the phrase reads
// off the wire.
type catcher struct {
	own   *ecdh.PrivateKey
	mu    sync.Mutex
	calls []relay.ProxyCall
}

func catch(t *testing.T, url string, n *node) *catcher {
	t.Helper()
	own, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := &catcher{own: own}
	listen(t, url, n, func(_ context.Context, call relay.ProxyCall) (int, []byte) {
		c.mu.Lock()
		c.calls = append(c.calls, call)
		c.mu.Unlock()
		switch call.Path {
		case phraseKeyPath:
			body, _ := json.Marshal(newPhraseAsk{Key: own.PublicKey().Bytes()})
			return http.StatusOK, body
		case phrasePath:
			return http.StatusNoContent, nil
		}
		return http.StatusNotFound, nil
	})
	return c
}

// on is the body of every call c got on path.
func (c *catcher) on(path string) [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out [][]byte
	for _, call := range c.calls {
		if call.Path == path {
			out = append(out, call.Body)
		}
	}
	return out
}

func carriesSecret(raw []byte, secrets ...[]byte) bool {
	for _, s := range secrets {
		for _, form := range [][]byte{s, []byte(base64.StdEncoding.EncodeToString(s)), []byte(hex.EncodeToString(s))} {
			if bytes.Contains(raw, form) {
				return true
			}
		}
	}
	return false
}

func TestWhatChangePhraseSendsOpensOnlyForTheMemberItWentTo(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	d := open(t, "delta", "delta-1", setup{relay: url})
	waitFor(t, "alpha to see delta", func() bool { return len(a.f.Members()) == 1 })
	meet(t, a, d)
	if err := d.f.Close(); err != nil {
		t.Fatal(err)
	}
	c := catch(t, url, d)
	waitFor(t, "alpha to reach delta", func() bool { m, _ := memberOf(a.f, d.id); return m.Online() })

	moved, err := a.f.ChangePhrase(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	secret := a.lastKept()
	if !slices.Equal(moved, []string{d.id}) {
		t.Fatalf("the new phrase reached %v, want delta", moved)
	}
	sent := c.on(phrasePath)
	if len(sent) != 1 {
		t.Fatalf("delta got %d calls with the new phrase", len(sent))
	}
	if carriesSecret(sent[0], secret, testSecret) {
		t.Errorf("the new phrase went out readable under the old one: %s", sent[0])
	}
	other, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := openNewPhrase(other, sent[0], testSecret, a.id, d.id); err == nil {
		t.Errorf("another key with the old phrase opened it to %x", got.Secret)
	}
	if got, err := openNewPhrase(c.own, sent[0], testSecret, a.id, d.id); err != nil || !bytes.Equal(got.Secret, secret) {
		t.Errorf("delta opens %x, %v, want the new secret", got.Secret, err)
	}
}

func TestChangePhraseSendsNothingToAMemberTakenOut(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	r := open(t, "romeo", "romeo-1", setup{relay: url})
	for _, n := range []*node{a, b, r} {
		waitFor(t, n.name+" to see everybody", func() bool { return len(n.f.Members()) == 2 })
	}
	if err := a.f.Remove(r.id); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bravo to take romeo out", func() bool { _, ok := memberOf(b.f, r.id); return !ok })
	if err := r.f.Close(); err != nil {
		t.Fatal(err)
	}
	c := catch(t, url, r)

	moved, err := a.f.ChangePhrase(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(moved, []string{b.id}) {
		t.Errorf("the new phrase reached %v, want bravo alone", moved)
	}
	if n := len(c.on(phrasePath)) + len(c.on(phraseKeyPath)); n > 0 {
		t.Errorf("romeo, taken out, got %d calls about the new phrase", n)
	}
}

func TestChangePhraseHandsAPluginNoSecretAndItFollowsWithTheKeys(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	p := openKeysOnly(t, url, "watcher", "watcher-1", Domain.Keys(testSecret))
	q := openKeysOnly(t, url, "watcher", "watcher-2", Domain.Keys(testSecret))
	for _, n := range []*node{a, b, p, q} {
		waitFor(t, n.name+" to see everybody", func() bool { return len(n.f.Members()) == 3 })
	}
	meet(t, a, p)
	meet(t, a, q)
	// watcher-2 holds the keys alone but answers as if it held the phrase.
	if err := q.f.Close(); err != nil {
		t.Fatal(err)
	}
	liar := catch(t, url, q)
	waitFor(t, "alpha to reach watcher-2", func() bool { m, _ := memberOf(a.f, q.id); return m.Online() })

	moved, err := a.f.ChangePhrase(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	secret := a.lastKept()
	if slices.Contains(moved, p.id) || !slices.Contains(moved, b.id) {
		t.Errorf("the new phrase reached %v, want bravo and not the plugin", moved)
	}
	old := Domain.Keys(testSecret)
	for _, sent := range liar.on(phrasePath) {
		if carriesSecret(sent, secret, testSecret) {
			t.Errorf("watcher-2 was sent a secret readable: %s", sent)
		}
		for _, held := range [][]byte{nil, old.Frame, old.PeerAuth, []byte(old.Group)} {
			if got, err := openNewPhrase(liar.own, sent, held, a.id, q.id); err == nil {
				t.Errorf("watcher-2 opened the new phrase to %x", got.Secret)
			}
		}
	}

	for _, n := range []*node{a, b} {
		if err := n.f.Close(); err != nil {
			t.Fatal(err)
		}
		n.f = reopen(t, n, setup{relay: url, secret: secret, moved: testSecret})
	}
	waitFor(t, "alpha to refuse the plugin on the old phrase", func() bool {
		_, err := p.f.Status(ctx(t), a.id, "")
		return refusalCode(err) == phraseChanged
	})
	set, err := newKeys(t, p)
	if err != nil {
		t.Fatal(err)
	}
	if set.Group != Domain.Keys(secret).Group {
		t.Error("the plugin did not get the keys under the new phrase")
	}
}

func TestChangePhraseSendsNothingToAMemberWaitingForApproval(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	w := &node{name: "whisky-1", id: identity(t, "whisky-1").ID()}
	id := identity(t, w.name)
	if err := a.f.group.Import(group.Roster{Members: []group.Member{{ID: w.id, Kind: member.KindInstance, Key: id.Public(), State: group.StatePending}}}); err != nil {
		t.Fatal(err)
	}
	c := catch(t, url, w)
	waitFor(t, "alpha to see whisky waiting", func() bool {
		for _, m := range a.f.group.Members() {
			if m.ID == w.id {
				return m.State == group.StatePending && m.Online()
			}
		}
		return false
	})

	if _, err := a.f.ChangePhrase(ctx(t)); err != nil {
		t.Fatal(err)
	}
	if n := len(c.on(phrasePath)) + len(c.on(phraseKeyPath)); n > 0 {
		t.Errorf("whisky, waiting for approval, got %d calls about the new phrase", n)
	}
}
