package fortress

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/group"
)

// waitsForNewPhrase reports whether member to turns from away because the
// fortress takes nobody new until its phrase changes.
func waitsForNewPhrase(t *testing.T, from, to *node) bool {
	t.Helper()
	status, body, _ := from.f.group.Call(ctx(t), to.id, http.MethodGet, aboutPath, nil)
	return status == http.StatusForbidden && bytes.Contains(body, []byte(`"`+group.ClosedUntilNewPhrase+`"`))
}

// removeFrom has a take out each member of out, and waits until bravo did too.
func removeFrom(t *testing.T, a, b *node, out ...*node) {
	t.Helper()
	for _, n := range out {
		if err := a.f.Remove(n.id); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "bravo to take "+n.name+" out", func() bool { _, ok := memberOf(b.f, n.id); return !ok })
	}
}

func TestAfterARemovalAFreshKeyWithThePhraseFindsNobody(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	c := open(t, "charlie", "charlie-1", setup{relay: url})
	for _, n := range []*node{a, b, c} {
		waitFor(t, n.name+" to see everybody", func() bool { return len(n.f.Members()) == 2 })
	}
	meet(t, a, b)
	removeFrom(t, a, b, c)
	closeAll(t, c)

	back := open(t, "charlie", "charlie-2", setup{relay: url})
	for _, n := range []*node{a, b} {
		waitFor(t, n.name+" to turn charlie away", func() bool { return waitsForNewPhrase(t, back, n) })
	}
	waitFor(t, "charlie to know it is shut out", back.f.ShutOut)
	for _, m := range back.f.Members() {
		if m.Device != "" {
			t.Errorf("charlie, back under a new key, lists %+v", m)
		}
	}
	for _, n := range []*node{a, b} {
		if m, ok := memberOf(n.f, back.id); ok && m.State == group.StateApproved {
			t.Errorf("%s lets charlie in again as %+v", n.name, m)
		}
	}
}

func TestAfterARemovalANewDeviceWaitsForTheNewPhrase(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	c := open(t, "charlie", "charlie-1", setup{relay: url})
	for _, n := range []*node{a, b, c} {
		waitFor(t, n.name+" to see everybody", func() bool { return len(n.f.Members()) == 2 })
	}
	meet(t, a, b)
	removeFrom(t, a, b, c)

	e := open(t, "echo", "echo-1", setup{relay: url})
	waitFor(t, "alpha to turn echo away", func() bool { return waitsForNewPhrase(t, e, a) })
	// bravo stays closed when it opens again.
	closeAll(t, b)
	b.f = reopen(t, b, setup{relay: url})
	waitFor(t, "bravo to turn echo away", func() bool { return waitsForNewPhrase(t, e, b) })

	secret := changePhrase(t, url, a, b)
	closeAll(t, e)
	e.f = reopen(t, e, setup{relay: url, secret: secret})
	waitFor(t, "echo to join under the new phrase", func() bool {
		_, err := e.f.Status(ctx(t), a.id, "")
		return err == nil
	})
	if e.f.ShutOut() {
		t.Error("echo, in under the new phrase, still says it is shut out")
	}
}

func TestAMemberAwayDuringARemovalClosesOnItsReturn(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	c := open(t, "charlie", "charlie-1", setup{relay: url})
	d := open(t, "delta", "delta-1", setup{relay: url})
	for _, n := range []*node{a, b, c, d} {
		waitFor(t, n.name+" to see everybody", func() bool { return len(n.f.Members()) == 3 })
	}
	meet(t, a, b)
	meet(t, a, d)
	closeAll(t, d)
	removeFrom(t, a, b, c)

	d.f = reopen(t, d, setup{relay: url})
	waitFor(t, "delta to take charlie out", func() bool { _, ok := memberOf(d.f, c.id); return !ok })
	e := open(t, "echo", "echo-1", setup{relay: url})
	waitFor(t, "delta to turn echo away", func() bool { return waitsForNewPhrase(t, e, d) })
}

func TestPluginsAndAwayMembersFollowAChangeAfterARemoval(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	c := open(t, "charlie", "charlie-1", setup{relay: url})
	d := open(t, "delta", "delta-1", setup{relay: url})
	p := openKeysOnly(t, url, "watcher", "watcher-1", Domain.Keys(testSecret))
	for _, n := range []*node{a, b, c, d, p} {
		waitFor(t, n.name+" to see everybody", func() bool { return len(n.f.Members()) == 4 })
	}
	meet(t, a, b)
	meet(t, a, d)
	meet(t, a, p)
	closeAll(t, d, p)
	removeFrom(t, a, b, c)
	secret := changePhrase(t, url, a, b)

	follow(t, url, d, secret)
	p.f = reopenKeysOnly(t, p, url, Domain.Keys(testSecret))
	set, err := newKeys(t, p)
	if err != nil {
		t.Fatalf("the plugin got no new keys: %v", err)
	}
	if set.Group != Domain.Keys(secret).Group {
		t.Error("the plugin got keys of another phrase")
	}
	e := open(t, "echo", "echo-1", setup{relay: url, secret: secret})
	waitFor(t, "echo to join under the new phrase", func() bool {
		_, err := e.f.Status(ctx(t), a.id, "")
		return err == nil
	})
}
