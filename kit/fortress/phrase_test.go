package fortress

import (
	"bytes"
	"slices"
	"testing"
)

func TestANewPhraseTakesTheMembersAlongAndLeavesTheRemovedOut(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	c := open(t, "charlie", "charlie-1", setup{relay: url})
	d := open(t, "delta", "delta-1", setup{relay: url})
	for _, n := range []*node{a, b, c, d} {
		waitFor(t, n.name+" to see everybody", func() bool { return len(n.f.Members()) == 3 })
	}
	meet(t, a, b)
	if err := a.f.SetPermission("bravo", "alpha", "files.drop", false); err != nil {
		t.Fatal(err)
	}
	if err := a.f.Remove(c.id); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bravo to take charlie out", func() bool { _, ok := memberOf(b.f, c.id); return !ok })
	// delta is away while the phrase changes.
	if err := d.f.Close(); err != nil {
		t.Fatal(err)
	}

	moved, err := a.f.ChangePhrase(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(moved, []string{b.id}) {
		t.Errorf("the new phrase reached %v, want bravo alone", moved)
	}
	secret := a.lastKept()
	if len(secret) == 0 || !bytes.Equal(b.lastKept(), secret) || c.lastKept() != nil || d.lastKept() != nil {
		t.Fatalf("kept: alpha %x, bravo %x, charlie %x, delta %x", secret, b.lastKept(), c.lastKept(), d.lastKept())
	}

	// alpha and bravo open again under the new phrase and keep what they knew.
	for _, n := range []*node{a, b} {
		if err := n.f.Close(); err != nil {
			t.Fatal(err)
		}
		n.f = reopen(t, n, setup{relay: url, secret: secret, moved: testSecret})
	}
	waitFor(t, "alpha and bravo to meet again", func() bool {
		m, _ := memberOf(a.f, b.id)
		return m.Online() && m.App.ID == "bravo"
	})
	if on(a.f.Permissions(), "bravo", "alpha", "files.drop") {
		t.Error("the switched off permission is on again under the new phrase")
	}
	if _, ok := memberOf(a.f, c.id); ok {
		t.Error("alpha lists charlie again under the new phrase")
	}

	// charlie, with the old phrase, gets nothing, even under a new key.
	c2 := open(t, "charlie", "charlie-2", setup{relay: url})
	for _, n := range []*node{c, c2} {
		if _, err := n.f.Status(ctx(t), a.id, ""); err == nil {
			t.Errorf("%s reads alpha under the old phrase", n.name)
		}
	}

	// delta, away during the change, reads nothing under the old phrase,
	// takes the new one from alpha or bravo and is in at once.
	d.f = reopen(t, d, setup{relay: url})
	if _, err := d.f.Status(ctx(t), a.id, ""); err == nil {
		t.Error("delta reads alpha under the old phrase")
	}
	waitFor(t, "delta to take the new phrase", func() bool { return bytes.Equal(d.lastKept(), secret) })
	if err := d.f.Close(); err != nil {
		t.Fatal(err)
	}
	d.f = reopen(t, d, setup{relay: url, secret: secret, moved: testSecret})
	waitFor(t, "delta to reach alpha", func() bool { m, _ := memberOf(d.f, a.id); return m.Online() })
	if _, err := d.f.Status(ctx(t), a.id, ""); err != nil {
		t.Errorf("delta reads alpha after entering the new phrase: %v", err)
	}
}

func TestWithoutAKeeperThePhraseStays(t *testing.T) {
	n := &node{name: "alpha-1", app: "alpha", store: &memStore{}, pairStore: &memStore{}}
	cfg := config(t, n, setup{})
	cfg.Keeper = nil
	f, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if _, err := f.ChangePhrase(ctx(t)); err == nil {
		t.Error("a fortress with nowhere to keep the phrase changed it")
	}
}
