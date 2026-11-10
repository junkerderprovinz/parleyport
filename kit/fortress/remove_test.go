package fortress

import (
	"net/http"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/group"
)

func TestARemovedMemberCanDoNothing(t *testing.T) {
	n := inRelay(t, "alpha", "alpha-1", "bravo", "bravo-1", "charlie", "charlie-1")
	a, b, c := n[0], n[1], n[2]
	meet(t, a, b)
	meet(t, a, c)
	meet(t, b, c)

	if err := a.f.Remove(c.id); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "charlie to hear it", func() bool { return c.removed.Load() > 0 })
	waitFor(t, "bravo to take charlie out", func() bool { _, ok := memberOf(b.f, c.id); return !ok })

	for _, target := range []*node{a, b} {
		if _, err := c.f.Status(ctx(t), target.id, ""); err == nil {
			t.Errorf("charlie still reads %s's status", target.name)
		}
		if _, err := c.f.Act(ctx(t), target.id, "files.drop", []byte(`"x"`)); err == nil {
			t.Errorf("charlie still acts at %s", target.name)
		}
		if len(target.drops()) > 0 {
			t.Errorf("%s ran %v for a removed member", target.name, target.drops())
		}
	}
	if err := b.f.Approve(c.id); err == nil {
		t.Error("bravo approved charlie again with the same key")
	}
}

func TestRemovingAnInstanceTakesItOutOfItsPairing(t *testing.T) {
	n := inRelay(t, "alpha", "alpha-1", "alpha", "alpha-2", "bravo", "bravo-1")
	a1, a2, b := n[0], n[1], n[2]
	meet(t, a1, a2)
	meet(t, a1, b)
	meet(t, a2, b)
	waitFor(t, "the pairing to follow the fortress", func() bool {
		p, _ := pairedWith(a1.f.Pairing(), a2.id)
		return p.State == group.StateApproved
	})

	// The owner takes alpha-2 out on bravo's page; alpha-1 hears it as a
	// member of the fortress and takes alpha-2 out of the pairing as well.
	if err := b.f.Remove(a2.id); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "alpha-1 to take alpha-2 out of the pairing", func() bool {
		_, ok := pairedWith(a1.f.Pairing(), a2.id)
		return !ok
	})
	status, body, _ := a2.f.Pairing().Call(ctx(t), a1.id, http.MethodGet, "/api/whoami", nil)
	if status != http.StatusGone {
		t.Errorf("alpha-2 calls its old sibling: %d %s, want 410", status, body)
	}
}

func TestRemovingFromThePairingTakesItOutOfTheFortress(t *testing.T) {
	n := inRelay(t, "alpha", "alpha-1", "alpha", "alpha-2", "bravo", "bravo-1")
	a1, a2, b := n[0], n[1], n[2]
	meet(t, a1, a2)
	meet(t, a1, b)
	meet(t, a2, b)
	waitFor(t, "the pairing to follow the fortress", func() bool {
		p, _ := pairedWith(a1.f.Pairing(), a2.id)
		return p.State == group.StateApproved
	})
	if err := a1.f.Pairing().Remove(a2.id); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bravo to take alpha-2 out", func() bool { _, ok := memberOf(b.f, a2.id); return !ok })
}

func TestAMemberKeepsTheAppItNamedFirst(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	waitFor(t, "both on the relay", func() bool { return len(a.f.Members()) == 1 && len(b.f.Members()) == 1 })
	meet(t, a, b)

	// bravo-1 comes back claiming to run alpha, which would let it into
	// alpha's pairing and under alpha's permissions.
	if err := b.f.Close(); err != nil {
		t.Fatal(err)
	}
	b.app = "alpha"
	b.f = reopen(t, b, setup{relay: url})
	a.f.mu.Lock()
	a.f.described[b.id] = time.Time{}
	a.f.mu.Unlock()
	waitFor(t, "alpha to ask bravo again", func() bool {
		a.f.mu.Lock()
		defer a.f.mu.Unlock()
		return a.f.described[b.id].After(time.Now())
	})
	if m, _ := memberOf(a.f, b.id); m.App.ID != "bravo" {
		t.Errorf("alpha lists bravo-1 as %q, want the app it named first", m.App.ID)
	}
	if p, ok := pairedWith(a.f.Pairing(), b.id); ok && p.State == group.StateApproved {
		t.Error("alpha approved bravo-1 in its own pairing")
	}
}
