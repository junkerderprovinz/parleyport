package fortress

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/group"
)

func changedOf(n *node) time.Time {
	n.f.mu.Lock()
	defer n.f.mu.Unlock()
	return n.f.book.Changed
}

// follow opens n on the phrase before the change, waits until a member hands
// it secret and opens it again under that.
func follow(t *testing.T, url string, n *node, secret []byte) {
	t.Helper()
	n.f = reopen(t, n, setup{relay: url})
	waitFor(t, n.name+" to take the new phrase", func() bool { return bytes.Equal(n.lastKept(), secret) })
	if err := n.f.Close(); err != nil {
		t.Fatal(err)
	}
	n.f = reopen(t, n, setup{relay: url, secret: secret, moved: testSecret})
}

// neverHanded fails t when member to hands n's key, asking on the phrase
// before the change, the new phrase or the keys under it.
func neverHanded(t *testing.T, url string, n *node, to ...*node) {
	t.Helper()
	c := asker(t, url, n)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, m := range to {
			if _, status, raw := askFor(t, c, m); status == http.StatusOK {
				t.Fatalf("%s handed %s %s", m.name, n.name, raw)
			}
			if raw, status, _ := c.Proxy(ctx(t), m.id, http.MethodGet, movedPath, nil); status == http.StatusOK {
				t.Fatalf("%s handed %s the new keys %s", m.name, n.name, raw)
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func closeAll(t *testing.T, nodes ...*node) {
	t.Helper()
	for _, n := range nodes {
		if err := n.f.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAnInstanceThatFollowedLateHandsAMemberTakenOutNothing(t *testing.T) {
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
	// delta is away while charlie is taken out and the phrase changes.
	closeAll(t, d)
	if err := a.f.Remove(c.id); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bravo to take charlie out", func() bool { _, ok := memberOf(b.f, c.id); return !ok })
	closeAll(t, c)
	secret := changePhrase(t, url, a, b)

	d.f = reopen(t, d, setup{relay: url})
	waitFor(t, "delta to take the new phrase", func() bool { return bytes.Equal(d.lastKept(), secret) })
	if _, ok := d.f.group.Roster().Removed[c.id]; !ok {
		t.Error("delta followed without hearing that charlie was taken out")
	}
	// Nobody who was there for the change is in reach any more.
	closeAll(t, a, b, d)
	d.f = reopen(t, d, setup{relay: url, secret: secret, moved: testSecret})
	neverHanded(t, url, c, d)
}

func TestEveryMemberCountsTheChangeFromWhenThePhraseChanged(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	d := open(t, "delta", "delta-1", setup{relay: url})
	for _, n := range []*node{a, b, d} {
		waitFor(t, n.name+" to see everybody", func() bool { return len(n.f.Members()) == 2 })
	}
	meet(t, a, d)
	closeAll(t, d)
	before := time.Now()
	if _, err := a.f.ChangePhrase(ctx(t)); err != nil {
		t.Fatal(err)
	}
	after := time.Now()
	secret := a.lastKept()
	// Opening again a while later must not move the change.
	time.Sleep(50 * time.Millisecond)
	closeAll(t, a, b)
	for _, n := range []*node{a, b} {
		n.f = reopen(t, n, setup{relay: url, secret: secret, moved: testSecret})
	}
	changed := changedOf(a)
	if changed.Before(before.Round(0)) || changed.After(after) {
		t.Fatalf("alpha counts the change from %v, want between %v and %v", changed, before, after)
	}
	if !changedOf(b).Equal(changed) {
		t.Errorf("bravo counts the change from %v, alpha from %v", changedOf(b), changed)
	}
	time.Sleep(50 * time.Millisecond)
	follow(t, url, d, secret)
	if !changedOf(d).Equal(changed) {
		t.Errorf("delta, which followed late, counts the change from %v, alpha from %v", changedOf(d), changed)
	}
}

func TestANewcomerAStragglerTookInAfterTheChangeGetsNothing(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	d := open(t, "delta", "delta-1", setup{relay: url})
	e := open(t, "echo", "echo-1", setup{relay: url})
	for _, n := range []*node{a, b, d, e} {
		waitFor(t, n.name+" to see everybody", func() bool { return len(n.f.Members()) == 3 })
	}
	meet(t, a, d)
	meet(t, a, e)
	closeAll(t, d, e)
	secret := changePhrase(t, url, a, b)

	// echo comes back while alpha is there and follows. delta comes back when
	// only echo could tell it, and takes in zulu, new on the old phrase.
	e.f = reopen(t, e, setup{relay: url})
	waitFor(t, "echo to take the new phrase", func() bool { return bytes.Equal(e.lastKept(), secret) })
	closeAll(t, e, a, b)
	d.f = reopen(t, d, setup{relay: url})
	z := open(t, "zulu", "zulu-1", setup{relay: url})
	waitFor(t, "delta to take zulu in", func() bool {
		status, _, _ := z.f.group.Call(ctx(t), d.id, http.MethodGet, aboutPath, nil)
		return status == http.StatusOK
	})
	e.f = reopen(t, e, setup{relay: url, secret: secret, moved: testSecret})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if d.lastKept() != nil {
			t.Fatal("echo, which followed late, handed delta the new phrase")
		}
		time.Sleep(50 * time.Millisecond)
	}

	a.f = reopen(t, a, setup{relay: url, secret: secret, moved: testSecret})
	waitFor(t, "delta to take the new phrase from alpha", func() bool { return bytes.Equal(d.lastKept(), secret) })
	for _, m := range d.f.group.Members() {
		if m.ID == z.id && m.State == group.StateApproved {
			t.Error("delta still lets zulu in after hearing of the change")
		}
	}
	closeAll(t, d, z)
	d.f = reopen(t, d, setup{relay: url, secret: secret, moved: testSecret})
	neverHanded(t, url, z, a, d, e)
	if _, ok := memberOf(d.f, z.id); ok {
		t.Error("delta lists zulu under the new phrase")
	}
}

func TestTakingANewPhraseForgetsWhoeverWasFirstMetAfterTheChange(t *testing.T) {
	url := relayServer(t)
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	changed := time.Now().Round(0)
	z := open(t, "zulu", "zulu-1", setup{relay: url})
	waitFor(t, "bravo to take zulu in", func() bool {
		status, _, _ := z.f.group.Call(ctx(t), b.id, http.MethodGet, aboutPath, nil)
		return status == http.StatusOK
	})
	if err := b.f.takeNew(newPhrase{Secret: []byte("fedcba9876543210"), Changed: changed}, false); err != nil {
		t.Fatal(err)
	}
	for _, m := range b.f.group.Members() {
		if m.ID == z.id && m.State == group.StateApproved {
			t.Error("bravo takes zulu, first met after the change, along to the new phrase")
		}
	}
}

func TestABookALateFollowerMovesStaysLateWhateverTimeCameWithIt(t *testing.T) {
	for _, at := range []time.Time{{}, time.Now().Add(time.Hour)} {
		raw, err := json.Marshal(book{Group: "old", Next: &handed{Changed: at, Late: true}})
		if err != nil {
			t.Fatal(err)
		}
		b, err := loadBook(raw, "new", "old")
		if err != nil {
			t.Fatal(err)
		}
		if !b.Late || b.Changed.After(time.Now()) || b.Changed.IsZero() {
			t.Errorf("handed at %v, the book reads late %v, changed %v", at, b.Late, b.Changed)
		}
	}
}
