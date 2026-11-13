package group

import (
	"net/http"
	"testing"
)

func TestAMemberThatLeavesIsDroppedAtOnceAndCountsAsNoRemoval(t *testing.T) {
	n := onRelay(t, "alpha", "bravo", "charlie")
	a, b, c := n[0], n[1], n[2]
	meet(t, a, b)
	meet(t, a, c)
	meet(t, b, c)

	b.g.Leave()
	if err := b.g.Close(); err != nil {
		t.Fatal(err)
	}
	for _, other := range []*node{a, c} {
		if _, listed := memberOf(other.g, b.id); listed {
			t.Errorf("%s still lists bravo after it left", other.name)
		}
		if _, out := other.g.Roster().Removed[b.id]; out {
			t.Errorf("%s counts bravo's leaving as a removal", other.name)
		}
	}
	if b.removed.Load() > 0 {
		t.Error("bravo heard it was removed when it left")
	}
}

func TestAMemberAwayWhileAnotherLeftDropsItOnItsReturn(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", setup{relay: url})
	b := open(t, "bravo", setup{relay: url})
	c := open(t, "charlie", setup{relay: url})
	waitFor(t, "all three on the relay", func() bool {
		return len(a.g.Members()) == 2 && len(b.g.Members()) == 2 && len(c.g.Members()) == 2
	})
	meet(t, a, b)
	meet(t, a, c)
	meet(t, b, c)
	if err := c.g.Close(); err != nil {
		t.Fatal(err)
	}
	b.g.Leave()
	if err := b.g.Close(); err != nil {
		t.Fatal(err)
	}

	back := open(t, "charlie", setup{relay: url, store: c.store})
	waitFor(t, "charlie to drop bravo", func() bool { _, listed := memberOf(back.g, b.id); return !listed })
	if _, out := back.g.Roster().Removed[b.id]; out {
		t.Error("charlie counts bravo's leaving as a removal")
	}
}

func TestOnlyAMemberItselfSaysItLeft(t *testing.T) {
	n := onRelay(t, "alpha", "bravo", "charlie")
	a, b, c := n[0], n[1], n[2]
	meet(t, a, b)
	meet(t, a, c)

	body := []byte(`{"op":"leave","id":"` + b.id + `"}`)
	_, _, _ = call(t, c, a, http.MethodPost, decisionPath, body)
	if got, _ := memberOf(a.g, b.id); got.State != StateApproved {
		t.Errorf("alpha lists %+v after charlie said bravo left, want bravo still approved", got)
	}
}
