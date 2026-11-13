package fortress

import (
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/group"
)

func TestAMemberThatLeavesIsGoneFromTheFortressAndThePairing(t *testing.T) {
	n := inRelay(t, "alpha", "alpha-1", "alpha", "alpha-2", "bravo", "bravo-1")
	a1, a2, b := n[0], n[1], n[2]
	meet(t, a1, a2)
	meet(t, a1, b)
	meet(t, a2, b)
	waitFor(t, "the pairing to follow the fortress", func() bool {
		p1, _ := pairedWith(a1.f.Pairing(), a2.id)
		p2, _ := pairedWith(a2.f.Pairing(), a1.id)
		return p1.State == group.StateApproved && p2.State == group.StateApproved
	})

	a2.f.Leave()
	if err := a2.f.Close(); err != nil {
		t.Fatal(err)
	}
	for _, other := range []*node{a1, b} {
		if _, listed := memberOf(other.f, a2.id); listed {
			t.Errorf("%s still lists alpha-2 after it left", other.name)
		}
		if !other.f.removedSince(time.Time{}).IsZero() {
			t.Errorf("%s counts alpha-2's leaving as a removal", other.name)
		}
	}
	if _, ok := pairedWith(a1.f.Pairing(), a2.id); ok {
		t.Error("alpha-1 still pairs alpha-2 after it left")
	}
	if a2.removed.Load() > 0 {
		t.Error("alpha-2 heard it was removed when it left")
	}
}
