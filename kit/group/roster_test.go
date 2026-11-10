package group

import (
	"bytes"
	"context"
	"encoding/hex"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/member"
)

// served is what alpha answers a call from id to /api/whoami.
func served(a *node, from member.Identity, id string) int {
	status, _ := a.g.handle(context.Background(), signedBy(from, id, a.id, "/api/whoami"))
	return status
}

func TestTheRosterListsWhoIsInAndWhoWasTakenOut(t *testing.T) {
	a := open(t, "alpha", setup{})
	bravo, charlie := identity(t, "bravo"), identity(t, "charlie")
	phone := device(t, member.KindMobile, "pixel")
	served(a, bravo, "b1")
	served(a, charlie, "c1")
	served(a, phone, "p1")
	if err := a.g.Approve(bravo.ID()); err != nil {
		t.Fatal(err)
	}
	if err := a.g.Remove(phone.ID()); err != nil {
		t.Fatal(err)
	}

	r := a.g.Roster()
	states := map[string]State{}
	for _, m := range r.Members {
		states[m.ID] = m.State
		if m.LastSeen.IsZero() || len(m.Key) == 0 {
			t.Errorf("the roster lists %+v without its key or when it was last there", m)
		}
	}
	if states[bravo.ID()] != StateApproved || states[charlie.ID()] != StatePending || len(states) != 2 {
		t.Errorf("roster members = %v, want bravo approved and charlie pending", states)
	}
	if _, ok := r.Removed[phone.ID()]; !ok || len(r.Removed) != 1 {
		t.Errorf("roster removed = %v, want the phone", r.Removed)
	}
	if _, ok := r.Revoked[hex.EncodeToString(phone.Public())]; !ok {
		t.Errorf("roster revoked = %v, want the phone's key", r.Revoked)
	}
}

func TestImportBringsInAGroupKeptElsewhere(t *testing.T) {
	a := open(t, "alpha", setup{})
	bravo := identity(t, "bravo")
	phone := device(t, member.KindMobile, "pixel")
	browser := device(t, member.KindExtension, "firefox")
	viewer := device(t, member.KindViewer, "wall")
	lost := device(t, member.KindMobile, "lost")
	old := identity(t, "old")
	seen := time.Now().Add(-48 * time.Hour)

	err := a.g.Import(Roster{
		Members: []Member{
			{ID: bravo.ID(), Kind: member.KindInstance, Key: bravo.Public(), State: StateApproved, Name: "bravo", Deployment: "container", Address: "https://bravo.lan", LastSeen: seen},
			{ID: phone.ID(), Kind: member.KindMobile, Key: phone.Public(), State: StateApproved, Name: "Pixel", Deployment: "mobile", LastSeen: seen},
			{ID: browser.ID(), Kind: member.KindExtension, Key: browser.Public(), State: StatePending, Name: "Firefox", Deployment: "extension", LastSeen: seen},
			{ID: viewer.ID(), Kind: member.KindViewer, Key: viewer.Public(), State: StateApproved, Name: "Wall", LastSeen: seen},
		},
		Removed: map[string]time.Time{lost.ID(): seen},
		Revoked: map[string]time.Time{hex.EncodeToString(old.Public()): seen},
	})
	if err != nil {
		t.Fatal(err)
	}

	check := func(when string) {
		t.Helper()
		for _, want := range []struct {
			id, name string
			state    State
		}{
			{bravo.ID(), "bravo", StateApproved},
			{phone.ID(), "Pixel", StateApproved},
			{browser.ID(), "Firefox", StatePending},
			{viewer.ID(), "Wall", StateApproved},
		} {
			m, ok := memberOf(a.g, want.id)
			if !ok || m.State != want.state || m.Name != want.name || !m.LastSeen.Equal(seen) || len(m.Key) == 0 {
				t.Errorf("%s alpha lists %+v, want %s %s, last seen %v", when, m, want.name, want.state, seen)
			}
		}
		if m, _ := memberOf(a.g, bravo.ID()); m.Address != "https://bravo.lan" || m.Deployment != "container" {
			t.Errorf("%s alpha lists bravo as %+v, want its address and deployment", when, m)
		}
		if _, gone := a.g.Roster().Removed[lost.ID()]; !gone {
			t.Errorf("%s alpha forgot the lost phone was taken out", when)
		}
	}
	check("after the import")
	if a.g.Close() != nil {
		t.Fatal("close")
	}
	a.g = openGroup(t, a, setup{store: a.store})
	check("after a restart")

	for _, c := range []struct {
		name string
		from member.Identity
		want int
	}{
		{"the approved phone", phone, http.StatusOK},
		{"the waiting browser", browser, http.StatusForbidden},
		{"the removed phone", lost, http.StatusGone},
		{"the revoked key", old, http.StatusGone},
	} {
		if got := served(a, c.from, c.name); got != c.want {
			t.Errorf("%s calls alpha = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestImportTakesNothingItShouldNot(t *testing.T) {
	bravo := identity(t, "bravo")
	phone := device(t, member.KindMobile, "pixel")
	other := device(t, member.KindMobile, "other")
	approved := Member{ID: phone.ID(), Kind: member.KindMobile, Key: phone.Public(), State: StateApproved}

	for _, c := range []struct {
		name   string
		before func(a *node)
		in     Roster
		check  func(t *testing.T, a *node)
	}{
		{
			name: "a key that does not make the id",
			in:   Roster{Members: []Member{{ID: phone.ID(), Kind: member.KindMobile, Key: other.Public(), State: StateApproved}}},
			check: func(t *testing.T, a *node) {
				if _, listed := memberOf(a.g, phone.ID()); listed {
					t.Error("alpha pinned a key under an id it does not make")
				}
			},
		},
		{
			name: "a kind the id does not have",
			in:   Roster{Members: []Member{{ID: phone.ID(), Kind: member.KindExtension, Key: phone.Public(), State: StateApproved}}},
			check: func(t *testing.T, a *node) {
				if _, listed := memberOf(a.g, phone.ID()); listed {
					t.Error("alpha pinned a phone as a browser")
				}
			},
		},
		{
			name: "a member listed and taken out at once",
			in:   Roster{Members: []Member{approved}, Removed: map[string]time.Time{phone.ID(): time.Now()}},
			check: func(t *testing.T, a *node) {
				if _, listed := memberOf(a.g, phone.ID()); listed {
					t.Error("alpha let in a phone the same import took out")
				}
			},
		},
		{
			name:   "a member taken out before",
			before: func(a *node) { served(a, phone, "p0"); _ = a.g.Remove(phone.ID()) },
			in:     Roster{Members: []Member{approved}},
			check: func(t *testing.T, a *node) {
				if _, listed := memberOf(a.g, phone.ID()); listed {
					t.Error("an import brought back a phone alpha took out")
				}
			},
		},
		{
			name:   "an approved member imported as waiting",
			before: func(a *node) { served(a, phone, "p0"); _ = a.g.Approve(phone.ID()) },
			in:     Roster{Members: []Member{{ID: phone.ID(), Kind: member.KindMobile, Key: phone.Public(), State: StatePending}}},
			check: func(t *testing.T, a *node) {
				if m, _ := memberOf(a.g, phone.ID()); m.State != StateApproved {
					t.Errorf("alpha lists the phone as %q, want it still approved", m.State)
				}
			},
		},
		{
			name: "a member with no state",
			in:   Roster{Members: []Member{{ID: phone.ID(), Kind: member.KindMobile, Key: phone.Public()}}},
			check: func(t *testing.T, a *node) {
				if _, listed := memberOf(a.g, phone.ID()); listed {
					t.Error("alpha pinned a member the import gave no state")
				}
			},
		},
		{
			name: "the instance itself",
			in:   Roster{Members: []Member{{ID: identity(t, "alpha").ID(), Kind: member.KindInstance, Key: identity(t, "alpha").Public(), State: StateApproved}}},
			check: func(t *testing.T, a *node) {
				for _, m := range a.g.Roster().Members {
					if m.ID == a.id {
						t.Error("alpha pinned its own key")
					}
				}
			},
		},
		{
			name: "more waiting members than may wait",
			in: func() Roster {
				var r Roster
				for i := range maxWaiting + 4 {
					d := device(t, member.KindMobile, "waiting"+string(rune('a'+i)))
					r.Members = append(r.Members, Member{ID: d.ID(), Kind: member.KindMobile, Key: d.Public(), State: StatePending})
				}
				return r
			}(),
			check: func(t *testing.T, a *node) {
				if n := len(a.g.Roster().Members); n != maxWaiting {
					t.Errorf("alpha pinned %d waiting members, want %d", n, maxWaiting)
				}
			},
		},
		{
			name: "a revoked key that is no key",
			in:   Roster{Revoked: map[string]time.Time{"not hex": time.Now(), hex.EncodeToString(bravo.Public()[:8]): time.Now()}},
			check: func(t *testing.T, a *node) {
				if n := len(a.g.Roster().Revoked); n != 0 {
					t.Errorf("alpha keeps %d revoked keys that are no keys", n)
				}
			},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := open(t, "alpha", setup{})
			if c.before != nil {
				c.before(a)
			}
			if err := a.g.Import(c.in); err != nil {
				t.Fatal(err)
			}
			c.check(t, a)
		})
	}

	t.Run("another key for a pinned member", func(t *testing.T) {
		a := open(t, "alpha", setup{})
		served(a, bravo, "b0")
		mallory := identity(t, "mallory")
		if err := a.g.Import(Roster{Members: []Member{{ID: bravo.ID(), Kind: member.KindInstance, Key: mallory.Public(), State: StateApproved}}}); err != nil {
			t.Fatal(err)
		}
		if m, _ := memberOf(a.g, bravo.ID()); m.State != StatePending || !bytes.Equal(m.Key, bravo.Public()) {
			t.Errorf("alpha lists %+v, want bravo waiting under its own key", m)
		}
	})
}

func TestAPassedOnApprovalLetsADeviceIn(t *testing.T) {
	a := open(t, "alpha", setup{})
	phone := device(t, member.KindMobile, "pixel")
	if err := a.g.Import(Roster{Members: []Member{{ID: phone.ID(), Kind: member.KindMobile, Key: phone.Public(), State: StateApproved}}}); err != nil {
		t.Fatal(err)
	}
	if got := served(a, phone, "p1"); got != http.StatusOK {
		t.Errorf("the phone approved elsewhere calls alpha = %d, want 200 at once", got)
	}
}

func TestARevokedKeyTakesItsMemberOut(t *testing.T) {
	var mu sync.Mutex
	var heard []string
	a := open(t, "alpha", setup{onRemove: func(id string) { mu.Lock(); heard = append(heard, id); mu.Unlock() }})
	phone := device(t, member.KindMobile, "pixel")
	lost := device(t, member.KindMobile, "lost")
	served(a, phone, "p1")
	if err := a.g.Approve(phone.ID()); err != nil {
		t.Fatal(err)
	}
	in := Roster{
		Removed: map[string]time.Time{lost.ID(): time.Now()},
		Revoked: map[string]time.Time{hex.EncodeToString(phone.Public()): time.Now()},
	}
	for range 2 {
		if err := a.g.Import(in); err != nil {
			t.Fatal(err)
		}
	}
	if _, listed := memberOf(a.g, phone.ID()); listed {
		t.Error("alpha still lists the phone whose key was revoked")
	}
	if _, gone := a.g.Roster().Removed[phone.ID()]; !gone {
		t.Error("alpha does not list the phone as taken out")
	}
	if got := served(a, phone, "p2"); got != http.StatusGone {
		t.Errorf("the phone calls = %d, want 410", got)
	}
	mu.Lock()
	defer mu.Unlock()
	slices.Sort(heard)
	want := []string{lost.ID(), phone.ID()}
	slices.Sort(want)
	if !slices.Equal(heard, want) {
		t.Errorf("OnRemove heard %v, want each of %v once", heard, want)
	}
}

func TestANewerSightingRenamesAMember(t *testing.T) {
	a := open(t, "alpha", setup{})
	phone := device(t, member.KindMobile, "pixel")
	now := time.Now()
	sighting := func(name string, at time.Time) {
		t.Helper()
		err := a.g.Import(Roster{Members: []Member{{ID: phone.ID(), Kind: member.KindMobile, Key: phone.Public(), State: StateApproved, Name: name, LastSeen: at}}})
		if err != nil {
			t.Fatal(err)
		}
	}
	sighting("Pixel", now.Add(-time.Hour))
	sighting("Pixel old", now.Add(-2*time.Hour))
	if m, _ := memberOf(a.g, phone.ID()); m.Name != "Pixel" || !m.LastSeen.Equal(now.Add(-time.Hour)) {
		t.Errorf("after an older sighting alpha lists %+v, want Pixel an hour ago", m)
	}
	sighting("Pixel 9", now.Add(-time.Minute))
	if m, _ := memberOf(a.g, phone.ID()); m.Name != "Pixel 9" || !m.LastSeen.Equal(now.Add(-time.Minute)) {
		t.Errorf("after a newer sighting alpha lists %+v, want Pixel 9 a minute ago", m)
	}
	sighting("From the future", now.Add(time.Hour))
	if m, _ := memberOf(a.g, phone.ID()); m.LastSeen.After(time.Now()) {
		t.Errorf("alpha lists the phone as last seen at %v, ahead of its own clock", m.LastSeen)
	}
}

func TestNamesAndLastSeenTravelWithTheRoster(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", setup{relay: url})
	b := open(t, "bravo", setup{relay: url})
	waitFor(t, "both on the relay", func() bool { return len(a.g.Members()) == 1 && len(b.g.Members()) == 1 })
	meet(t, a, b)
	if err := b.g.Close(); err != nil {
		t.Fatal(err)
	}

	phone := device(t, member.KindMobile, "pixel")
	seen := time.Now().Add(-3 * time.Hour)
	if err := a.g.Import(Roster{Members: []Member{{ID: phone.ID(), Kind: member.KindMobile, Key: phone.Public(), State: StateApproved, Name: "Pixel", Deployment: "mobile", LastSeen: seen}}}); err != nil {
		t.Fatal(err)
	}

	b.g = openGroup(t, b, setup{relay: url, store: b.store})
	waitFor(t, "bravo to learn the phone's name from alpha's roster", func() bool {
		m, _ := memberOf(b.g, phone.ID())
		return m.State == StateApproved && m.Name == "Pixel" && m.Deployment == "mobile" && m.LastSeen.Equal(seen)
	})
}
