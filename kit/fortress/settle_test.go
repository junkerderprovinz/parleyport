package fortress

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/group"
)

// backdate restarts p's group on the app's own phrase as if it had been
// retired ago before now.
func backdate(t *testing.T, url string, p *paired, ago time.Duration) {
	t.Helper()
	if err := p.g.Close(); err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(p.store.data, &doc); err != nil {
		t.Fatal(err)
	}
	at, err := json.Marshal(time.Now().Add(-ago))
	if err != nil {
		t.Fatal(err)
	}
	doc["retired"] = at
	if p.store.data, err = json.Marshal(doc); err != nil {
		t.Fatal(err)
	}
	p.open(t, url, nil)
}

func behindOf(f *Fortress) []string {
	var names []string
	for _, m := range f.Behind() {
		names = append(names, m.Name)
	}
	return names
}

func TestTheOldPairingStaysOpenUntilEveryoneFollowed(t *testing.T) {
	url := relayServer(t)
	a, b := openPaired(t, url, "alpha-1"), openPaired(t, url, "alpha-2")
	pairUp(t, a, b)
	n := moveIn(t, url, a, nil)

	if n.f.Settle(a.g) {
		t.Fatal("the old pairing closes while alpha-2 has not followed")
	}
	backdate(t, url, a, moveWindow-time.Hour)
	if n.f.Settle(a.g) {
		t.Error("the old pairing closes before the window is over")
	}

	waitFor(t, "alpha-1 to reach alpha-2 again", func() bool { m, _ := pairedWith(a.g, b.id); return m.Online() })
	if took := Move(ctx(t), a.g, testSecret); !slices.Equal(took, []string{b.id}) {
		t.Fatalf("Move reached %v", took)
	}
	if err := b.g.Close(); err != nil {
		t.Fatal(err)
	}
	moveIn(t, url, b, nil)
	waitFor(t, "the old pairing to close once alpha-2 followed", func() bool { return n.f.Settle(a.g) })
	if behind := n.f.Behind(); len(behind) != 0 {
		t.Errorf("left behind %v, though everyone followed", behind)
	}
}

func TestTheOldPairingClosesWhenTheWindowIsOverAndKeepsWhoStayedBehind(t *testing.T) {
	url := relayServer(t)
	a, b := openPaired(t, url, "alpha-1"), openPaired(t, url, "alpha-2")
	pairUp(t, a, b)
	_, pid := approvePhone(t, url, a, "phone")
	n := moveIn(t, url, a, nil)

	if n.f.Settle(a.g) {
		t.Fatal("the old pairing closes at once")
	}
	if behind := n.f.Behind(); len(behind) != 0 {
		t.Errorf("left behind %v before the window is over", behind)
	}
	backdate(t, url, a, moveWindow+time.Minute)
	if !n.f.Settle(a.g) {
		t.Fatal("the old pairing stays open after the window")
	}
	if got := behindOf(n.f); !slices.Equal(got, []string{"alpha-2", "phone"}) {
		t.Fatalf("left behind %v, want alpha-2 and the phone", got)
	}
	if err := a.g.Close(); err != nil {
		t.Fatal(err)
	}

	if err := n.f.Close(); err != nil {
		t.Fatal(err)
	}
	n.f = reopen(t, n, setup{relay: url, previous: oldSecret})
	if got := behindOf(n.f); !slices.Equal(got, []string{"alpha-2", "phone"}) {
		t.Fatalf("left behind after a restart %v, want alpha-2 and the phone", got)
	}

	// The owner enters the fortress phrase on alpha-2, which comes along
	// under its own key, and takes the phone out.
	if err := b.g.Close(); err != nil {
		t.Fatal(err)
	}
	moveIn(t, url, b, nil)
	waitFor(t, "alpha-2 to come along", func() bool { return slices.Equal(behindOf(n.f), []string{"phone"}) })
	if err := n.f.Remove(pid.ID()); err != nil {
		t.Fatal(err)
	}
	if behind := n.f.Behind(); len(behind) != 0 {
		t.Errorf("left behind %v after the phone was taken out", behind)
	}
	if m, _ := pairedWith(n.f.Pairing(), b.id); m.State != group.StateApproved {
		t.Errorf("alpha-2 is %q in the pairing", m.State)
	}
}
