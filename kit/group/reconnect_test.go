package group

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

// A member that is opened again, as an app does to change its pairing, is
// off the relay for a moment. A call made in that moment reaches it once it
// is back.
func TestACallReachesAMemberThatIsOpenedAgain(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", setup{relay: url})
	b := open(t, "bravo", setup{relay: url, noListener: true})
	waitFor(t, "alpha to see bravo", func() bool { m, _ := memberOf(a.g, b.id); return m.Relay })
	meet(t, a, b)

	_ = b.g.Close()
	waitFor(t, "alpha to see bravo leave", func() bool { m, _ := memberOf(a.g, b.id); return !m.Relay })
	type answer struct {
		status int
		err    error
	}
	got := make(chan answer, 1)
	go func() {
		status, _, err := call(t, a, b, http.MethodGet, "/api/whoami", nil)
		got <- answer{status, err}
	}()
	time.Sleep(500 * time.Millisecond)
	b.g = openGroup(t, b, setup{relay: url, noListener: true})

	if r := <-got; r.err != nil || r.status != http.StatusOK {
		t.Errorf("alpha's call while bravo was away = %d %v, want 200 once bravo is back", r.status, r.err)
	}
}

func TestACallToAMemberThatStaysAwayGivesUpWithinTheCallersTime(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", setup{relay: url})
	b := open(t, "bravo", setup{relay: url, noListener: true})
	waitFor(t, "alpha to see bravo", func() bool { m, _ := memberOf(a.g, b.id); return m.Relay })
	meet(t, a, b)
	_ = b.g.Close()
	waitFor(t, "alpha to see bravo leave", func() bool { m, _ := memberOf(a.g, b.id); return !m.Relay })

	for _, wait := range []time.Duration{300 * time.Millisecond, 10 * time.Second} {
		ctx, cancel := context.WithTimeout(context.Background(), wait)
		began := time.Now()
		_, _, err := a.g.Call(ctx, b.id, http.MethodGet, "/api/whoami", nil)
		took := time.Since(began)
		cancel()
		if !errors.Is(err, ErrUnreachable) {
			t.Errorf("call with %v = %v, want ErrUnreachable", wait, err)
		}
		if limit := min(wait, reconnectSettle) + time.Second; took > limit {
			t.Errorf("call with %v took %v, want at most %v", wait, took, limit)
		}
	}
}

// A member that changes its announce leaves the relay and joins it again.
// A call right after the change reaches it.
func TestACallReachesAMemberThatChangedItsAnnounce(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", setup{relay: url})
	b := open(t, "bravo", setup{relay: url, noListener: true})
	waitFor(t, "alpha to see bravo", func() bool { m, _ := memberOf(a.g, b.id); return m.Relay })
	meet(t, a, b)

	for _, name := range []string{"Cellar", "Attic"} {
		b.g.SetSelf(Self{Name: name, Deployment: "container"})
		status, _, err := call(t, a, b, http.MethodGet, "/api/whoami", nil)
		if err != nil || status != http.StatusOK {
			t.Errorf("alpha's call right after bravo became %s = %d %v, want 200", name, status, err)
		}
	}
}
