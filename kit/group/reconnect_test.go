package group

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/lan"
	"github.com/junkerderprovinz/parleyport/kit/relay"
)

// A member that is opened again, as an app does to change its pairing, is
// off the relay for a moment and answers at its address like an instance in
// no group. A call made in that moment reaches it once it is back.
func TestACallReachesAMemberThatIsOpenedAgain(t *testing.T) {
	for _, tc := range []struct {
		name   string
		direct bool
	}{
		{"on the relay", false},
		{"at its address too", true},
	} {
		direct := tc.direct
		t.Run(tc.name, func(t *testing.T) {
			url := relayServer(t)
			la := lan.New(lan.Config{})
			t.Cleanup(func() { _ = la.Close() })
			a := open(t, "alpha", setup{relay: url, lan: la})
			b := open(t, "bravo", setup{relay: url, noListener: !direct})
			waitFor(t, "alpha to see bravo", func() bool { m, _ := memberOf(a.g, b.id); return m.Relay })
			if direct {
				la.Observe(tagged(a.g, lan.Peer{ID: b.id, Name: "bravo", URL: b.srv.URL}))
			}
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
			b.g = openGroup(t, b, setup{relay: url, noListener: !direct})
			b.current.Store(b.g)

			if r := <-got; r.err != nil || r.status != http.StatusOK {
				t.Errorf("alpha's call while bravo was away = %d %v, want 200 once bravo is back", r.status, r.err)
			}
		})
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

// A member that reconnects while it serves a call never sends the answer.
// The call may have done its work there, so only a call that changes
// nothing is made again.
func TestACallCutOffAfterItReachedTheMemberIsMadeAgainOnlyIfItChangesNothing(t *testing.T) {
	for _, tc := range []struct {
		method string
		want   int32
	}{
		{http.MethodPost, 1},
		{http.MethodGet, 2},
	} {
		t.Run(tc.method, func(t *testing.T) {
			var served atomic.Int32
			var bravo atomic.Pointer[Group]
			app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if served.Add(1) == 1 {
					bravo.Load().SetSelf(Self{Name: "bravo", Deployment: "container"})
				}
				w.WriteHeader(http.StatusNoContent)
			})
			url := relayServer(t)
			a := open(t, "alpha", setup{relay: url})
			b := open(t, "bravo", setup{relay: url, noListener: true, app: app})
			bravo.Store(b.g)
			waitFor(t, "alpha to see bravo", func() bool { m, _ := memberOf(a.g, b.id); return m.Relay })
			meet(t, a, b)

			status, _, err := call(t, a, b, tc.method, "/api/job", nil)
			if got := served.Load(); got != tc.want {
				t.Errorf("bravo served the %s %d times, want %d", tc.method, got, tc.want)
			}
			switch {
			case tc.want == 1 && !errors.Is(err, relay.ErrCutOff):
				t.Errorf("call = %d %v, want relay.ErrCutOff", status, err)
			case tc.want == 2 && (err != nil || status != http.StatusNoContent):
				t.Errorf("call = %d %v, want 204", status, err)
			}
		})
	}
}
