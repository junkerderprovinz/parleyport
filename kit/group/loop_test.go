package group

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/lan"
)

// reports is where an instance's OnChange calls arrive.
type reports chan struct{}

func newReports() reports { return make(reports, 64) }

func (r reports) report() {
	select {
	case r <- struct{}{}:
	default:
	}
}

// after waits a moment for whatever is still on its way, forgets it, does
// what and expects it reported within limit.
func (r reports) after(t *testing.T, what string, limit time.Duration, do func()) {
	t.Helper()
	time.Sleep(200 * time.Millisecond)
	r.drain()
	do()
	select {
	case <-r:
	case <-time.After(limit):
		t.Fatalf("no change reported after %s", what)
	}
}

func (r reports) drain() {
	for {
		select {
		case <-r:
		default:
			return
		}
	}
}

func TestChangesAreReported(t *testing.T) {
	url := relayServer(t)
	r := newReports()
	a := open(t, "alpha", setup{relay: url, onChange: r.report})
	var b *node
	r.after(t, "bravo comes", 10*time.Second, func() { b = open(t, "bravo", setup{relay: url}) })
	waitFor(t, "alpha to list bravo waiting", func() bool { m, _ := memberOf(a.g, b.id); return m.State == StatePending })

	r.after(t, "alpha approves bravo", 2*time.Second, func() {
		if err := a.g.Approve(b.id); err != nil {
			t.Fatal(err)
		}
	})
	r.after(t, "bravo goes", 5*time.Second, func() { _ = b.g.Close() })
	if m, _ := memberOf(a.g, b.id); m.Online() {
		t.Errorf("alpha lists %+v, want bravo away", m)
	}
	r.after(t, "alpha takes bravo out", 2*time.Second, func() {
		if err := a.g.Remove(b.id); err != nil {
			t.Fatal(err)
		}
	})
}

func TestCallsThatChangeNothingAreNotReported(t *testing.T) {
	url := relayServer(t)
	r := newReports()
	a := open(t, "alpha", setup{relay: url, onChange: r.report})
	b := open(t, "bravo", setup{relay: url})
	waitFor(t, "both on the relay", func() bool { return len(a.g.Members()) == 1 && len(b.g.Members()) == 1 })
	meet(t, a, b)
	whoami(t, a, b)
	whoami(t, b, a)
	time.Sleep(300 * time.Millisecond)
	r.drain()

	for range 5 {
		whoami(t, a, b)
		whoami(t, b, a)
	}
	time.Sleep(500 * time.Millisecond)
	select {
	case <-r:
		t.Error("calls between two approved members were reported as a change")
	default:
	}
}

func TestArrivalsAreKeptWithinBounds(t *testing.T) {
	la := lan.New(lan.Config{})
	t.Cleanup(func() { _ = la.Close() })
	a := open(t, "alpha", setup{lan: la})
	for i := range 1000 {
		id := fmt.Sprintf("%040x", i+1)
		la.Observe(tagged(a.g, lan.Peer{ID: id, URL: "http://192.168.1.2:1"}))
	}
	a.g.mu.Lock()
	n := len(a.g.arrived)
	a.g.mu.Unlock()
	if n > maxArrivals {
		t.Errorf("alpha keeps %d arrivals, want at most %d", n, maxArrivals)
	}
}

func TestAnInstanceArrivingOnTheNetworkIsGreetedAtOnce(t *testing.T) {
	la, lb := lan.New(lan.Config{}), lan.New(lan.Config{})
	t.Cleanup(func() { _ = la.Close(); _ = lb.Close() })
	a := open(t, "alpha", setup{lan: la})
	b := open(t, "bravo", setup{lan: lb})
	// Both had their first look around when they opened.
	time.Sleep(300 * time.Millisecond)

	la.Observe(tagged(a.g, lan.Peer{ID: b.id, Name: "bravo", URL: b.srv.URL, Deployment: "container"}))
	deadline := time.Now().Add(5 * time.Second)
	for {
		if m, _ := memberOf(b.g, a.id); m.State == StatePending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("alpha did not greet bravo until its next tick")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if status, _, _ := call(t, a, b, http.MethodGet, "/api/whoami", nil); status != http.StatusForbidden {
		t.Errorf("alpha calls bravo = %d, want bravo's memberPending", status)
	}
}
