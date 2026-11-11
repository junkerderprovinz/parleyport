package fortress

import (
	"bytes"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/group"
	"github.com/junkerderprovinz/parleyport/kit/keys"
	"github.com/junkerderprovinz/parleyport/kit/lan"
)

// paired is an instance of alpha paired with its siblings under the app's own
// phrase, before any fortress: its group, the secret Moving handed it and,
// once it moved, its fortress.
type paired struct {
	name  string
	id    string
	g     *group.Group
	store *memStore
	in    atomic.Pointer[Fortress]

	mu    sync.Mutex
	moved []byte
	// leave is the group the instance closes as soon as it keeps a secret,
	// the way an app hurries into the fortress.
	leave *group.Group
}

func (p *paired) Keep(secret []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.moved = bytes.Clone(secret)
	if p.leave != nil {
		go func(g *group.Group) { _ = g.Close() }(p.leave)
	}
	return nil
}

func (p *paired) leaveOnKeep() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.leave = p.g
}

func (p *paired) given() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return bytes.Clone(p.moved)
}

func openPaired(t *testing.T, url, name string) *paired {
	t.Helper()
	return openPairedOn(t, url, name, nil)
}

// openPairedOn opens a paired instance that also finds its siblings on l.
func openPairedOn(t *testing.T, url, name string, l *lan.Service) *paired {
	t.Helper()
	p := &paired{name: name, id: identity(t, name).ID(), store: &memStore{}}
	g, err := group.Open(group.Config{
		Domain: keys.Domain("alpha"), Secret: oldSecret, Identity: identity(t, name),
		Self: group.Self{Name: name}, Relay: group.RelayOwn, RelayURL: url, Store: p.store, LAN: l,
	}, Moved(Moving(appRoutes(), p), p.in.Load))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	p.g = g
	return p
}

func pairUp(t *testing.T, a, b *paired) {
	t.Helper()
	for _, pair := range [][2]*paired{{a, b}, {b, a}} {
		from, to := pair[0], pair[1]
		waitFor(t, from.name+" to see "+to.name+" ask", func() bool {
			m, _ := pairedWith(from.g, to.id)
			return m.State != ""
		})
		if err := from.g.Approve(to.id); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTheMoveTakesThePairingIntoTheFortress(t *testing.T) {
	url := relayServer(t)
	a, b := openPaired(t, url, "alpha-1"), openPaired(t, url, "alpha-2")
	pairUp(t, a, b)

	moved := Move(ctx(t), a.g, testSecret)
	if !slices.Equal(moved, []string{b.id}) {
		t.Fatalf("Move reached %v, want alpha-2", moved)
	}
	if !bytes.Equal(b.given(), testSecret) {
		t.Fatalf("alpha-2 was given %x", b.given())
	}

	// Each instance now opens the fortress with what it had, the pairing
	// moving from the app's own phrase.
	var nodes []*node
	for _, p := range []*paired{a, b} {
		if err := p.g.Close(); err != nil {
			t.Fatal(err)
		}
		n := &node{name: p.name, app: "alpha", id: p.id, store: &memStore{}, pairStore: p.store}
		cfg := config(t, n, setup{relay: url, previous: oldSecret})
		f, err := Open(cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		n.f = f
		nodes = append(nodes, n)
	}
	n1, n2 := nodes[0], nodes[1]
	waitFor(t, "both approved in the fortress without anybody approving", func() bool {
		m1, _ := memberOf(n1.f, n2.id)
		m2, _ := memberOf(n2.f, n1.id)
		return m1.State == group.StateApproved && m2.State == group.StateApproved
	})
	status, body, err := n1.f.Pairing().Call(ctx(t), n2.id, http.MethodGet, "/api/whoami", nil)
	if err != nil || status != http.StatusOK || string(body) != n1.id {
		t.Errorf("the moved pairing: %d %s %v", status, body, err)
	}
}

func TestMoveCountsAnInstanceThatLeavesTheOldGroupAsItTakesTheSecret(t *testing.T) {
	url := relayServer(t)
	a, b := openPaired(t, url, "alpha-1"), openPaired(t, url, "alpha-2")
	pairUp(t, a, b)
	b.leaveOnKeep()

	if moved := Move(ctx(t), a.g, testSecret); !slices.Equal(moved, []string{b.id}) {
		t.Fatalf("Move reached %v, want alpha-2, which took the secret", moved)
	}
	if !bytes.Equal(b.given(), testSecret) {
		t.Fatalf("alpha-2 was given %x", b.given())
	}
}

func TestOnlyAnApprovedSiblingMovesAnInstance(t *testing.T) {
	url := relayServer(t)
	a, b := openPaired(t, url, "alpha-1"), openPaired(t, url, "alpha-2")
	// alpha-1 approves alpha-2, but alpha-2 never approves alpha-1.
	waitFor(t, "alpha-2 to ask alpha-1", func() bool { m, _ := pairedWith(a.g, b.id); return m.State != "" })
	if err := a.g.Approve(b.id); err != nil {
		t.Fatal(err)
	}
	if moved := Move(ctx(t), a.g, testSecret); len(moved) != 0 {
		t.Errorf("Move reached %v, which never approved alpha-1", moved)
	}
	if b.given() != nil {
		t.Error("alpha-2 took a secret from an instance it never approved")
	}
}
