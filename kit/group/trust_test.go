package group

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/member"
	"github.com/junkerderprovinz/parleyport/kit/relay"
)

// onRelay opens one instance per name on a fresh relay and waits until each
// sees all others.
func onRelay(t *testing.T, names ...string) []*node {
	t.Helper()
	url := relayServer(t)
	nodes := make([]*node, len(names))
	for i, name := range names {
		nodes[i] = open(t, name, setup{relay: url})
	}
	for _, n := range nodes {
		waitFor(t, n.name+" to see everybody", func() bool {
			seen := 0
			for _, m := range n.g.Members() {
				if m.Relay {
					seen++
				}
			}
			return seen == len(nodes)-1
		})
	}
	return nodes
}

func TestAFirstCallWaitsForApproval(t *testing.T) {
	n := onRelay(t, "alpha", "bravo")
	a, b := n[0], n[1]

	status, body, err := call(t, a, b, http.MethodGet, "/api/whoami", nil)
	var untrusted *relay.UntrustedAnswer
	if !errors.As(err, &untrusted) || untrusted.Status != http.StatusForbidden || !bytes.Contains(untrusted.Body, []byte(`"memberPending"`)) {
		t.Fatalf("first call = %d %s %v, want bravo's memberPending", status, body, err)
	}

	got, _ := memberOf(b.g, a.id)
	if got.State != StatePending || !bytes.Equal(got.Key, identity(t, "alpha").Public()) {
		t.Errorf("bravo lists %+v, want alpha pending under its key", got)
	}
	if mine, _ := memberOf(a.g, b.id); !mine.Awaiting || mine.State == StateApproved {
		t.Errorf("alpha lists %+v, want alpha waiting at bravo and bravo not approved here", mine)
	}

	if err := b.g.Approve(a.id); err != nil {
		t.Fatal(err)
	}
	if err := a.g.Approve(identity(t, "nobody").ID()); !errors.Is(err, ErrNoSuchMember) {
		t.Errorf("approving a member that never called = %v, want ErrNoSuchMember", err)
	}
	_, _, _ = call(t, b, a, http.MethodGet, "/api/whoami", nil)
	if err := a.g.Approve(b.id); err != nil {
		t.Fatal(err)
	}
	if id := whoami(t, a, b); id != a.id {
		t.Errorf("bravo's app saw %q, want alpha", id)
	}
	if mine, _ := memberOf(a.g, b.id); mine.Awaiting || mine.State != StateApproved {
		t.Errorf("alpha lists %+v, want bravo approved and nothing waiting", mine)
	}
}

func TestInstancesThatMeetGreetEachOther(t *testing.T) {
	n := onRelay(t, "alpha", "bravo")
	a, b := n[0], n[1]
	waitFor(t, "both to wait for approval on each other", func() bool {
		ma, _ := memberOf(a.g, b.id)
		mb, _ := memberOf(b.g, a.id)
		return ma.State == StatePending && mb.State == StatePending && ma.Awaiting && mb.Awaiting
	})
}

func TestApprovalIsPassedOn(t *testing.T) {
	n := onRelay(t, "alpha", "bravo", "charlie", "delta")
	a, b, c, d := n[0], n[1], n[2], n[3]
	meet(t, a, b)
	meet(t, a, c)
	meet(t, b, c)

	_, _, _ = call(t, d, a, http.MethodGet, "/api/whoami", nil)
	if err := a.g.Approve(d.id); err != nil {
		t.Fatal(err)
	}
	for _, other := range []*node{b, c} {
		waitFor(t, other.name+" to approve delta too", func() bool {
			m, _ := memberOf(other.g, d.id)
			return m.State == StateApproved && bytes.Equal(m.Key, identity(t, "delta").Public())
		})
	}
	// delta never called bravo, and bravo serves it all the same.
	_, _, err := call(t, d, b, http.MethodGet, "/api/whoami", nil)
	var untrusted *relay.UntrustedAnswer
	if !errors.As(err, &untrusted) || untrusted.Status != http.StatusOK {
		t.Errorf("delta calls bravo: %v, want bravo's 200", err)
	}
}

func TestOnlyAnApprovedInstanceDecides(t *testing.T) {
	n := onRelay(t, "alpha", "bravo", "mallory")
	a, b, m := n[0], n[1], n[2]
	meet(t, a, b)
	_, _, _ = call(t, m, a, http.MethodGet, "/api/whoami", nil)

	// mallory holds the phrase but nobody approved it.
	body := []byte(`{"op":"remove","id":"` + b.id + `"}`)
	_, _, _ = call(t, m, a, http.MethodPost, decisionPath, body)
	if got, _ := memberOf(a.g, b.id); got.State != StateApproved {
		t.Errorf("alpha lists %+v after mallory's word, want bravo still approved", got)
	}
}

func TestRemovalRevokesTheKeyEverywhere(t *testing.T) {
	n := onRelay(t, "alpha", "bravo", "charlie")
	a, b, c := n[0], n[1], n[2]
	meet(t, a, b)
	meet(t, a, c)
	meet(t, b, c)

	if err := a.g.Remove(c.id); err != nil {
		t.Fatal(err)
	}
	if _, listed := memberOf(a.g, c.id); listed {
		t.Error("alpha still lists charlie")
	}
	waitFor(t, "charlie to hear it", func() bool { return c.removed.Load() > 0 })
	waitFor(t, "bravo to take charlie out", func() bool { _, listed := memberOf(b.g, c.id); return !listed })

	// charlie still trusts both, so their word reaches it as an answer.
	for _, n := range []*node{a, b} {
		status, body, err := call(t, c, n, http.MethodGet, "/api/whoami", nil)
		if err != nil || status != http.StatusGone || string(body) != "removed" {
			t.Errorf("charlie calls %s: %d %q %v, want 410 removed", n.name, status, body, err)
		}
	}
	if err := b.g.Approve(c.id); !errors.Is(err, ErrRemoved) {
		t.Errorf("approving charlie again = %v, want ErrRemoved", err)
	}
}

func TestRemovingAPendingMemberRefusesIt(t *testing.T) {
	n := onRelay(t, "alpha", "bravo")
	a, b := n[0], n[1]
	_, _, _ = call(t, b, a, http.MethodGet, "/api/whoami", nil)
	if err := a.g.Remove(b.id); err != nil {
		t.Fatal(err)
	}
	_, _, err := call(t, b, a, http.MethodGet, "/api/whoami", nil)
	var untrusted *relay.UntrustedAnswer
	if !errors.As(err, &untrusted) || untrusted.Status != http.StatusGone {
		t.Errorf("bravo calls again: %v, want 410", err)
	}
}

func TestAwayMembersCatchUpFromTheRoster(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", setup{relay: url})
	b := open(t, "bravo", setup{relay: url})
	c := open(t, "charlie", setup{relay: url})
	d := open(t, "delta", setup{relay: url})
	waitFor(t, "everybody on the relay", func() bool { return len(a.g.Members()) == 3 })
	meet(t, a, b)
	meet(t, a, c)
	meet(t, b, c)

	// bravo is away while alpha approves delta and removes charlie.
	if err := b.g.Close(); err != nil {
		t.Fatal(err)
	}
	_, _, _ = call(t, d, a, http.MethodGet, "/api/whoami", nil)
	if err := a.g.Approve(d.id); err != nil {
		t.Fatal(err)
	}
	if err := a.g.Remove(c.id); err != nil {
		t.Fatal(err)
	}

	b.g = openGroup(t, b, setup{relay: url, store: b.store})
	waitFor(t, "bravo to catch up from alpha's roster", func() bool {
		md, _ := memberOf(b.g, d.id)
		_, charlie := memberOf(b.g, c.id)
		return md.State == StateApproved && !charlie
	})
}

func TestApprovalsSurviveAReopen(t *testing.T) {
	n := onRelay(t, "alpha", "bravo")
	a, b := n[0], n[1]
	meet(t, a, b)
	if err := b.g.Close(); err != nil {
		t.Fatal(err)
	}
	b.g = openGroup(t, b, setup{store: b.store})
	m, listed := memberOf(b.g, a.id)
	if !listed || m.State != StateApproved || m.Relay || m.Direct || m.Name != "alpha" {
		t.Errorf("bravo lists %+v after a restart, want alpha approved and away", m)
	}
}

func TestANewPhraseStartsTheGroupOver(t *testing.T) {
	n := onRelay(t, "alpha", "bravo")
	a, b := n[0], n[1]
	meet(t, a, b)
	if err := b.g.Close(); err != nil {
		t.Fatal(err)
	}
	b.g = openGroup(t, b, setup{store: b.store, secret: []byte("another phrase..")})
	if _, listed := memberOf(b.g, a.id); listed {
		t.Error("bravo still lists alpha under a phrase alpha never entered")
	}
}

func TestAMovedGroupKeepsItsApprovals(t *testing.T) {
	n := onRelay(t, "alpha", "bravo", "charlie")
	a, b, c := n[0], n[1], n[2]
	meet(t, a, b)
	_, _, _ = call(t, c, a, http.MethodGet, "/api/whoami", nil)
	if err := a.g.Remove(c.id); err != nil {
		t.Fatal(err)
	}
	if err := a.g.Close(); err != nil {
		t.Fatal(err)
	}
	moved := []byte("the fortress one")
	a.g = openGroup(t, a, setup{store: a.store, secret: moved, previous: testSecret})
	if m, _ := memberOf(a.g, b.id); m.State != StateApproved {
		t.Errorf("alpha lists bravo as %q after the move, want approved", m.State)
	}
	if _, listed := memberOf(a.g, c.id); listed {
		t.Error("alpha lists charlie again, whom it took out before the move")
	}

	// The move is kept: opened once more under the new phrase alone, alpha
	// still knows bravo.
	if err := a.g.Close(); err != nil {
		t.Fatal(err)
	}
	a.g = openGroup(t, a, setup{store: a.store, secret: moved})
	if m, _ := memberOf(a.g, b.id); m.State != StateApproved {
		t.Errorf("alpha lists bravo as %q on the next start, want approved", m.State)
	}
}

func TestAPreviousPhraseThatDoesNotMatchStartsOver(t *testing.T) {
	n := onRelay(t, "alpha", "bravo")
	a, b := n[0], n[1]
	meet(t, a, b)
	if err := a.g.Close(); err != nil {
		t.Fatal(err)
	}
	a.g = openGroup(t, a, setup{store: a.store, secret: []byte("the fortress one"), previous: []byte("not the old one.")})
	if _, listed := memberOf(a.g, b.id); listed {
		t.Error("alpha kept bravo, approved under a phrase that was not the previous one")
	}
}

func TestOthersTakenOutAreReported(t *testing.T) {
	url := relayServer(t)
	var mu sync.Mutex
	heard := map[string][]string{}
	report := func(who string) func(string) {
		return func(id string) {
			mu.Lock()
			defer mu.Unlock()
			heard[who] = append(heard[who], id)
		}
	}
	a := open(t, "alpha", setup{relay: url, onRemove: report("alpha")})
	b := open(t, "bravo", setup{relay: url, onRemove: report("bravo")})
	c := open(t, "charlie", setup{relay: url, onRemove: report("charlie")})
	waitFor(t, "everybody on the relay", func() bool { return len(a.g.Members()) == 2 && len(b.g.Members()) == 2 })
	meet(t, a, b)
	meet(t, a, c)
	meet(t, b, c)

	if err := a.g.Remove(c.id); err != nil {
		t.Fatal(err)
	}
	if err := a.g.Remove(c.id); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bravo to take charlie out", func() bool { _, listed := memberOf(b.g, c.id); return !listed })
	waitFor(t, "charlie to hear it", func() bool { return c.removed.Load() > 0 })

	mu.Lock()
	defer mu.Unlock()
	for who, want := range map[string][]string{"alpha": {c.id}, "bravo": {c.id}, "charlie": nil} {
		if got := heard[who]; !slices.Equal(got, want) {
			t.Errorf("%s heard of %v, want %v", who, got, want)
		}
	}
}

func TestAPinThatCannotBeStoredIsRefused(t *testing.T) {
	url := relayServer(t)
	full := &memStore{fail: true}
	a := open(t, "alpha", setup{relay: url})
	b := open(t, "bravo", setup{relay: url, store: full})
	waitFor(t, "alpha to see bravo", func() bool { _, ok := memberOf(a.g, b.id); return ok })
	_, _, err := call(t, a, b, http.MethodGet, "/api/whoami", nil)
	var untrusted *relay.UntrustedAnswer
	if !errors.As(err, &untrusted) || !bytes.Contains(untrusted.Body, []byte("memberNotPinned")) {
		t.Errorf("err = %v, want memberNotPinned", err)
	}
	if m, _ := memberOf(b.g, a.id); m.State != StateUnknown || m.Key != nil {
		t.Errorf("bravo lists %+v, want alpha without a key, which was never stored", m)
	}
}

// signed is a call to target made by a member with the given seed, signed and
// stamped now, as the guard sees it once it opened.
func signed(t *testing.T, seed, target, path string) relay.ProxyCall {
	t.Helper()
	id := identity(t, seed)
	return relay.SignCall(testDomain.Signing(), &id, "req-"+seed, target, relay.ProxyCall{Method: http.MethodGet, Path: path})
}

func TestTheGuardRefusesWhatNoMemberSends(t *testing.T) {
	a := open(t, "alpha", setup{})
	now := time.Now()
	stale := signed(t, "old", a.id, "/api/whoami")
	stale.Sent = now.Add(-time.Hour).Unix()
	unsigned := relay.ProxyCall{ID: "u", Sent: now.Unix(), Method: http.MethodGet, Path: "/api/whoami"}
	unnamed := signed(t, "anon", a.id, "/api/whoami")
	unnamed.From = ""
	wrongKind := signed(t, "kind", a.id, "/api/whoami")
	wrongKind.Kind = member.KindMobile

	for name, c := range map[string]struct {
		call   relay.ProxyCall
		status int
		code   string
	}{
		"stale":      {stale, relay.StatusDrop, ""},
		"unsigned":   {unsigned, http.StatusForbidden, "memberUnsigned"},
		"unnamed":    {unnamed, http.StatusForbidden, "memberUnnamed"},
		"wrong kind": {wrongKind, http.StatusForbidden, "memberKind"},
	} {
		t.Run(name, func(t *testing.T) {
			status, body := a.g.handle(context.Background(), c.call)
			if status != c.status || !strings.Contains(string(body), c.code) {
				t.Errorf("= %d %s, want %d %s", status, body, c.status, c.code)
			}
		})
	}
}

func TestAReplayedCallIsDropped(t *testing.T) {
	a := open(t, "alpha", setup{})
	c := signed(t, "bravo", a.id, "/api/whoami")
	if status, _ := a.g.handle(context.Background(), c); status != http.StatusForbidden {
		t.Fatalf("first call = %d, want pending", status)
	}
	if err := a.g.Approve(identity(t, "bravo").ID()); err != nil {
		t.Fatal(err)
	}
	if status, _ := a.g.handle(context.Background(), c); status != relay.StatusDrop {
		t.Errorf("the same call again = %d, want it dropped", status)
	}
}

func TestStrangersCannotCrowdOutTheGroup(t *testing.T) {
	a := open(t, "alpha", setup{})
	ctx := context.Background()
	for i := range maxWaiting + 4 {
		// One source each, so only the waiting list stops them.
		c := signed(t, "stranger"+string(rune('a'+i)), a.id, "/api/whoami")
		_, _ = a.g.handle(relay.WithSource(ctx, "relay\x00"+string(rune('a'+i))), c)
	}
	status, body := a.g.handle(relay.WithSource(ctx, "relay\x00late"), signed(t, "late", a.id, "/api/whoami"))
	if status != http.StatusTooManyRequests || !strings.Contains(string(body), "groupFull") {
		t.Errorf("one more = %d %s, want groupFull", status, body)
	}
	pending := 0
	for _, m := range a.g.Members() {
		if m.State == StatePending {
			pending++
		}
	}
	if pending != maxWaiting {
		t.Errorf("%d pending, want %d", pending, maxWaiting)
	}
}

func TestOneSourceCannotPinManyKeys(t *testing.T) {
	a := open(t, "alpha", setup{})
	ctx := relay.WithSource(context.Background(), "direct\x00192.168.1.66")
	for _, seed := range []string{"k1", "k2"} {
		_, _ = a.g.handle(ctx, signed(t, seed, a.id, "/api/whoami"))
	}
	status, body := a.g.handle(ctx, signed(t, "k3", a.id, "/api/whoami"))
	if status != http.StatusTooManyRequests || !strings.Contains(string(body), "groupJoinsBusy") {
		t.Errorf("a third key from one source = %d %s, want groupJoinsBusy", status, body)
	}
}

func TestAnApprovedPhoneDoesNotDecideForTheGroup(t *testing.T) {
	n := onRelay(t, "alpha", "bravo")
	a, b := n[0], n[1]
	meet(t, a, b)

	seed := make([]byte, 32)
	phone, err := member.FromSeed(member.KindMobile, seed)
	if err != nil {
		t.Fatal(err)
	}
	ask := func(id, path string, body []byte) relay.ProxyCall {
		return relay.SignCall(testDomain.Signing(), &phone, id, a.id, relay.ProxyCall{Method: http.MethodPost, Path: path, Body: body})
	}
	_, _ = a.g.handle(context.Background(), ask("p1", "/api/whoami", nil))
	if err := a.g.Approve(phone.ID()); err != nil {
		t.Fatal(err)
	}
	status, _ := a.g.handle(context.Background(), ask("p2", decisionPath, []byte(`{"op":"remove","id":"`+b.id+`"}`)))
	if status != http.StatusNotFound {
		t.Errorf("a phone's decision = %d, want 404", status)
	}
	if m, _ := memberOf(a.g, b.id); m.State != StateApproved {
		t.Errorf("alpha lists %+v after the phone's word, want bravo still approved", m)
	}
}

func TestAViewerIsPinnedApprovedAndRemovedLikeAnyMember(t *testing.T) {
	a := open(t, "alpha", setup{})
	viewer, err := member.FromSeed(member.KindViewer, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	ask := func(id string) relay.ProxyCall {
		return relay.SignCall(testDomain.Signing(), &viewer, id, a.id, relay.ProxyCall{Method: http.MethodGet, Path: "/api/whoami"})
	}
	_, _ = a.g.handle(context.Background(), ask("v1"))
	if m, _ := memberOf(a.g, viewer.ID()); m.Kind != member.KindViewer || m.State != StatePending {
		t.Fatalf("alpha lists %+v, want the viewer waiting", m)
	}
	if err := a.g.Approve(viewer.ID()); err != nil {
		t.Fatal(err)
	}
	if status, body := a.g.handle(context.Background(), ask("v2")); status != http.StatusOK || !strings.Contains(string(body), "viewer") {
		t.Errorf("the approved viewer reads = %d %s", status, body)
	}
	if err := a.g.Remove(viewer.ID()); err != nil {
		t.Fatalf("removing the viewer: %v", err)
	}
	if status, _ := a.g.handle(context.Background(), ask("v3")); status != http.StatusGone {
		t.Errorf("the removed viewer reads = %d, want 410", status)
	}
}
