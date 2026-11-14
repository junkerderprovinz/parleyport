package fortress

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/group"
	"github.com/junkerderprovinz/parleyport/kit/lan"
	"github.com/junkerderprovinz/parleyport/kit/relay"
)

// openPlugin joins name for app with a directory of its own, the way
// cmd/fortress does, and opens the fortress from it. On this network it
// takes direct calls as well.
func openPlugin(t *testing.T, url, app, name string, onLAN bool) (*node, string) {
	t.Helper()
	dir := t.TempDir()
	if err := Join(dir, testSecret, Membership{App: app, Device: name, Relay: url, LAN: onLAN}); err != nil {
		t.Fatal(err)
	}
	n := &node{name: name, app: app}
	n.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f := n.current.Load(); f != nil && r.URL.Path == group.DirectPath {
			f.DirectHandler().ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(n.srv.Close)
	n.f = reopenPlugin(t, n, dir)
	n.id = n.f.self
	return n, dir
}

func reopenPlugin(t *testing.T, n *node, dir string) *Fortress {
	t.Helper()
	cfg, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LAN != nil {
		cfg.Self.DirectURL = n.srv.URL
		cfg.LAN.Start()
		t.Cleanup(func() { _ = cfg.LAN.Close() })
	}
	f, err := Open(cfg)
	if err != nil {
		t.Fatalf("open %s: %v", n.name, err)
	}
	t.Cleanup(func() { _ = f.Close() })
	n.current.Store(f)
	return f
}

// movedAway has a and b change the phrase while s, a plugin, follows it
// through a on its next run and then answers on the new one alone, with a
// and b gone.
func movedAway(t *testing.T, url string, a, b, s *node, dir string) {
	t.Helper()
	changePhrase(t, url, a, b)
	closeAll(t, s)
	s.f = reopenPlugin(t, s, dir)
	waitFor(t, s.name+" to follow", func() bool {
		moved, err := Follow(ctx(t), dir, s.f)
		return moved && err == nil
	})
	closeAll(t, s, a, b)
	s.f = reopenPlugin(t, s, dir)
}

func TestAPluginThatKnowsOnlyPluginsThatMovedIsToldThePhraseChanged(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	s, dir := openPlugin(t, url, "ledger", "tower", false)
	for _, n := range []*node{a, b, s} {
		waitFor(t, n.name+" to see everybody", func() bool { return len(n.f.Members()) == 2 })
	}
	meet(t, a, s)
	// The plugin joins while the instances that hold the phrase are away.
	closeAll(t, a, b)
	p := openKeysOnly(t, url, "guard", "guard-1", Domain.Keys(testSecret))
	meet(t, s, p)
	closeAll(t, p)
	a.f = reopen(t, a, setup{relay: url})
	b.f = reopen(t, b, setup{relay: url})
	waitFor(t, "alpha to see bravo", func() bool { m, _ := memberOf(a.f, b.id); return m.Online() })
	movedAway(t, url, a, b, s, dir)

	p.f = reopenKeysOnly(t, p, url, Domain.Keys(testSecret))
	waitFor(t, "the plugin left behind to hear the phrase changed", func() bool { return p.f.PhraseChanged() })
	p.f.mu.Lock()
	held := p.f.book.Group
	p.f.mu.Unlock()
	if held != Domain.GroupKey(testSecret) {
		t.Error("the plugin left behind moved off its keys")
	}
}

func TestAPluginThatFollowedAnswersTheOldKeysForThirtyDays(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	s, dir := openPlugin(t, url, "ledger", "tower", false)
	for _, n := range []*node{a, b, s} {
		waitFor(t, n.name+" to see everybody", func() bool { return len(n.f.Members()) == 2 })
	}
	movedAway(t, url, a, b, s, dir)
	if s.f.old == nil {
		t.Fatal("the plugin answers nobody on its old keys right after it followed")
	}
	closeAll(t, s)

	path := filepath.Join(dir, membershipFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	before, ok := m["before"].(map[string]any)
	if !ok {
		t.Fatalf("the membership keeps no keys from before: %s", raw)
	}
	before["changed"] = time.Now().Add(-moveWindow - time.Hour)
	if raw, err = json.Marshal(m); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(path, raw); err != nil {
		t.Fatal(err)
	}
	s.f = reopenPlugin(t, s, dir)
	if s.f.old != nil {
		t.Error("the plugin still answers on its old keys 30 days after the change")
	}
}

func TestAPluginStopsAnsweringTheOldKeysWhenTheThirtyDaysEndWhileItRuns(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	s, dir := openPlugin(t, url, "ledger", "tower", false)
	for _, n := range []*node{a, b, s} {
		waitFor(t, n.name+" to see everybody", func() bool { return len(n.f.Members()) == 2 })
	}
	movedAway(t, url, a, b, s, dir)
	c := asker(t, url, a)
	waitFor(t, "the plugin to answer on its old keys", func() bool {
		_, status, _ := c.Proxy(ctx(t), s.id, http.MethodGet, aboutPath, nil)
		return status == http.StatusGone
	})

	s.f.mu.Lock()
	s.f.book.Changed = time.Now().Add(-moveWindow - time.Hour)
	s.f.mu.Unlock()
	waitFor(t, "the plugin to leave its old keys", func() bool { return !seenOn(c, s.id) })
}

func TestAMemberTakenOutReachesNothingOnTheOldKeysOfAPluginThatMoved(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	s, dir := openPlugin(t, url, "ledger", "tower", false)
	w := openKeysOnly(t, url, "watcher", "watcher-1", Domain.Keys(testSecret))
	p := openKeysOnly(t, url, "guard", "guard-1", Domain.Keys(testSecret))
	for _, n := range []*node{a, b, s, w, p} {
		waitFor(t, n.name+" to see everybody", func() bool { return len(n.f.Members()) == 4 })
	}
	meet(t, a, s)
	meet(t, s, w)
	meet(t, s, p)
	closeAll(t, p)
	movedAway(t, url, a, b, s, dir)

	// The watcher asks on the old keys, and is taken out after.
	w.f.again(w.f.described, s.id, time.Time{})
	waitFor(t, "the watcher to hear the phrase changed", w.f.PhraseChanged)
	if err := s.f.Remove(w.id); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]string{"op": "remove", "id": p.id})
	if err != nil {
		t.Fatal(err)
	}
	if status, raw, err := w.f.group.Call(ctx(t), s.id, http.MethodPost, "/kit/group/v1/decision", body); err == nil && status == http.StatusNoContent {
		t.Errorf("the plugin took the word of a member taken out: %d %s", status, raw)
	}
	closeAll(t, w)

	p.f = reopenKeysOnly(t, p, url, Domain.Keys(testSecret))
	waitFor(t, "the guard to hear the phrase changed", p.f.PhraseChanged)
	time.Sleep(3 * time.Second)
	if n := p.removed.Load(); n != 0 {
		t.Errorf("the guard heard %d times that it was taken out, which nobody did", n)
	}
}

func TestOnTheOldKeysAMovedPluginTellsOnlyItsMembersThatThePhraseChanged(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	s, dir := openPlugin(t, url, "ledger", "tower", false)
	p := openKeysOnly(t, url, "guard", "guard-1", Domain.Keys(testSecret))
	out := openKeysOnly(t, url, "watcher", "watcher-out", Domain.Keys(testSecret))
	for _, n := range []*node{a, b, s, p, out} {
		waitFor(t, n.name+" to see everybody", func() bool { return len(n.f.Members()) == 4 })
	}
	meet(t, a, s)
	meet(t, s, p)
	if err := a.f.Remove(out.id); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the plugin to take watcher out", func() bool { _, ok := memberOf(s.f, out.id); return !ok })
	closeAll(t, p, out)
	movedAway(t, url, a, b, s, dir)

	member := asker(t, url, p)
	waitFor(t, "the plugin to answer on its old keys", func() bool {
		_, status, _ := member.Proxy(ctx(t), s.id, http.MethodGet, aboutPath, nil)
		return status != 0 && status != http.StatusBadGateway
	})
	for _, path := range []string{aboutPath, permissionsPath, movedPath, newPhrasePath, actPrefix + "files.drop"} {
		raw, status, err := member.Proxy(ctx(t), s.id, http.MethodGet, path, nil)
		if err != nil || status != http.StatusGone || refusalCode(refusal(status, raw)) != phraseChanged {
			t.Errorf("%s: %d %s %v, want only phrase_changed", path, status, raw, err)
		}
	}
	var listed []relay.Announce
	waitFor(t, "the plugin on the old keys", func() bool {
		listed = member.Siblings()
		return len(listed) > 0
	})
	for _, sib := range listed {
		if sib.InstanceID == s.id && (sib.Name != "" || sib.Deployment != "" || sib.Address != "") {
			t.Errorf("on the old keys the plugin goes by %+v", sib)
		}
	}

	// Neither a member taken out nor a newcomer holding the old keys learns
	// even that much.
	for _, n := range []*node{out, {name: "watcher-new"}} {
		c := asker(t, url, n)
		waitFor(t, "the plugin to answer "+n.name, func() bool {
			_, status, _ := c.Proxy(ctx(t), s.id, http.MethodGet, aboutPath, nil)
			return status != 0 && status != http.StatusBadGateway
		})
		raw, status, _ := c.Proxy(ctx(t), s.id, http.MethodGet, aboutPath, nil)
		if status == http.StatusGone || bytes.Contains(raw, []byte(phraseChanged)) {
			t.Errorf("%s was told %d %s", n.name, status, raw)
		}
	}
}

// changing answers on the old keys as n, a member that says the phrase
// changed to everybody, and counts the calls it gets.
func changing(t *testing.T, url string, n *node) (*relay.Client, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	c := listen(t, url, n, func(context.Context, relay.ProxyCall) (int, []byte) {
		calls.Add(1)
		return http.StatusGone, []byte(`{"error":"phrase_changed"}`)
	})
	return c, &calls
}

func TestOnlyAMemberOfTheBookCanSayThePhraseChanged(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	p := openKeysOnly(t, url, "guard", "guard-1", Domain.Keys(testSecret))
	out := openKeysOnly(t, url, "watcher", "watcher-out", Domain.Keys(testSecret))
	for _, n := range []*node{a, p, out} {
		waitFor(t, n.name+" to see everybody", func() bool { return len(n.f.Members()) == 2 })
	}
	meet(t, p, out)

	_, stray := changing(t, url, &node{name: "stray"})
	waitFor(t, "the plugin to ask a member it never knew", func() bool { return stray.Load() > 0 })
	time.Sleep(2 * time.Second)
	if p.f.PhraseChanged() {
		t.Error("a member the plugin never knew made it ask for new words")
	}

	if err := a.f.Remove(out.id); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the plugin to take watcher out", func() bool { _, ok := memberOf(p.f, out.id); return !ok })
	closeAll(t, out)
	_, removed := changing(t, url, out)
	time.Sleep(2 * time.Second)
	if p.f.PhraseChanged() || removed.Load() > 0 {
		t.Error("a member the plugin knows to be taken out made it ask for new words")
	}
}

func TestBeingToldThePhraseChangedOnlyAsksForTheNewWords(t *testing.T) {
	url := relayServer(t)
	p := openKeysOnly(t, url, "guard", "guard-1", Domain.Keys(testSecret))
	w := openKeysOnly(t, url, "watcher", "watcher-1", Domain.Keys(testSecret))
	meet(t, p, w)
	closeAll(t, w)

	c, _ := changing(t, url, w)
	p.f.again(p.f.described, w.id, time.Time{})
	waitFor(t, "the plugin to hear the phrase changed", func() bool { return p.f.PhraseChanged() })
	if set, err := p.f.NewKeys(ctx(t)); err == nil || set.Complete() {
		t.Errorf("the plugin got keys %+v from a member that only said the phrase changed", set)
	}
	if m, ok := memberOf(p.f, w.id); !ok || m.App.ID != "watcher" {
		t.Errorf("the plugin lists the member as %+v", m)
	}

	// The same member answering as usual on these keys lets it go again.
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	w.f = reopenKeysOnly(t, w, url, Domain.Keys(testSecret))
	waitFor(t, "the plugin to reach the member", func() bool { m, _ := pairedWith(p.f.group, w.id); return m.Online() })
	p.f.again(p.f.described, w.id, time.Time{})
	waitFor(t, "the plugin to let it go", func() bool { return !p.f.PhraseChanged() })

	// A member taken out says nothing that sticks once the plugin hears of it.
	closeAll(t, w)
	changing(t, url, w)
	p.f.again(p.f.described, w.id, time.Time{})
	waitFor(t, "the plugin to hear the phrase changed again", func() bool { return p.f.PhraseChanged() })
	if err := p.f.group.Import(group.Roster{Removed: map[string]time.Time{w.id: time.Now()}}); err != nil {
		t.Fatal(err)
	}
	if p.f.PhraseChanged() {
		t.Error("the word of a member taken out still asks for new words")
	}
}

func TestAnInstanceOnThisNetworkAloneHearsFromAPluginThatMoved(t *testing.T) {
	multicast(t)
	was := Multicast
	Multicast = netip.AddrPortFrom(netip.MustParseAddr("239.255.77.251"), freePort(t))
	t.Cleanup(func() { Multicast = was })
	network := func() *lan.Service {
		l := lan.New(lan.Config{Group: Multicast})
		l.Start()
		t.Cleanup(func() { _ = l.Close() })
		return l
	}
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{lan: network(), noPair: true})
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	c := open(t, "charlie", "charlie-1", setup{relay: url})
	s, dir := openPlugin(t, url, "ledger", "tower", true)
	waitFor(t, "alpha to reach the plugin on this network", func() bool { m, _ := memberOf(a.f, s.id); return m.Direct })
	meet(t, a, s)
	meet(t, b, s)
	closeAll(t, a)
	movedAway(t, url, b, c, s, dir)

	a.f = reopen(t, a, setup{lan: network(), noPair: true})
	waitFor(t, "alpha to hear the phrase changed", func() bool { return a.f.PhraseChanged() })
	if m, _ := memberOf(a.f, s.id); m.Online() {
		t.Errorf("alpha lists the plugin that moved as %+v", m)
	}

	// On this network as on the relay, a newcomer with the old phrase is not
	// told even that.
	d := open(t, "delta", "delta-1", setup{lan: network(), noPair: true})
	waitFor(t, "the plugin to answer delta", func() bool {
		status, body, err := d.f.group.Call(ctx(t), s.id, http.MethodGet, aboutPath, nil)
		if status == http.StatusGone || bytes.Contains(body, []byte(phraseChanged)) {
			t.Fatalf("delta was told %d %s", status, body)
		}
		return err == nil || !errors.Is(err, group.ErrUnreachable) && !errors.Is(err, group.ErrNoSuchMember)
	})
	if d.f.PhraseChanged() {
		t.Error("delta, new on the old phrase, asks for the new words")
	}
}
