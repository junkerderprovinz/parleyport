package fortress

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/group"
	"github.com/junkerderprovinz/parleyport/kit/keys"
)

// openKeysOnly starts name as a member of app that holds only the keys set,
// as a plugin does, with no pairing and nowhere to keep a phrase.
func openKeysOnly(t *testing.T, url, app, name string, set keys.Set) *node {
	t.Helper()
	n := &node{name: name, app: app, id: identity(t, name).ID(), store: &memStore{}}
	n.f = reopenKeysOnly(t, n, url, set)
	return n
}

func reopenKeysOnly(t *testing.T, n *node, url string, set keys.Set) *Fortress {
	t.Helper()
	cfg := config(t, n, setup{relay: url, noPair: true})
	cfg.Secret, cfg.Keys, cfg.Keeper = nil, set, nil
	f, err := Open(cfg)
	if err != nil {
		t.Fatalf("open %s: %v", n.name, err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// changePhrase has a change the phrase, which b takes as well, and opens both
// again under the new one. It returns the new secret.
func changePhrase(t *testing.T, url string, a, b *node) []byte {
	t.Helper()
	if _, err := a.f.ChangePhrase(ctx(t)); err != nil {
		t.Fatal(err)
	}
	secret := a.lastKept()
	if !bytes.Equal(b.lastKept(), secret) {
		t.Fatal("bravo did not take the new phrase")
	}
	for _, n := range []*node{a, b} {
		if err := n.f.Close(); err != nil {
			t.Fatal(err)
		}
		n.f = reopen(t, n, setup{relay: url, secret: secret, moved: testSecret})
	}
	return secret
}

// newKeys waits until n learns that a member took a new phrase and fetches
// the keys from it.
func newKeys(t *testing.T, n *node) (keys.Set, error) {
	t.Helper()
	var set keys.Set
	err := ErrNoNewPhrase
	deadline := time.Now().Add(10 * time.Second)
	for errors.Is(err, ErrNoNewPhrase) && time.Now().Before(deadline) {
		set, err = n.f.NewKeys(ctx(t))
		time.Sleep(20 * time.Millisecond)
	}
	return set, err
}

func TestAMemberWithKeysAloneFollowsANewPhraseAsItself(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	p := openKeysOnly(t, url, "watcher", "watcher-1", Domain.Keys(testSecret))
	for _, n := range []*node{a, b, p} {
		waitFor(t, n.name+" to see everybody", func() bool { return len(n.f.Members()) == 2 })
	}
	meet(t, a, p)
	if _, err := p.f.NewKeys(ctx(t)); !errors.Is(err, ErrNoNewPhrase) {
		t.Errorf("before any change NewKeys = %v, want ErrNoNewPhrase", err)
	}
	// The plugin runs now and then, and is away while the phrase changes.
	if err := p.f.Close(); err != nil {
		t.Fatal(err)
	}
	secret := changePhrase(t, url, a, b)

	p.f = reopenKeysOnly(t, p, url, Domain.Keys(testSecret))
	set, err := newKeys(t, p)
	if err != nil {
		t.Fatal(err)
	}
	want := Domain.Keys(secret)
	if set.Group != want.Group || !bytes.Equal(set.Frame, want.Frame) || !bytes.Equal(set.PeerAuth, want.PeerAuth) {
		t.Fatalf("the plugin got %+v, want the fortress's keys under the new phrase", set)
	}

	if err := p.f.Close(); err != nil {
		t.Fatal(err)
	}
	p.f = reopenKeysOnly(t, p, url, set)
	waitFor(t, "alpha to reach the plugin under the new phrase", func() bool { m, _ := memberOf(a.f, p.id); return m.Online() })
	if m, _ := memberOf(a.f, p.id); m.App.ID != "watcher" || len(a.f.Members()) != 2 {
		t.Errorf("alpha lists %+v, want bravo and the plugin as it was", a.f.Members())
	}
	if _, err := p.f.Status(ctx(t), a.id, ""); err != nil {
		t.Errorf("the plugin reads alpha under the new phrase: %v", err)
	}
}

func TestOnlyAMemberFromBeforeTheChangeGetsTheNewKeys(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	out := openKeysOnly(t, url, "watcher", "watcher-out", Domain.Keys(testSecret))
	for _, n := range []*node{a, b, out} {
		waitFor(t, n.name+" to see everybody", func() bool { return len(n.f.Members()) == 2 })
	}
	meet(t, a, b)
	meet(t, a, out)
	if err := a.f.Remove(out.id); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bravo to take the plugin out", func() bool { _, ok := memberOf(b.f, out.id); return !ok })
	changePhrase(t, url, a, b)

	// A member taken out before, and one that holds the old phrase but came
	// only after the change, both get nothing.
	late := openKeysOnly(t, url, "watcher", "watcher-late", Domain.Keys(testSecret))
	waitFor(t, "alpha to answer the late plugin", func() bool {
		status, _, _ := late.f.group.Call(ctx(t), a.id, http.MethodGet, movedPath, nil)
		return status != 0
	})
	for _, n := range []*node{out, late} {
		status, body, err := n.f.group.Call(ctx(t), a.id, http.MethodGet, movedPath, nil)
		if err == nil && status == http.StatusOK {
			t.Errorf("%s was handed %s", n.name, body)
		}
		if _, err := n.f.NewKeys(ctx(t)); err == nil {
			t.Errorf("%s got the new keys", n.name)
		}
	}
	if m, ok := memberOf(a.f, late.id); ok {
		t.Errorf("alpha lists the late plugin as %+v", m)
	}
}

func TestTheNewKeysOpenNoAppAndCarryNoSecret(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	p := openKeysOnly(t, url, "watcher", "watcher-1", Domain.Keys(testSecret))
	for _, n := range []*node{a, b, p} {
		waitFor(t, n.name+" to see everybody", func() bool { return len(n.f.Members()) == 2 })
	}
	meet(t, a, p)
	secret := changePhrase(t, url, a, b)
	// Under the old phrase the plugin reaches nothing but the handover.
	waitFor(t, "alpha to refuse its status on the old phrase", func() bool {
		_, err := p.f.Status(ctx(t), a.id, "")
		return refusalCode(err) == phraseChanged
	})
	if _, err := p.f.Act(ctx(t), a.id, "files.drop", []byte(`"x"`)); refusalCode(err) != "phrase_changed" || len(a.drops()) > 0 {
		t.Errorf("acting at alpha under the old phrase: %v, want phrase_changed", err)
	}
	if _, err := newKeys(t, p); err != nil {
		t.Fatal(err)
	}
	_, raw, err := p.f.group.Call(ctx(t), a.id, http.MethodGet, movedPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range [][]byte{secret, testSecret} {
		for _, form := range [][]byte{s, []byte(base64.StdEncoding.EncodeToString(s)), []byte(hex.EncodeToString(s))} {
			if bytes.Contains(raw, form) {
				t.Errorf("the plugin was handed a secret: %s", raw)
			}
		}
	}
	for _, app := range []keys.Domain{"alpha", "bravo"} {
		if bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(app.FrameKey(secret)))) || bytes.Contains(raw, []byte(app.GroupKey(secret))) {
			t.Errorf("the plugin was handed the keys of %s's pairing: %s", app, raw)
		}
	}
}

func TestTheOldPhraseClosesThirtyDaysAfterTheChange(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	waitFor(t, "alpha to see bravo", func() bool { return len(a.f.Members()) == 1 })
	secret := changePhrase(t, url, a, b)
	if a.f.old == nil {
		t.Fatal("alpha answers nobody on the old phrase right after the change")
	}

	if err := a.f.Close(); err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(a.store.data, &doc); err != nil {
		t.Fatal(err)
	}
	var bk map[string]any
	if err := json.Unmarshal(doc["fortress"], &bk); err != nil {
		t.Fatal(err)
	}
	bk["changed"] = time.Now().Add(-moveWindow - time.Hour)
	raw, err := json.Marshal(bk)
	if err != nil {
		t.Fatal(err)
	}
	doc["fortress"] = raw
	if a.store.data, err = json.Marshal(doc); err != nil {
		t.Fatal(err)
	}
	a.f = reopen(t, a, setup{relay: url, secret: secret, moved: testSecret})
	if a.f.old != nil {
		t.Error("alpha still answers on the old phrase 30 days after the change")
	}
}

func TestANewcomerOnTheOldPhraseLearnsNobody(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	waitFor(t, "alpha to see bravo", func() bool { return len(a.f.Members()) == 1 })
	changePhrase(t, url, a, b)

	late := open(t, "charlie", "charlie-1", setup{relay: url})
	waitFor(t, "alpha to refuse charlie on the old phrase", func() bool {
		status, _, _ := late.f.group.Call(ctx(t), a.id, http.MethodGet, aboutPath, nil)
		return status == http.StatusForbidden
	})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, m := range late.f.Members() {
			if m.Device != "" || m.ID == a.id {
				t.Fatalf("charlie, new on the old phrase, lists %+v", m)
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := late.f.NewKeys(ctx(t)); err == nil {
		t.Error("charlie got the new keys")
	}
}

func TestAMemberTakenOutAfterTheChangeGetsNoNewKeys(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	p := openKeysOnly(t, url, "watcher", "watcher-1", Domain.Keys(testSecret))
	for _, n := range []*node{a, b, p} {
		waitFor(t, n.name+" to see everybody", func() bool { return len(n.f.Members()) == 2 })
	}
	meet(t, a, p)
	if err := p.f.Close(); err != nil {
		t.Fatal(err)
	}
	changePhrase(t, url, a, b)
	if err := a.f.Remove(p.id); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bravo to take the plugin out", func() bool { _, ok := memberOf(b.f, p.id); return !ok })

	p.f = reopenKeysOnly(t, p, url, Domain.Keys(testSecret))
	for _, n := range []*node{a, b} {
		waitFor(t, n.name+" to answer the plugin", func() bool {
			status, _, _ := p.f.group.Call(ctx(t), n.id, http.MethodGet, movedPath, nil)
			return status != 0
		})
		if status, body, _ := p.f.group.Call(ctx(t), n.id, http.MethodGet, movedPath, nil); status == http.StatusOK {
			t.Errorf("%s handed the plugin, taken out, %s", n.name, body)
		}
	}
	if _, err := p.f.NewKeys(ctx(t)); err == nil {
		t.Error("the plugin, taken out, got the new keys")
	}
}

// closedTo reports whether member to refuses from as a stranger.
func closedTo(t *testing.T, from, to *node) bool {
	t.Helper()
	status, body, _ := from.f.group.Call(ctx(t), to.id, http.MethodGet, aboutPath, nil)
	return status == http.StatusForbidden && bytes.Contains(body, []byte(`"groupClosed"`))
}

func TestAPluginThatHasNotFollowedYetRefusesANewcomerOnTheOldPhrase(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	p := openKeysOnly(t, url, "watcher", "watcher-1", Domain.Keys(testSecret))
	for _, n := range []*node{a, b, p} {
		waitFor(t, n.name+" to see everybody", func() bool { return len(n.f.Members()) == 2 })
	}
	meet(t, a, p)
	meet(t, b, p)
	// The plugin stays on the old phrase and asks nobody anything until its
	// watcher runs again.
	changePhrase(t, url, a, b)

	late := openKeysOnly(t, url, "watcher", "watcher-late", Domain.Keys(testSecret))
	waitFor(t, "the plugin to answer the newcomer", func() bool {
		status, _, _ := late.f.group.Call(ctx(t), p.id, http.MethodGet, aboutPath, nil)
		return status != 0
	})
	if !closedTo(t, late, p) {
		t.Error("the plugin, still on the old phrase, takes in a newcomer on it")
	}
	for _, n := range []*node{a, b} {
		waitFor(t, n.name+" to refuse the newcomer", func() bool { return closedTo(t, late, n) })
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, m := range late.f.group.Roster().Members {
			if m.ID == a.id || m.ID == b.id {
				t.Fatalf("the newcomer was handed %+v", m)
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if m, ok := memberOf(p.f, late.id); ok && m.State == group.StateApproved {
		t.Errorf("the plugin lists the newcomer as %+v", m)
	}
}

func TestAPluginShutsOutANewcomerOnceItHearsThePhraseChanged(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	p := openKeysOnly(t, url, "watcher", "watcher-1", Domain.Keys(testSecret))
	for _, n := range []*node{a, b, p} {
		waitFor(t, n.name+" to see everybody", func() bool { return len(n.f.Members()) == 2 })
	}
	meet(t, a, p)
	secret := changePhrase(t, url, a, b)
	// Nobody who took the new phrase is in reach, so the plugin cannot know.
	for _, n := range []*node{a, b} {
		if err := n.f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	late := openKeysOnly(t, url, "watcher", "watcher-late", Domain.Keys(testSecret))
	waitFor(t, "the plugin to take the newcomer in", func() bool {
		status, _, _ := late.f.group.Call(ctx(t), p.id, http.MethodGet, aboutPath, nil)
		return status == http.StatusOK
	})

	a.f = reopen(t, a, setup{relay: url, secret: secret, moved: testSecret})
	waitFor(t, "alpha to tell the plugin the phrase changed", func() bool {
		_, err := p.f.Status(ctx(t), a.id, "")
		return refusalCode(err) == phraseChanged
	})
	waitFor(t, "the plugin to refuse the newcomer", func() bool { return closedTo(t, late, p) })
	if m, ok := memberOf(p.f, late.id); ok && m.State == group.StateApproved {
		t.Errorf("the plugin lists the newcomer as %+v", m)
	}
	if _, err := p.f.Status(ctx(t), late.id, ""); err == nil {
		t.Error("the plugin still reads the newcomer")
	}
}
