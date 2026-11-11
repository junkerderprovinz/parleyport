package fortress

import (
	"sync/atomic"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/keys"
	"github.com/junkerderprovinz/parleyport/kit/member"
	"github.com/junkerderprovinz/parleyport/kit/relay"
)

func TestOnChangeHearsAMemberSayWhichAppItRuns(t *testing.T) {
	url := relayServer(t)
	a := &node{name: "alpha-1", app: "alpha", id: identity(t, "alpha-1").ID(), store: &memStore{}, pairStore: &memStore{}}
	var heard atomic.Bool
	cfg := config(t, a, setup{relay: url})
	cfg.OnChange = func() {
		f := a.current.Load()
		if f == nil {
			return
		}
		for _, m := range f.Members() {
			if m.App.ID == "bravo" {
				heard.Store(true)
			}
		}
	}
	f, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a.current.Store(f)
	a.f = f
	t.Cleanup(func() { _ = f.Close() })
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	meet(t, a, b)
	waitFor(t, "OnChange to hear that bravo runs bravo", heard.Load)
}

// phoneOnRelay puts a phone of app on the relay at url, holding the phrase.
func phoneOnRelay(t *testing.T, url, app string) member.Identity {
	t.Helper()
	id, err := member.NewIdentity(member.KindMobile)
	if err != nil {
		t.Fatal(err)
	}
	d := keys.Domain(app)
	c, err := relay.NewClient(relay.ClientOptions{
		URL:      url,
		Key:      d.GroupKey(testSecret),
		FrameKey: d.FrameKey(testSecret),
		Signing:  d.Signing(),
		Self:     relay.Announce{Name: "pixel", Deployment: string(member.KindMobile), Client: true, Member: id.ID()},
		Identity: &id,
	})
	if err != nil {
		t.Fatal(err)
	}
	c.Start()
	t.Cleanup(func() { _ = c.Close() })
	return id
}

func TestThePairingTakesOnlyTheKindsTheAppAllows(t *testing.T) {
	url := relayServer(t)
	open1 := func(name string, kinds []member.Kind) *Fortress {
		n := &node{name: name, app: "alpha", id: identity(t, name).ID(), store: &memStore{}, pairStore: &memStore{}}
		cfg := config(t, n, setup{relay: url})
		cfg.Pairing.Kinds = kinds
		f, err := Open(cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		return f
	}
	strict := open1("alpha-1", []member.Kind{member.KindInstance})
	loose := open1("alpha-2", nil)
	phone := phoneOnRelay(t, url, "alpha")
	listed := func(f *Fortress) bool {
		for _, m := range f.Pairing().Members() {
			if m.ID == phone.ID() {
				return true
			}
		}
		return false
	}
	waitFor(t, "the open pairing to see the phone", func() bool { return listed(loose) })
	if listed(strict) {
		t.Error("a pairing that takes instances alone lists a phone")
	}
}
