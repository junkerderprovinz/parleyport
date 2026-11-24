package group

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/member"
	"github.com/junkerderprovinz/parleyport/kit/relay"
)

// phraseKeeper is what an app keeps of the new phrases handed to it.
type phraseKeeper struct {
	mu   sync.Mutex
	took []NewPhrase
	err  error
}

func (k *phraseKeeper) keep(p NewPhrase) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.err != nil {
		return k.err
	}
	k.took = append(k.took, p)
	return nil
}

func (k *phraseKeeper) kept() []NewPhrase {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]NewPhrase(nil), k.took...)
}

func TestAnApprovedInstanceTakesANewPhraseSealedForItAlone(t *testing.T) {
	url := relayServer(t)
	var k phraseKeeper
	a := open(t, "alpha", setup{relay: url})
	b := open(t, "bravo", setup{relay: url, onNewPhrase: k.keep})
	waitFor(t, "alpha to see bravo", func() bool { m, _ := memberOf(a.g, b.id); return m.Relay })
	meet(t, a, b)
	gone := identity(t, "gone").ID()
	if err := a.g.Import(Roster{Removed: map[string]time.Time{gone: time.Now()}}); err != nil {
		t.Fatal(err)
	}

	changed := time.Now().Round(0)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.g.HandNewPhrase(ctx, b.id, a.g.NewPhrase(movedSecret, changed)); err != nil {
		t.Fatalf("hand the new phrase to bravo: %v", err)
	}
	took := k.kept()
	if len(took) != 1 || !bytes.Equal(took[0].Secret, movedSecret) || !took[0].Changed.Equal(changed) {
		t.Fatalf("bravo kept %+v, want the new secret as of %v", took, changed)
	}
	if _, out := b.g.Roster().Removed[gone]; !out {
		t.Error("bravo did not take out the member alpha knows to be out")
	}

	newcomer := device(t, member.KindMobile, "newcomer")
	status, body := b.g.handle(context.Background(), signedBy(newcomer, "newcomer-1", b.id, "/api/whoami"))
	if status != http.StatusForbidden || !bytes.Contains(body, []byte(ClosedUntilNewPhrase)) {
		t.Errorf("a newcomer on the old phrase got %d %s, want it refused until the phrase changes", status, body)
	}
	if status, _, err := call(t, a, b, http.MethodGet, "/api/whoami", nil); err != nil || status != http.StatusOK {
		t.Errorf("alpha, a member from before, got %d %v on the old phrase", status, err)
	}
}

func TestANewPhraseGoesToNobodyWithoutTheOldPhraseItself(t *testing.T) {
	url := relayServer(t)
	var k phraseKeeper
	a := open(t, "alpha", setup{relay: url})
	b := open(t, "bravo", setup{relay: url, keysOnly: true, onNewPhrase: k.keep})
	waitFor(t, "alpha to see bravo", func() bool { m, _ := memberOf(a.g, b.id); return m.Relay })
	meet(t, a, b)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.g.HandNewPhrase(ctx, b.id, a.g.NewPhrase(movedSecret, time.Now())); err == nil {
		t.Error("bravo, which holds only keys, took the new phrase")
	}
	if len(k.kept()) != 0 {
		t.Error("bravo kept a new phrase it cannot open")
	}
	if err := b.g.HandNewPhrase(ctx, a.id, NewPhrase{Secret: movedSecret}); err == nil {
		t.Error("a group on keys alone handed a new phrase on")
	}
}

func TestANewPhraseOpensOnlyForTheKeyItWasSealedFor(t *testing.T) {
	a := open(t, "alpha", setup{})
	own, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := a.g.sealPhrase(own.PublicKey().Bytes(), NewPhrase{Secret: movedSecret}, "alpha", "bravo")
	if err != nil {
		t.Fatal(err)
	}
	if p, err := a.g.openPhrase(own, sealed, "alpha", "bravo"); err != nil || !bytes.Equal(p.Secret, movedSecret) {
		t.Fatalf("the instance it was sealed for opened %v, %v", p, err)
	}
	if _, err := a.g.openPhrase(other, sealed, "alpha", "bravo"); err == nil {
		t.Error("another key opened the new phrase")
	}
	if _, err := a.g.openPhrase(own, sealed, "alpha", "charlie"); err == nil {
		t.Error("the new phrase opened for another instance than the one it was sealed for")
	}
	b := open(t, "bravo", setup{secret: []byte("another phrase!!")})
	if _, err := b.g.openPhrase(own, sealed, "alpha", "bravo"); err == nil {
		t.Error("the new phrase opened without the phrase it was handed on")
	}
}

func TestOnlyAnApprovedInstanceHandsANewPhrase(t *testing.T) {
	var k phraseKeeper
	b := open(t, "bravo", setup{onNewPhrase: k.keep})
	phone := device(t, member.KindMobile, "phone")
	if err := b.g.Import(Roster{Members: []Member{{ID: phone.ID(), Kind: member.KindMobile, Key: phone.Public(), State: StateApproved}}}); err != nil {
		t.Fatal(err)
	}
	if status, _ := b.g.handle(context.Background(), posted(phone, "phone-1", b.id, phraseKeyPath)); status == http.StatusOK {
		t.Error("a phone was offered a key to hand a new phrase with")
	}
	stranger := identity(t, "stranger")
	if status, _ := b.g.handle(context.Background(), posted(stranger, "stranger-1", b.id, phraseKeyPath)); status == http.StatusOK {
		t.Error("an instance waiting for approval was offered a key to hand a new phrase with")
	}
}

func TestANewPhraseTheAppCannotKeepIsNotTaken(t *testing.T) {
	url := relayServer(t)
	k := phraseKeeper{err: errors.New("disk full")}
	a := open(t, "alpha", setup{relay: url})
	b := open(t, "bravo", setup{relay: url, onNewPhrase: k.keep})
	waitFor(t, "alpha to see bravo", func() bool { m, _ := memberOf(a.g, b.id); return m.Relay })
	meet(t, a, b)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.g.HandNewPhrase(ctx, b.id, a.g.NewPhrase(movedSecret, time.Now())); err == nil {
		t.Error("alpha counts the phrase as handed over although bravo could not keep it")
	}
}

// posted is a POST to target's path signed by from under request id.
func posted(from member.Identity, id, target, path string) relay.ProxyCall {
	return relay.SignCall(testDomain.Signing(), &from, id, target, relay.ProxyCall{Method: http.MethodPost, Path: path})
}
