package fortress

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/group"
	"github.com/junkerderprovinz/parleyport/kit/phrase"
)

// A new phrase travels on the phrase before, whose calls are sealed under keys
// a member taken out still holds. So the secret is sealed once more, under a
// key from a one-off exchange between the two ends and the phrase before:
// only the instance it is meant for opens it, and only if it held that
// phrase itself rather than the keys alone. ChangePhrase hands it this way to
// the members in reach, and an instance away for the change asks for it at
// newPhrasePath.
const newPhrasePath = prefix + "new-phrase"

type newPhraseAsk struct {
	Key []byte `json:"key"`
}

type newPhraseAnswer struct {
	Key    []byte `json:"key"`
	Sealed []byte `json:"sealed"`
}

// newPhrase is what a member hands with the secret of a new phrase: when the
// fortress took it, and whom it knows to be taken out, so that the one it
// hands it to cannot carry a member taken out, or one first met after the
// change, over to the new phrase.
type newPhrase struct {
	Secret  []byte               `json:"secret"`
	Changed time.Time            `json:"changed"`
	Removed map[string]time.Time `json:"removed,omitempty"`
	Revoked map[string]time.Time `json:"revoked,omitempty"`
}

// handing is secret with when the fortress took it and the removals this
// instance knows.
func (f *Fortress) handing(secret []byte, changed time.Time) newPhrase {
	r := f.group.Roster()
	return newPhrase{Secret: secret, Changed: changed, Removed: r.Removed, Revoked: r.Revoked}
}

// takeNew takes p, the phrase a member handed this instance, as of when the
// fortress took it: whoever was first met after that is forgotten, whoever
// the member knows to be taken out is taken out here, and the keeper keeps
// the secret. The book under the new phrase counts the change from then too,
// and late marks an instance that took it after the change, which serves
// nobody on the phrase before.
func (f *Fortress) takeNew(p newPhrase, late bool) error {
	if len(p.Secret) != phrase.SecretLen || bytes.Equal(p.Secret, f.secret) {
		return errors.New("fortress: the new phrase came unusable")
	}
	f.shut(p.Changed)
	if err := f.group.Import(group.Roster{Removed: p.Removed, Revoked: p.Revoked}); err != nil {
		return err
	}
	if err := f.moveBook(&handed{Changed: p.Changed, Late: late}); err != nil {
		return err
	}
	if err := f.keeper.Keep(p.Secret); err != nil {
		_ = f.moveBook(nil)
		return err
	}
	return nil
}

// moveBook keeps h in the book for the phrase it moves to next.
func (f *Fortress) moveBook(h *handed) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.book.Next = h
	return f.saveLocked()
}

// catchUp takes the phrase the fortress changed to from member id, which
// said it took it. Only an instance that holds the phrase itself does; one
// that holds only keys follows with NewKeys. One member is asked at a time,
// and a member that was not asked or did not hand it over is described again
// soon, until one did.
func (f *Fortress) catchUp(id string) {
	if f.keeper == nil || len(f.secret) == 0 {
		return
	}
	f.mu.Lock()
	switch {
	case f.closed || f.caught:
		f.mu.Unlock()
		return
	case f.catching:
		f.described[id] = time.Now().Add(retryAfter)
		f.mu.Unlock()
		return
	}
	f.catching = true
	f.wg.Add(1)
	f.mu.Unlock()
	go func() {
		defer f.wg.Done()
		ctx, cancel := context.WithTimeout(f.ctx, callTimeout)
		defer cancel()
		p, err := f.askNewPhrase(ctx, id)
		if err == nil {
			err = f.takeNew(p, true)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.catching = false
		if err == nil {
			f.caught = true
		} else {
			f.described[id] = time.Now().Add(retryAfter)
		}
	}()
}

// askNewPhrase asks member id for the phrase it took.
func (f *Fortress) askNewPhrase(ctx context.Context, id string) (newPhrase, error) {
	own, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return newPhrase{}, err
	}
	body, err := json.Marshal(newPhraseAsk{Key: own.PublicKey().Bytes()})
	if err != nil {
		return newPhrase{}, err
	}
	status, raw, err := f.group.Call(ctx, id, http.MethodPost, newPhrasePath, body)
	if err != nil {
		return newPhrase{}, err
	}
	if status != http.StatusOK {
		return newPhrase{}, refusal(status, raw)
	}
	return openNewPhrase(own, raw, f.secret, id, f.self)
}

// handNewPhrase answers member to, on the phrase before, with this
// instance's secret, sealed for the key it asked with. serveOld checked that
// to is an instance of the fortress as it stands, within the window.
func (f *Fortress) handNewPhrase(w http.ResponseWriter, r *http.Request, to string) {
	var ask newPhraseAsk
	raw, err := io.ReadAll(r.Body)
	if err != nil || json.Unmarshal(raw, &ask) != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	answer, err := sealNewPhrase(ask.Key, f.handing(f.secret, f.changed()), f.previous, f.self, to)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	writeJSON(w, answer)
}

// changed is when the fortress took the phrase this instance is on, before
// when it took the one before.
func (f *Fortress) changed() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.book.Changed
}

func (f *Fortress) before() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.book.Before
}

// sealNewPhrase seals p, from member from to member to, for the key to asked
// with.
func sealNewPhrase(asked []byte, p newPhrase, held []byte, from, to string) (newPhraseAnswer, error) {
	plain, err := json.Marshal(p)
	if err != nil {
		return newPhraseAnswer{}, err
	}
	peer, err := ecdh.X25519().NewPublicKey(asked)
	if err != nil {
		return newPhraseAnswer{}, err
	}
	own, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return newPhraseAnswer{}, err
	}
	aead, err := newPhraseSeal(own, peer, held, from, to)
	if err != nil {
		return newPhraseAnswer{}, err
	}
	return newPhraseAnswer{Key: own.PublicKey().Bytes(), Sealed: aead.Seal(nil, make([]byte, aead.NonceSize()), plain, nil)}, nil
}

// openNewPhrase opens raw, the answer member from gave member to, which asked
// with own and held the phrase before as held.
func openNewPhrase(own *ecdh.PrivateKey, raw, held []byte, from, to string) (newPhrase, error) {
	var answer newPhraseAnswer
	if err := json.Unmarshal(raw, &answer); err != nil {
		return newPhrase{}, fmt.Errorf("fortress: %s answered unreadably: %w", from, err)
	}
	peer, err := ecdh.X25519().NewPublicKey(answer.Key)
	if err != nil {
		return newPhrase{}, err
	}
	aead, err := newPhraseSeal(own, peer, held, from, to)
	if err != nil {
		return newPhrase{}, err
	}
	plain, err := aead.Open(nil, make([]byte, aead.NonceSize()), answer.Sealed, nil)
	if err != nil {
		return newPhrase{}, err
	}
	var p newPhrase
	if err := json.Unmarshal(plain, &p); err != nil {
		return newPhrase{}, fmt.Errorf("fortress: %s sealed something unreadable: %w", from, err)
	}
	return p, nil
}

// newPhraseSeal is the seal between own and peer, which both ends make from
// their one-off keys, the secret of the phrase before and who hands the new
// one to whom. Every answer has a key of its own, so the nonce never repeats.
func newPhraseSeal(own *ecdh.PrivateKey, peer *ecdh.PublicKey, held []byte, from, to string) (cipher.AEAD, error) {
	shared, err := own.ECDH(peer)
	if err != nil {
		return nil, err
	}
	ends := [][]byte{own.PublicKey().Bytes(), peer.Bytes()}
	if bytes.Compare(ends[0], ends[1]) > 0 {
		ends[0], ends[1] = ends[1], ends[0]
	}
	info := string(Domain) + "/new-phrase/v1\x00" + from + "\x00" + to + "\x00" + string(ends[0]) + string(ends[1])
	key, err := hkdf.Key(sha256.New, append(shared, held...), nil, info, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// offer is the one-off key a member that changes the phrase seals the new
// one for, and when it runs out.
type offer struct {
	key   *ecdh.PrivateKey
	until time.Time
}

// offerPhraseKey answers member from, which is about to change the phrase,
// with a one-off key to seal the new one for, one per member at a time.
func (f *Fortress) offerPhraseKey(w http.ResponseWriter, from string) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	now := time.Now()
	f.mu.Lock()
	for id, o := range f.offered {
		if now.After(o.until) {
			delete(f.offered, id)
		}
	}
	f.offered[from] = offer{key: key, until: now.Add(callTimeout)}
	f.mu.Unlock()
	writeJSON(w, newPhraseAsk{Key: key.PublicKey().Bytes()})
}

// takePhrase opens the phrase member from sent, sealed for the key it was
// offered, and takes it.
func (f *Fortress) takePhrase(w http.ResponseWriter, r *http.Request, from string) {
	f.mu.Lock()
	o, ok := f.offered[from]
	delete(f.offered, from)
	f.mu.Unlock()
	raw, err := io.ReadAll(r.Body)
	if !ok || time.Now().After(o.until) || err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	p, err := openNewPhrase(o.key, raw, f.secret, from, f.self)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if err := f.takeNew(p, false); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// removedSince is when the latest member was taken out after since, zero
// when none was.
func (f *Fortress) removedSince(since time.Time) time.Time {
	var last time.Time
	for _, at := range f.group.Roster().Removed {
		if at.After(since) && at.After(last) {
			last = at
		}
	}
	return last
}

// heardBefore reports whether this instance first heard from member id
// before removed, or nobody was taken out. A member taken out keeps the
// phrase it had, and may be back under a new key, so a member first met
// after that is handed no new phrase and enters it like a newcomer.
func (f *Fortress) heardBefore(id string, removed time.Time) bool {
	if removed.IsZero() {
		return true
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	at, ok := f.book.Heard[id]
	return ok && at.Before(removed)
}
