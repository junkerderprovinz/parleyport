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

// catchUp takes the phrase the fortress changed to from member id, which
// said it took it, and hands it to the keeper. Only an instance that holds
// the phrase itself does; one that holds only keys follows with NewKeys. One
// that was handed it asks nobody again.
func (f *Fortress) catchUp(id string) {
	if f.keeper == nil || len(f.secret) == 0 {
		return
	}
	f.mu.Lock()
	if f.catching || f.closed {
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
		secret, err := f.askNewPhrase(ctx, id)
		if err == nil {
			err = f.keeper.Keep(secret)
		}
		if err != nil {
			f.mu.Lock()
			f.catching = false
			f.mu.Unlock()
		}
	}()
}

// askNewPhrase asks member id for the secret of the phrase it took.
func (f *Fortress) askNewPhrase(ctx context.Context, id string) ([]byte, error) {
	own, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(newPhraseAsk{Key: own.PublicKey().Bytes()})
	if err != nil {
		return nil, err
	}
	status, raw, err := f.group.Call(ctx, id, http.MethodPost, newPhrasePath, body)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, refusal(status, raw)
	}
	secret, err := openNewPhrase(own, raw, f.secret, id, f.self)
	if err != nil {
		return nil, err
	}
	if len(secret) != phrase.SecretLen || bytes.Equal(secret, f.secret) {
		return nil, errors.New("fortress: the new phrase came unusable")
	}
	return secret, nil
}

// handNewPhrase answers member to, on the phrase before, with this
// instance's secret, sealed for the key it asked with. serveOld checked that
// to is an instance of the fortress as it stands.
func (f *Fortress) handNewPhrase(w http.ResponseWriter, r *http.Request, to string) {
	f.mu.Lock()
	changed := f.book.Changed
	f.mu.Unlock()
	if time.Since(changed) >= moveWindow {
		writeError(w, http.StatusGone, phraseChanged)
		return
	}
	var ask newPhraseAsk
	raw, err := io.ReadAll(r.Body)
	if err != nil || json.Unmarshal(raw, &ask) != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	answer, err := sealNewPhrase(ask.Key, f.secret, f.previous, f.self, to)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	writeJSON(w, answer)
}

// sealNewPhrase seals secret, from member from to member to, for the key to
// asked with.
func sealNewPhrase(asked, secret, held []byte, from, to string) (newPhraseAnswer, error) {
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
	return newPhraseAnswer{Key: own.PublicKey().Bytes(), Sealed: aead.Seal(nil, make([]byte, aead.NonceSize()), secret, nil)}, nil
}

// openNewPhrase opens raw, the answer member from gave member to, which asked
// with own and held the phrase before as held.
func openNewPhrase(own *ecdh.PrivateKey, raw, held []byte, from, to string) ([]byte, error) {
	var answer newPhraseAnswer
	if err := json.Unmarshal(raw, &answer); err != nil {
		return nil, fmt.Errorf("fortress: %s answered unreadably: %w", from, err)
	}
	peer, err := ecdh.X25519().NewPublicKey(answer.Key)
	if err != nil {
		return nil, err
	}
	aead, err := newPhraseSeal(own, peer, held, from, to)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, make([]byte, aead.NonceSize()), answer.Sealed, nil)
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
// offered, and hands it to the keeper.
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
	secret, err := openNewPhrase(o.key, raw, f.secret, from, f.self)
	if err != nil || len(secret) != phrase.SecretLen || bytes.Equal(secret, f.secret) {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if err := f.keeper.Keep(secret); err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
