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

// An instance that was away while the phrase changed asks a member that took
// the new one for it, on the phrase before. Calls there are sealed under that
// phrase, which a member taken out still holds, so the secret travels sealed
// once more: under a key from a one-off exchange between the two and the
// phrase before, so only the instance that asked opens it, and only if it
// held that phrase itself rather than the keys alone.
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
