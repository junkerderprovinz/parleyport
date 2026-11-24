package group

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
	"net/http"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/member"
	"github.com/junkerderprovinz/parleyport/kit/relay"
)

// A group that moves to a new phrase hands it to its instances on the phrase
// before, whose calls are sealed under keys a member taken out still holds.
// So the secret is sealed once more, under a key from a one-off exchange
// between the two ends and the phrase before: only the instance it is meant
// for opens it, and only if it holds that phrase itself rather than the keys
// alone.
const (
	phraseKeyPath = internalPrefix + "phrase-key"
	newPhrasePath = internalPrefix + "new-phrase"
)

// NewPhrase is a new phrase as one instance hands it to another: its secret,
// when the group took it, and whom the instance knows to be taken out, so the
// one it reaches cannot carry such a member over to the new phrase.
type NewPhrase struct {
	Secret  []byte               `json:"secret"`
	Changed time.Time            `json:"changed"`
	Removed map[string]time.Time `json:"removed,omitempty"`
	Revoked map[string]time.Time `json:"revoked,omitempty"`
}

// NewPhrase is secret, taken by the group at changed, with the removals this
// instance knows.
func (g *Group) NewPhrase(secret []byte, changed time.Time) NewPhrase {
	r := g.Roster()
	return NewPhrase{Secret: bytes.Clone(secret), Changed: changed, Removed: r.Removed, Revoked: r.Revoked}
}

type phraseKey struct {
	Key []byte `json:"key"`
}

type sealedPhrase struct {
	Key    []byte `json:"key"`
	Sealed []byte `json:"sealed"`
}

// HandNewPhrase hands p to instance id, sealed for it alone: it asks id for a
// one-off key and sends p sealed for that key and the phrase this group runs
// on. The other end takes it with Config.OnNewPhrase. An instance that
// answers with neither gets nothing, and the error says why.
func (g *Group) HandNewPhrase(ctx context.Context, id string, p NewPhrase) error {
	if len(g.secret) == 0 {
		return errors.New("group: only a group opened on its secret hands a new phrase on")
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	status, raw, err := g.Call(ctx, id, http.MethodPost, phraseKeyPath, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("group: %s offered no key for the new phrase: %d %s", id, status, raw)
	}
	var asked phraseKey
	if err := json.Unmarshal(raw, &asked); err != nil {
		return fmt.Errorf("group: %s offered a key unreadably: %w", id, err)
	}
	body, err := g.sealPhrase(asked.Key, p, g.self, id)
	if err != nil {
		return err
	}
	status, raw, err = g.Call(ctx, id, http.MethodPost, newPhrasePath, body)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent {
		return fmt.Errorf("group: %s did not take the new phrase: %d %s", id, status, raw)
	}
	return nil
}

// offer is the one-off key an instance that hands the new phrase seals it
// for, and when it runs out.
type offer struct {
	key   *ecdh.PrivateKey
	until time.Time
}

// takesPhrase reports whether this instance takes a new phrase from caller.
func (g *Group) takesPhrase(caller Caller) bool {
	return g.onNewPhrase != nil && len(g.secret) > 0 && caller.Kind == member.KindInstance && !g.vouchedOnly
}

// offerPhraseKey answers instance from, which is about to hand over a new
// phrase, with a one-off key to seal it for, one per instance at a time.
func (g *Group) offerPhraseKey(from string) (int, []byte) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return http.StatusInternalServerError, nil
	}
	now := time.Now()
	g.mu.Lock()
	for id, o := range g.offered {
		if now.After(o.until) {
			delete(g.offered, id)
		}
	}
	g.offered[from] = offer{key: key, until: now.Add(callTimeout)}
	g.mu.Unlock()
	b, _ := json.Marshal(phraseKey{Key: key.PublicKey().Bytes()})
	return http.StatusOK, b
}

// takePhrase opens the new phrase instance from sent, sealed for the key it
// was offered, and hands it to the app. Whoever p names as taken out is out
// here first, and from then on the group takes nobody new on this phrase.
func (g *Group) takePhrase(from string, raw []byte) (int, []byte) {
	g.mu.Lock()
	o, ok := g.offered[from]
	delete(g.offered, from)
	g.mu.Unlock()
	if !ok || time.Now().After(o.until) {
		return http.StatusBadRequest, relay.RefusalBody("phraseKeyGone", "ask for a key first")
	}
	p, err := g.openPhrase(o.key, raw, from, g.self)
	if err != nil || len(p.Secret) != len(g.secret) || bytes.Equal(p.Secret, g.secret) {
		return http.StatusBadRequest, relay.RefusalBody("phraseUnusable", "the new phrase came unusable")
	}
	if err := g.Import(Roster{Removed: p.Removed, Revoked: p.Revoked}); err != nil {
		return http.StatusInternalServerError, nil
	}
	changed := p.Changed
	if changed.IsZero() || changed.After(time.Now()) {
		changed = time.Now()
	}
	g.TakeNoNew(changed)
	if err := g.onNewPhrase(p); err != nil {
		return http.StatusInternalServerError, nil
	}
	return http.StatusNoContent, nil
}

// sealPhrase seals p, from instance from to instance to, for the key to
// offered.
func (g *Group) sealPhrase(offered []byte, p NewPhrase, from, to string) ([]byte, error) {
	plain, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	peer, err := ecdh.X25519().NewPublicKey(offered)
	if err != nil {
		return nil, err
	}
	own, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	aead, err := g.phraseSeal(own, peer, from, to)
	if err != nil {
		return nil, err
	}
	return json.Marshal(sealedPhrase{Key: own.PublicKey().Bytes(), Sealed: aead.Seal(nil, make([]byte, aead.NonceSize()), plain, nil)})
}

// openPhrase opens raw, which instance from sealed for to under own.
func (g *Group) openPhrase(own *ecdh.PrivateKey, raw []byte, from, to string) (NewPhrase, error) {
	var s sealedPhrase
	if err := json.Unmarshal(raw, &s); err != nil {
		return NewPhrase{}, err
	}
	peer, err := ecdh.X25519().NewPublicKey(s.Key)
	if err != nil {
		return NewPhrase{}, err
	}
	aead, err := g.phraseSeal(own, peer, from, to)
	if err != nil {
		return NewPhrase{}, err
	}
	plain, err := aead.Open(nil, make([]byte, aead.NonceSize()), s.Sealed, nil)
	if err != nil {
		return NewPhrase{}, err
	}
	var p NewPhrase
	if err := json.Unmarshal(plain, &p); err != nil {
		return NewPhrase{}, err
	}
	return p, nil
}

// phraseSeal is the seal both ends make from their one-off keys, the secret
// of the phrase the group runs on and who hands the new one to whom. Every
// hand-over has keys of its own, so the nonce never repeats.
func (g *Group) phraseSeal(own *ecdh.PrivateKey, peer *ecdh.PublicKey, from, to string) (cipher.AEAD, error) {
	shared, err := own.ECDH(peer)
	if err != nil {
		return nil, err
	}
	ends := [][]byte{own.PublicKey().Bytes(), peer.Bytes()}
	if bytes.Compare(ends[0], ends[1]) > 0 {
		ends[0], ends[1] = ends[1], ends[0]
	}
	info := string(g.domain) + "/new-phrase/v1\x00" + from + "\x00" + to + "\x00" + string(ends[0]) + string(ends[1])
	key, err := hkdf.Key(sha256.New, append(shared, g.secret...), nil, info, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
