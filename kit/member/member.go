// Package member is the key pair each member of a group holds of its own.
//
// Every member shares the frame key, so a seal alone says only that somebody
// holding the phrase sent a frame. Each member therefore also holds an Ed25519
// key and goes by an id made from it, so nobody can speak for that id without
// the key behind it. The id's shape tells the kinds apart: 40 hex digits for an
// instance, "phone-" and 64 for a phone, "browser-" and 64 for an extension.
package member

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
)

// Kind is the sort of device a member is. It is part of every signature, so
// one kind's key never counts as another's.
type Kind string

// The kinds of member.
const (
	KindInstance  Kind = "instance"
	KindMobile    Kind = "mobile"
	KindExtension Kind = "extension"
)

// ID is the id a member of kind goes by with key, or "" for an unknown kind or
// a key of the wrong length.
func ID(kind Kind, key []byte) string {
	if len(key) != ed25519.PublicKeySize {
		return ""
	}
	sum := sha256.Sum256(key)
	switch kind {
	case KindInstance:
		return hex.EncodeToString(sum[:20])
	case KindMobile:
		return "phone-" + hex.EncodeToString(sum[:])
	case KindExtension:
		return "browser-" + hex.EncodeToString(sum[:])
	}
	return ""
}

// Fingerprint is how a person compares two member keys by eye: the start of
// the key's hash in four groups.
func Fingerprint(key []byte) string {
	sum := sha256.Sum256(key)
	h := hex.EncodeToString(sum[:8])
	return strings.Join([]string{h[0:4], h[4:8], h[8:12], h[12:16]}, " ")
}

// Identity is a member's own key pair and the kind it signs as.
type Identity struct {
	kind Kind
	key  ed25519.PrivateKey
}

// NewIdentity mints a key pair for a new member of kind.
func NewIdentity(kind Kind) (Identity, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return Identity{}, fmt.Errorf("member: no randomness for a key: %w", err)
	}
	return FromSeed(kind, seed)
}

// FromSeed restores the identity whose Seed is seed.
func FromSeed(kind Kind, seed []byte) (Identity, error) {
	if len(seed) != ed25519.SeedSize {
		return Identity{}, fmt.Errorf("member: seed is %d bytes, want %d", len(seed), ed25519.SeedSize)
	}
	switch kind {
	case KindInstance, KindMobile, KindExtension:
	default:
		return Identity{}, fmt.Errorf("member: unknown kind %q", kind)
	}
	return Identity{kind: kind, key: ed25519.NewKeyFromSeed(seed)}, nil
}

// Kind is the kind i signs as.
func (i Identity) Kind() Kind { return i.kind }

// ID is the id i goes by.
func (i Identity) ID() string { return ID(i.kind, i.Public()) }

// Public is the public half of i's key.
func (i Identity) Public() ed25519.PublicKey { return i.key.Public().(ed25519.PublicKey) }

// Seed is what the app stores to restore i with FromSeed. It is the private
// key, so it belongs under the app's seal.
func (i Identity) Seed() []byte { return i.key.Seed() }

// Sign signs message with i's key.
func (i Identity) Sign(message []byte) []byte { return ed25519.Sign(i.key, message) }

// Message is the layout every member signature covers: the label, a zero
// byte, each field after its length and then n. The lengths keep a byte from
// moving between two fields without changing the message.
func Message(label string, n uint64, fields ...[]byte) []byte {
	out := []byte(label + "\x00")
	for _, field := range fields {
		out = binary.BigEndian.AppendUint64(out, uint64(len(field)))
		out = append(out, field...)
	}
	return binary.BigEndian.AppendUint64(out, n)
}

// helloLabel opens every hello proof. The relay checks proofs against it for
// every app, so it keeps the spelling it was introduced under.
const helloLabel = "knightloader/relay/member-hello/v3"

// HelloMessage is what a member of kind signs to prove that id is its own on
// the group key relayKey, at the relay it reached as relayHost, on the
// connection that relay sent challenge on.
func HelloMessage(relayKey, relayHost, id string, kind Kind, challenge []byte) []byte {
	return Message(helloLabel, 0, []byte(relayKey), []byte(relayHost), []byte(id), []byte(kind), challenge)
}

// Proof shows that a connection holds the key its announced id is made from.
// It signs the challenge of one connection and names the relay the member
// dialled, so neither a hello seen on another connection nor one a second
// relay passes on proves anything.
type Proof struct {
	Kind  Kind   `json:"kind"`
	Relay string `json:"relay"`
	Key   []byte `json:"key"`
	Sig   []byte `json:"sig"`
}

// ProveHello signs the proof of i's id on the group key relayKey, for the
// connection on which the relay i reached as relayHost sent challenge.
func (i Identity) ProveHello(relayKey, relayHost string, challenge []byte) *Proof {
	return &Proof{
		Kind:  i.kind,
		Relay: relayHost,
		Key:   i.Public(),
		Sig:   i.Sign(HelloMessage(relayKey, relayHost, i.ID(), i.kind, challenge)),
	}
}

// Proves reports whether p shows the key id is made from, on the group key
// relayKey and the connection challenge was sent on, to a relay going by one
// of names. A nil proof proves nothing.
func (p *Proof) Proves(relayKey, id string, challenge []byte, names []string) bool {
	if p == nil || ID(p.Kind, p.Key) != id || len(p.Sig) != ed25519.SignatureSize ||
		p.Relay == "" || !slices.Contains(names, p.Relay) {
		return false
	}
	return ed25519.Verify(p.Key, HelloMessage(relayKey, p.Relay, id, p.Kind, challenge), p.Sig)
}
