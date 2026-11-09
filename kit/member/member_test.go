package member

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/internal/vectors"
)

func load(t *testing.T) *vectors.File {
	t.Helper()
	v, err := vectors.Load()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func decoded(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func vectorIdentity(t *testing.T, v *vectors.File, kind Kind) Identity {
	t.Helper()
	seed, err := hex.DecodeString(v.Member.Seed)
	if err != nil {
		t.Fatal(err)
	}
	id, err := FromSeed(kind, seed)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestIDsMatchTheVectors(t *testing.T) {
	v := load(t)
	for kind, want := range v.Member.IDs {
		id := vectorIdentity(t, v, Kind(kind))
		if got := base64.StdEncoding.EncodeToString(id.Public()); got != v.Member.PublicKey {
			t.Fatalf("public key = %s, want %s", got, v.Member.PublicKey)
		}
		if got := id.ID(); got != want {
			t.Errorf("%s id = %s, want %s", kind, got, want)
		}
		if got := ID(Kind(kind), id.Public()); got != want {
			t.Errorf("ID(%s) = %s, want %s", kind, got, want)
		}
	}
}

func TestAnIDNeedsAKnownKindAndAWholeKey(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	if ID("robot", key) != "" {
		t.Error("an unknown kind made an id")
	}
	if ID(KindMobile, key[:10]) != "" {
		t.Error("a short key made an id")
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	if ID(KindMobile, key) == ID(KindMobile, other) {
		t.Error("two keys make one id")
	}
}

func TestFingerprintMatchesTheVector(t *testing.T) {
	v := load(t)
	id := vectorIdentity(t, v, KindInstance)
	if got := Fingerprint(id.Public()); got != v.Member.Fingerprint {
		t.Errorf("Fingerprint = %q, want %q", got, v.Member.Fingerprint)
	}
}

func TestAnIdentityComesBackFromItsSeed(t *testing.T) {
	id, err := NewIdentity(KindInstance)
	if err != nil {
		t.Fatal(err)
	}
	again, err := FromSeed(KindInstance, id.Seed())
	if err != nil {
		t.Fatal(err)
	}
	if again.ID() != id.ID() || again.Kind() != KindInstance || !again.Public().Equal(id.Public()) {
		t.Errorf("restored %s, want %s", again.ID(), id.ID())
	}
	if other, _ := NewIdentity(KindInstance); other.ID() == id.ID() {
		t.Error("two new identities share an id")
	}
}

func TestAnIdentityNeedsAKnownKindAndAWholeSeed(t *testing.T) {
	if _, err := NewIdentity("robot"); err == nil {
		t.Error("NewIdentity accepted an unknown kind")
	}
	if _, err := FromSeed(KindInstance, make([]byte, 31)); err == nil {
		t.Error("FromSeed accepted a short seed")
	}
	if _, err := FromSeed("", make([]byte, ed25519.SeedSize)); err == nil {
		t.Error("FromSeed accepted an empty kind")
	}
}

// The relay checks hello proofs against this layout, so a change here locks
// every member out of reclaiming its id.
func TestTheHelloVectorStaysTheSame(t *testing.T) {
	v := load(t)
	h := v.Member.Hello
	id := vectorIdentity(t, v, Kind(h.Kind))
	challenge := decoded(t, h.Challenge)
	proof := id.ProveHello(h.RelayKey, h.RelayHost, challenge)
	if got := base64.StdEncoding.EncodeToString(proof.Sig); got != h.Signature {
		t.Errorf("hello signature = %s, want %s", got, h.Signature)
	}
	if proof.Kind != Kind(h.Kind) || proof.Relay != h.RelayHost || !bytes.Equal(proof.Key, id.Public()) {
		t.Errorf("proof = %+v, want it to name the kind, relay and key", proof)
	}
	if !proof.Proves(h.RelayKey, v.Member.IDs[h.Kind], challenge, []string{h.RelayHost}) {
		t.Error("the vector hello does not prove the vector id")
	}
}

func TestAHelloProvesOnlyTheIDItsKeyMakes(t *testing.T) {
	v := load(t)
	h := v.Member.Hello
	phone := vectorIdentity(t, v, KindMobile)
	challenge := decoded(t, h.Challenge)
	names := []string{h.RelayHost}
	own := phone.ProveHello(h.RelayKey, h.RelayHost, challenge)

	stranger, err := NewIdentity(KindMobile)
	if err != nil {
		t.Fatal(err)
	}
	// Another relay the phone dialled passes this relay's challenge on, and the
	// phone signs it for the relay it dialled.
	passedOn := phone.ProveHello(h.RelayKey, "other-relay.example.net", challenge)
	renamed := *passedOn
	renamed.Relay = h.RelayHost
	asInstance := *own
	asInstance.Kind = KindInstance

	for name, tc := range map[string]struct {
		proof *Proof
		id    string
		key   string
		ch    []byte
	}{
		"without a proof":         {nil, phone.ID(), h.RelayKey, challenge},
		"for another id":          {own, stranger.ID(), h.RelayKey, challenge},
		"by another key":          {stranger.ProveHello(h.RelayKey, h.RelayHost, challenge), phone.ID(), h.RelayKey, challenge},
		"on another relay key":    {own, phone.ID(), "another-relay-key-0123456789abcdef", challenge},
		"for another connection":  {own, phone.ID(), h.RelayKey, make([]byte, len(challenge))},
		"under another kind's id": {&asInstance, ID(KindInstance, phone.Public()), h.RelayKey, challenge},
		"for another relay":       {passedOn, phone.ID(), h.RelayKey, challenge},
		"renamed to this relay":   {&renamed, phone.ID(), h.RelayKey, challenge},
	} {
		if tc.proof.Proves(tc.key, tc.id, tc.ch, names) {
			t.Errorf("a hello %s proves its id", name)
		}
	}
	if !own.Proves(h.RelayKey, phone.ID(), challenge, names) {
		t.Fatal("the phone's proof of its own id does not hold")
	}
}

func TestEveryFieldOfAMessageIsBoundToItsPlace(t *testing.T) {
	base := Message("alpha/test", 7, []byte("ab"), []byte("c"))
	for name, other := range map[string][]byte{
		"another label":         Message("beta/test", 7, []byte("ab"), []byte("c")),
		"another number":        Message("alpha/test", 8, []byte("ab"), []byte("c")),
		"a byte moved across":   Message("alpha/test", 7, []byte("a"), []byte("bc")),
		"a field more":          Message("alpha/test", 7, []byte("ab"), []byte("c"), nil),
		"the label run into it": Message("alpha/tes", 7, []byte("tab"), []byte("c")),
	} {
		if bytes.Equal(base, other) {
			t.Errorf("%s gives the same message", name)
		}
	}
}
