package relay

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

// The vector KnightLoader's instances, app and extension are held to, copied
// from its relay package. Ed25519 is deterministic, so a fixed seed and a
// fixed hello give one signature, and a relay that checks hellos any other way
// turns every KnightLoader member away.
var (
	vectorSeed     = bytes.Repeat([]byte{0x2a}, ed25519.SeedSize)
	vectorRelayKey = "relay-key-of-the-vector-0123456789"
	// vectorRelayHost is the relay the vector hello is meant for.
	vectorRelayHost = "relay.example.com"
	// vectorChallenge is the challenge the vector hello answers, in base64.
	vectorChallenge = "XFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFw="
)

const (
	vectorInstanceID = "b600306cfa76723fdec395e53a9b3d9fdb78b1e2"
	vectorPhoneID    = "phone-b600306cfa76723fdec395e53a9b3d9fdb78b1e2d7a23c32fcbcd2dc6d0c4092"
	vectorBrowserID  = "browser-b600306cfa76723fdec395e53a9b3d9fdb78b1e2d7a23c32fcbcd2dc6d0c4092"
	vectorHelloSig   = "U/kIXyBTKTsSTbXyWn3IqdWTgkEKOfsDtY9+asOM8WTn7jG9XHeF9/toZ1+60J+ap70GId2ySigv7ZFT3PhvBg=="
)

// decoded is the bytes of base64 text s.
func decoded(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// keyNumber is a distinct 32-byte value for each n.
func keyNumber(n int) []byte {
	k := make([]byte, ed25519.PublicKeySize)
	binary.BigEndian.PutUint64(k, uint64(n))
	return k
}

func TestAMembersIDIsMadeFromItsKey(t *testing.T) {
	key := ed25519.NewKeyFromSeed(vectorSeed).Public().(ed25519.PublicKey)
	for kind, want := range map[string]string{KindInstance: vectorInstanceID, KindMobile: vectorPhoneID, KindExtension: vectorBrowserID} {
		if got := MemberID(kind, key); got != want {
			t.Errorf("MemberID(%s) = %s, want %s", kind, got, want)
		}
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	if MemberID(KindMobile, other) == vectorPhoneID {
		t.Error("two keys make one id")
	}
	if MemberID("robot", key) != "" || MemberID(KindMobile, key[:10]) != "" {
		t.Error("an unknown kind or a short key made an id")
	}
}

func TestTheHelloVectorStaysTheSame(t *testing.T) {
	member := ed25519.NewKeyFromSeed(vectorSeed)
	proof := ProveID(member, KindMobile, vectorRelayKey, vectorRelayHost, vectorPhoneID, decoded(t, vectorChallenge))
	if got := base64.StdEncoding.EncodeToString(proof.Sig); got != vectorHelloSig {
		t.Errorf("hello signature = %s, want %s; KnightLoader's app proves its id with the old message", got, vectorHelloSig)
	}
	hello := Hello{Key: vectorRelayKey, Announce: Announce{InstanceID: vectorPhoneID}, Proof: proof}
	if !hello.proves(decoded(t, vectorChallenge), []string{vectorRelayHost}) {
		t.Error("the vector hello does not prove the vector id")
	}
}

// TestAHelloFromTheAppIsReadAsItIsSent: the app writes the proof as JSON of
// its own, with the key and signature in base64, and Hello has to read it to
// the same bytes the vector signed.
func TestAHelloFromTheAppIsReadAsItIsSent(t *testing.T) {
	member := ed25519.NewKeyFromSeed(vectorSeed)
	proof := ProveID(member, KindMobile, vectorRelayKey, vectorRelayHost, vectorPhoneID, decoded(t, vectorChallenge))
	frame := `{"type":"hello","data":{"key":"` + vectorRelayKey + `","proof":{"kind":"mobile","relay":"` + vectorRelayHost +
		`","key":"` + base64.StdEncoding.EncodeToString(proof.Key) + `","sig":"` + vectorHelloSig +
		`"},"announce":{"instanceId":"` + vectorPhoneID + `","sealed":"AAAA"}}}`
	env, err := Decode([]byte(frame))
	if err != nil {
		t.Fatal(err)
	}
	var h Hello
	if err := env.Into(&h); err != nil {
		t.Fatal(err)
	}
	if !h.proves(decoded(t, vectorChallenge), []string{vectorRelayHost}) {
		t.Fatal("the app's hello does not prove its id")
	}
}

func TestAHelloProvesOnlyTheIDItsKeyMakes(t *testing.T) {
	member := ed25519.NewKeyFromSeed(vectorSeed)
	challenge := decoded(t, vectorChallenge)
	hello := func(id string, p *IDProof) Hello {
		return Hello{Key: vectorRelayKey, Announce: Announce{InstanceID: id}, Proof: p}
	}
	names := []string{vectorRelayHost}
	if !hello(vectorPhoneID, ProveID(member, KindMobile, vectorRelayKey, vectorRelayHost, vectorPhoneID, challenge)).proves(challenge, names) {
		t.Fatal("a phone's proof of its own id does not hold")
	}
	other := MemberID(KindMobile, keyNumber(7))
	// Another relay the phone dialled passes on this relay's challenge, and the
	// phone signs it for the relay it dialled.
	passedOn := ProveID(member, KindMobile, vectorRelayKey, "other-relay.example.net", vectorPhoneID, challenge)
	renamed := *passedOn
	renamed.Relay = vectorRelayHost
	for name, h := range map[string]Hello{
		"without a proof":         hello(vectorPhoneID, nil),
		"for another id":          hello(other, ProveID(member, KindMobile, vectorRelayKey, vectorRelayHost, other, challenge)),
		"on another relay key":    hello(vectorPhoneID, ProveID(member, KindMobile, "another-relay-key-0123456789abcdef", vectorRelayHost, vectorPhoneID, challenge)),
		"for another connection":  hello(vectorPhoneID, ProveID(member, KindMobile, vectorRelayKey, vectorRelayHost, vectorPhoneID, make([]byte, challengeSize))),
		"under another kind's id": hello(vectorInstanceID, ProveID(member, KindMobile, vectorRelayKey, vectorRelayHost, vectorInstanceID, challenge)),
		"for another relay":       hello(vectorPhoneID, passedOn),
		"renamed to this relay":   hello(vectorPhoneID, &renamed),
	} {
		if h.proves(challenge, names) {
			t.Errorf("a hello %s proves its id", name)
		}
	}
}

// TestTheLargestClientHelloFitsTheLimit: the extension's hello is the largest
// a KnightLoader 1.9 member sends, with its longest id, a name of characters
// JSON escapes to six bytes, its lasting member id sealed beside them and a
// proof for a relay name of the longest a DNS name can be.
func TestTheLargestClientHelloFitsTheLimit(t *testing.T) {
	id := strings.Repeat("f", 72)
	identity, err := json.Marshal(map[string]any{
		"name":       strings.Repeat("<", MaxNameBytes),
		"deployment": "extension",
		"client":     true,
		"member":     strings.Repeat("<", 72),
	})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := seal(testFrameKey, announceAAD(id), identity)
	if err != nil {
		t.Fatal(err)
	}
	proof := ProveID(ed25519.NewKeyFromSeed(vectorSeed), KindExtension, strings.Repeat("k", 64), strings.Repeat("r", 253), id, make([]byte, challengeSize))
	frame, err := Encode(TypeHello, Hello{Key: strings.Repeat("k", 64), Announce: Announce{InstanceID: id, Sealed: sealed}, Proof: proof})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(frame) > helloLimit {
		t.Fatalf("the largest client hello is %d bytes, over the %d the relay reads", len(frame), helloLimit)
	}
}

// TestRelayHost: the relay a hello's proof names. KnightLoader's app is held
// to these rows too.
func TestRelayHost(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"a dialled address", "wss://relay.example.com/relay/connect", "relay.example.com"},
		{"the port goes", "ws://192.168.20.30:8760/relay/connect", "192.168.20.30"},
		{"in lower case", "https://Relay.Example.COM", "relay.example.com"},
		{"without the dot of a full name", "https://relay.example.com./kl", "relay.example.com"},
		{"an IPv6 literal without its brackets", "ws://[::1]:8760/relay/connect", "::1"},
		{"a bare host", "relay.example.com", "relay.example.com"},
		{"a bare host and a port", "127.0.0.1:8760", "127.0.0.1"},
		{"whitespace from a setting", "  https://relay.example.com  ", "relay.example.com"},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		if got := RelayHost(tc.in); got != tc.want {
			t.Errorf("%s: RelayHost(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}
