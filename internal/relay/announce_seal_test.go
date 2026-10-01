package relay

// The relay server reads Announce.InstanceID only (matching a reconnect,
// addressing a presence frame, picking a proxy target) and never the name,
// deployment or client flag. These tests pin that the relay keeps what it
// routes on and gets nothing else.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestAnnounceRoundTripsThroughTheSeal(t *testing.T) {
	in := Announce{InstanceID: "alpha", Name: "BOTTICH", Deployment: "container", Client: true, Address: "https://kl.example.org"}

	wire, err := sealAnnounce(testFrameKey, in)
	if err != nil {
		t.Fatalf("sealAnnounce: %v", err)
	}
	if wire.Name != "" || wire.Deployment != "" || wire.Client || wire.Address != "" {
		t.Errorf("wire form still carries identity: %+v", wire)
	}
	if wire.InstanceID != "alpha" {
		t.Errorf("wire form lost the routing field: %+v", wire)
	}
	if len(wire.Sealed) == 0 {
		t.Fatal("nothing was sealed")
	}

	got := openAnnounce(testFrameKey, wire)
	if got.InstanceID != in.InstanceID || got.Name != in.Name ||
		got.Deployment != in.Deployment || got.Client != in.Client || got.Address != in.Address {
		t.Errorf("round trip = %+v, want %+v", got, in)
	}
	if len(got.Sealed) != 0 {
		t.Errorf("the opened form still carries the blob: %+v", got)
	}
}

// TestTheSealedIdentityIsNotInTheEncodedFrame searches the marshalled bytes
// rather than comparing structs, since empty fields are also what a forgotten
// json tag produces.
func TestTheSealedIdentityIsNotInTheEncodedFrame(t *testing.T) {
	wire, err := sealAnnounce(testFrameKey, Announce{
		InstanceID: "alpha",
		Name:       "jdp-workstation",
		Deployment: "desktop",
		Address:    "https://kl.example.org",
	})
	if err != nil {
		t.Fatalf("sealAnnounce: %v", err)
	}
	frame, err := Encode(TypeAnnounce, wire)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	for _, secret := range []string{"jdp-workstation", "desktop", "kl.example.org"} {
		if bytes.Contains(frame, []byte(secret)) {
			t.Errorf("the encoded announce contains %q in the clear:\n%s", secret, frame)
		}
	}
	if !bytes.Contains(frame, []byte("alpha")) {
		t.Errorf("the encoded announce lost the id the relay routes on:\n%s", frame)
	}
}

// TestTheLargestHelloFitsTheLimit uses the characters JSON escapes to six
// bytes, since relays already running refuse a first frame over helloLimit.
func TestTheLargestHelloFitsTheLimit(t *testing.T) {
	wire, err := sealAnnounce(testFrameKey, Announce{
		InstanceID: strings.Repeat("f", 40),
		Name:       strings.Repeat("<", MaxNameBytes),
		Deployment: "container",
		Address:    "https://" + strings.Repeat("&", MaxAddressBytes-len("https://")),
	})
	if err != nil {
		t.Fatalf("sealAnnounce: %v", err)
	}
	if !strings.HasPrefix(openAnnounce(testFrameKey, wire).Address, "https://") {
		t.Fatal("an address of exactly MaxAddressBytes was dropped")
	}
	frame, err := Encode(TypeHello, Hello{Key: strings.Repeat("k", 64), Announce: wire})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(frame) > helloLimit {
		t.Fatalf("the largest hello is %d bytes, over the %d the relay reads", len(frame), helloLimit)
	}
}

func TestAnAddressTooLongIsLeftOutRatherThanCut(t *testing.T) {
	long := "https://" + strings.Repeat("a", MaxAddressBytes)
	wire, err := sealAnnounce(testFrameKey, Announce{InstanceID: "alpha", Address: long})
	if err != nil {
		t.Fatalf("sealAnnounce: %v", err)
	}
	if got := openAnnounce(testFrameKey, wire).Address; got != "" {
		t.Fatalf("a %d byte address arrived as %q", len(long), got)
	}
}

// TestARelayCannotMoveAnIdentityToAnotherInstance checks the binding to the
// instance id: a relay that attaches the NAS's sealed name to another
// connection gets a tag failure, not a machine listed under a false name.
func TestARelayCannotMoveAnIdentityToAnotherInstance(t *testing.T) {
	wire, err := sealAnnounce(testFrameKey, Announce{InstanceID: "alpha", Name: "the NAS"})
	if err != nil {
		t.Fatalf("sealAnnounce: %v", err)
	}

	// A hostile relay forwards alpha's blob under bravo's id.
	moved := Announce{InstanceID: "bravo", Sealed: wire.Sealed}
	got := openAnnounce(testFrameKey, moved)
	if got.Name != "" {
		t.Errorf("a moved identity opened as %+v, want nothing usable", got)
	}
	if got.InstanceID != "bravo" {
		t.Errorf("the peer was dropped entirely (%+v); it should still be listed, just unnamed", got)
	}
}

// TestAWrongFrameKeyLeavesThePeerListedButUnnamed keeps a peer on another frame
// key visible, since hiding it would hide the symptom of the key mismatch.
func TestAWrongFrameKeyLeavesThePeerListedButUnnamed(t *testing.T) {
	wire, err := sealAnnounce(testFrameKey, Announce{InstanceID: "alpha", Name: "the NAS"})
	if err != nil {
		t.Fatalf("sealAnnounce: %v", err)
	}
	other := make([]byte, 32)
	for i := range other {
		other[i] = 0x5a
	}

	got := openAnnounce(other, wire)
	if got.InstanceID != "alpha" {
		t.Errorf("the peer vanished: %+v", got)
	}
	if got.Name != "" {
		t.Errorf("a foreign key produced a name: %+v", got)
	}
}

// TestAnAnnounceFromBeforeTheSealIsStillReadable covers a mixed-version group:
// an older instance still sends its identity in the clear.
func TestAnAnnounceFromBeforeTheSealIsStillReadable(t *testing.T) {
	legacy := []byte(`{"instanceId":"alpha","name":"BOTTICH","deployment":"container"}`)
	var a Announce
	if err := json.Unmarshal(legacy, &a); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	got := openAnnounce(testFrameKey, a)
	if got.Name != "BOTTICH" || got.Deployment != "container" {
		t.Errorf("an old peer read as %+v, want its plaintext identity", got)
	}
}

// TestTwoRealClientsStillSeeEachOthersNames runs both sides end to end, which
// catches a seal applied on one side only.
func TestTwoRealClientsStillSeeEachOthersNames(t *testing.T) {
	addr, _ := relayOn(t, "127.0.0.1:0")
	const key = "shared-relay-test-key-0123456789ab"

	alpha := startClient(t, addr, key, "alpha", nil)
	bravo := startClient(t, addr, key, "bravo", nil)
	waitFor(t, "alpha to connect", alpha.Connected)
	waitFor(t, "bravo to connect", bravo.Connected)

	named := func(c *Client, id string) func() bool {
		return func() bool {
			for _, s := range c.Siblings() {
				if s.InstanceID == id {
					// startClient announces Name == id and "desktop".
					return s.Name == id && s.Deployment == "desktop"
				}
			}
			return false
		}
	}
	waitFor(t, "alpha to see bravo by name", named(alpha, "bravo"))
	waitFor(t, "bravo to see alpha by name", named(bravo, "alpha"))
}

// TestOpensAnIdentitySealedByTheMobilePort checks this package against the
// phone's TypeScript port (mobile/src/api/relayFrame.ts); the extension's
// port (extension/src/relay.js) speaks the same frame. A change to the domain,
// separator, field names or nonce framing would pass every Go-only test.
//
// The vector was sealed with @noble/ciphers through relayFrame.ts's
// announceAAD and JSON shape, with a fixed nonce of 0x07 bytes so it is
// reproducible.
func TestOpensAnIdentitySealedByTheMobilePort(t *testing.T) {
	key := DeriveFrameKey([]byte("cross-implementation vector"))
	sealed, err := base64.StdEncoding.DecodeString(
		"BwcHBwcHBwcHBwcHKowzi1tX9hS/RbpFD36F1jz5pHjOvE8p9pXq7oULX/Xf0cCMQxbXtTdsUR7tCWHualBstwHbZzUY0vpg/urebU1me215Eg==")
	if err != nil {
		t.Fatalf("the vector itself is not valid base64: %v", err)
	}

	id, err := OpenIdentity(key, "phone", sealed)
	if err != nil {
		t.Fatalf("could not open an identity the mobile port sealed: %v", err)
	}
	if id.Name != "Pixel 8" || id.Deployment != "mobile" || !id.Client {
		t.Errorf("opened %+v, want the phone's own announce", id)
	}

	if _, err := OpenIdentity(key, "nas", sealed); err == nil {
		t.Error("a mobile-sealed identity opened under an id it was not bound to")
	}
}

// TestAClientFlagSurvivesTheSeal: without the flag a phone would be listed on
// every Instances page as a target that answers 501.
func TestAClientFlagSurvivesTheSeal(t *testing.T) {
	addr, _ := relayOn(t, "127.0.0.1:0")
	const key = "shared-relay-test-key-0123456789ab"

	instance := startClient(t, addr, key, "nas", nil)
	waitFor(t, "the instance to connect", instance.Connected)

	phone, err := NewClient(ClientOptions{
		URL:      "http://" + addr,
		Key:      key,
		FrameKey: testFrameKey,
		Self:     Announce{InstanceID: "phone", Name: "Pixel", Deployment: "mobile", Client: true},
	})
	if err != nil {
		t.Fatalf("new phone: %v", err)
	}
	phone.minBackoff, phone.maxBackoff = testBackoff, 4*testBackoff
	phone.Start()
	defer func() { _ = phone.Close() }()

	deadline := time.Now().Add(wsTimeout)
	for time.Now().Before(deadline) {
		for _, s := range instance.Siblings() {
			if s.InstanceID == "phone" {
				if !s.Client {
					t.Fatalf("the phone arrived as a browsable instance: %+v", s)
				}
				if s.Name != "Pixel" {
					t.Fatalf("the phone arrived as %+v, want its name through the seal", s)
				}
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the instance never saw the phone at all")
}
