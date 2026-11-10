package relay

// The relay server reads Announce.InstanceID only (matching a reconnect,
// addressing a presence frame, picking a proxy target) and never the name,
// deployment or client flag. These tests pin that the relay keeps what it
// routes on and gets nothing else.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/junkerderprovinz/parleyport/kit/keys"
	"github.com/junkerderprovinz/parleyport/kit/member"
)

func TestAnnounceRoundTripsThroughTheSeal(t *testing.T) {
	in := Announce{InstanceID: alphaID, Name: "CELLAR", Deployment: "container", Client: true, Address: "https://alpha.example.org"}

	wire, err := sealAnnounce(testFrameKey, in)
	if err != nil {
		t.Fatalf("sealAnnounce: %v", err)
	}
	if wire.Name != "" || wire.Deployment != "" || wire.Client || wire.Address != "" {
		t.Errorf("wire form still carries identity: %+v", wire)
	}
	if wire.InstanceID != alphaID {
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
		InstanceID: alphaID,
		Name:       "owner-workstation",
		Deployment: "desktop",
		Address:    "https://alpha.example.org",
	})
	if err != nil {
		t.Fatalf("sealAnnounce: %v", err)
	}
	frame, err := Encode(TypeAnnounce, wire)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	for _, secret := range []string{"owner-workstation", "desktop", "alpha.example.org"} {
		if bytes.Contains(frame, []byte(secret)) {
			t.Errorf("the encoded announce contains %q in the clear:\n%s", secret, frame)
		}
	}
	if !bytes.Contains(frame, []byte(alphaID)) {
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

func TestTheLargestAnswerFitsAFrame(t *testing.T) {
	if MaxAnswerBytes < 8<<20 {
		t.Fatalf("a relay frame carries an answer of %d bytes, want at least 8 MiB", MaxAnswerBytes)
	}
	id := strings.Repeat("f", 32)
	res := SignResult(testSigning, &alphaKey, id, []byte("call"), ProxyResult{Status: http.StatusOK, Body: make([]byte, MaxAnswerBytes)})
	frame, err := Encode(TypeProxyResponse, ProxyResponse{RequestID: id, Sealed: sealResultFor(t, id, res)})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(frame) > readLimit {
		t.Fatalf("the largest answer is a frame of %d bytes, over the %d a relay reads", len(frame), readLimit)
	}
}

func TestAnAddressTooLongIsLeftOutRatherThanCut(t *testing.T) {
	long := "https://" + strings.Repeat("a", MaxAddressBytes)
	wire, err := sealAnnounce(testFrameKey, Announce{InstanceID: alphaID, Address: long})
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
	wire, err := sealAnnounce(testFrameKey, Announce{InstanceID: alphaID, Name: "the NAS"})
	if err != nil {
		t.Fatalf("sealAnnounce: %v", err)
	}

	// A hostile relay forwards alpha's blob under bravo's id.
	moved := Announce{InstanceID: bravoID, Sealed: wire.Sealed}
	got := openAnnounce(testFrameKey, moved)
	if got.Name != "" {
		t.Errorf("a moved identity opened as %+v, want nothing usable", got)
	}
	if got.InstanceID != bravoID {
		t.Errorf("the peer was dropped entirely (%+v); it should still be listed, just unnamed", got)
	}
}

// TestAWrongFrameKeyLeavesThePeerListedButUnnamed keeps a peer on another frame
// key visible, since hiding it would hide the symptom of the key mismatch.
func TestAWrongFrameKeyLeavesThePeerListedButUnnamed(t *testing.T) {
	wire, err := sealAnnounce(testFrameKey, Announce{InstanceID: alphaID, Name: "the NAS"})
	if err != nil {
		t.Fatalf("sealAnnounce: %v", err)
	}
	other := make([]byte, 32)
	for i := range other {
		other[i] = 0x5a
	}

	got := openAnnounce(other, wire)
	if got.InstanceID != alphaID {
		t.Errorf("the peer vanished: %+v", got)
	}
	if got.Name != "" {
		t.Errorf("a foreign key produced a name: %+v", got)
	}
}

// TestAnIdentitySentInTheClearIsIgnored: the relay can write an unsealed
// announce for any id, so its name, address and client flag would let it list
// a phishing address under a member's id or invent phones.
func TestAnIdentitySentInTheClearIsIgnored(t *testing.T) {
	plain := []byte(`{"instanceId":"` + nasID + `","name":"NAS","deployment":"mobile","client":true,"address":"https://login.example.net"}`)
	var a Announce
	if err := json.Unmarshal(plain, &a); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	got := openAnnounce(testFrameKey, a)
	if got.InstanceID != nasID || got.Name != "" || got.Deployment != "" || got.Client || got.Address != "" {
		t.Errorf("an unsealed announce read as %+v, want only its bare id", got)
	}
}

// hostileRelay accepts one client, reads its hello and sends it frames, as a
// relay operator could. It returns the address to dial.
func hostileRelay(t *testing.T, frames ...[]byte) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.CloseNow() }()
		challenge := frameOf(TypeChallenge, Challenge{Nonce: make([]byte, challengeSize)})
		if err := c.Write(r.Context(), websocket.MessageText, challenge); err != nil {
			return
		}
		if _, _, err := c.Read(r.Context()); err != nil {
			return
		}
		for _, f := range frames {
			if err := c.Write(r.Context(), websocket.MessageText, f); err != nil {
				return
			}
		}
		_, _, _ = c.Read(r.Context())
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func sealedAnnounce(t *testing.T, a Announce) []byte {
	t.Helper()
	wire, err := sealAnnounce(testFrameKey, a)
	if err != nil {
		t.Fatalf("sealAnnounce: %v", err)
	}
	return frameOf(TypeAnnounce, wire)
}

func TestAnInstanceUnderAnIDOfAnotherShapeIsNotListed(t *testing.T) {
	url := hostileRelay(t,
		sealedAnnounce(t, Announce{InstanceID: "nas", Name: "NAS", Deployment: "container"}),
		sealedAnnounce(t, Announce{InstanceID: "phone-1", Name: "Pixel", Deployment: "mobile", Client: true}),
		sealedAnnounce(t, Announce{InstanceID: bravoID, Name: "Laptop", Deployment: "desktop"}),
	)
	c := startClient(t, strings.TrimPrefix(url, "http://"), "shared-relay-test-key-0123456789ab", alphaID, nil)
	waitFor(t, "the last announce to arrive", func() bool {
		for _, s := range c.Siblings() {
			if s.InstanceID == bravoID {
				return true
			}
		}
		return false
	})
	var ids []string
	for _, s := range c.Siblings() {
		ids = append(ids, s.InstanceID)
	}
	if len(ids) != 2 || ids[0] != bravoID || ids[1] != "phone-1" {
		t.Fatalf("siblings = %v, want the laptop and the phone; an instance has to carry an id shaped like one", ids)
	}
}

func TestARelayCannotGrowTheSiblingListWithoutBound(t *testing.T) {
	var frames [][]byte
	id := func(i int) string { return fmt.Sprintf("%040x", i+1) }
	for i := 0; i < maxClientsPerKey+10; i++ {
		frames = append(frames, sealedAnnounce(t, Announce{InstanceID: id(i)}))
	}
	// Frames are handled in order, so once this one has, every announce has.
	frames = append(frames, frameOf(TypePresence, Presence{InstanceID: id(0)}))
	url := hostileRelay(t, frames...)

	c := startClient(t, strings.TrimPrefix(url, "http://"), "shared-relay-test-key-0123456789ab", alphaID, nil)
	waitFor(t, "the flood to be handled", func() bool {
		sibs := c.Siblings()
		return len(sibs) > 0 && sibs[0].InstanceID != id(0)
	})
	if got := len(c.Siblings()); got != maxClientsPerKey-1 {
		t.Fatalf("%d siblings after the flood, want %d", got, maxClientsPerKey-1)
	}
}

// TestTwoRealClientsStillSeeEachOthersNames runs both sides end to end, which
// catches a seal applied on one side only.
func TestTwoRealClientsStillSeeEachOthersNames(t *testing.T) {
	addr, _ := relayOn(t, "127.0.0.1:0")
	const key = "shared-relay-test-key-0123456789ab"

	alpha := startClient(t, addr, key, alphaID, nil)
	bravo := startClient(t, addr, key, bravoID, nil)
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
	waitFor(t, "alpha to see bravo by name", named(alpha, bravoID))
	waitFor(t, "bravo to see alpha by name", named(bravo, alphaID))
}

// Another implementation sealed this identity, so the test fails if either
// side changes the label, separator, field names or nonce framing.
func TestOpensAnIdentitySealedByAnotherImplementation(t *testing.T) {
	v := loadVectors(t).Sealed
	key := keys.Domain(v.Domain).FrameKey([]byte(v.Secret))
	sealed := decoded(t, v.Identity.Sealed)
	id, err := OpenIdentity(key, v.Identity.InstanceID, sealed)
	if err != nil {
		t.Fatalf("could not open the vector identity: %v", err)
	}
	if id.Name != v.Identity.Name || id.Deployment != v.Identity.Deployment || id.Client != v.Identity.Client {
		t.Errorf("opened %+v, want %+v", id, v.Identity)
	}
	if _, err := OpenIdentity(key, nasID, sealed); err == nil {
		t.Error("the vector identity opened under an id it was not bound to")
	}
}

// TestAClientFlagSurvivesTheSeal: without the flag a phone would be listed by
// every instance as a target that answers 501.
func TestAClientFlagSurvivesTheSeal(t *testing.T) {
	addr, _ := relayOn(t, "127.0.0.1:0")
	const key = "shared-relay-test-key-0123456789ab"

	instance := startClient(t, addr, key, nasID, nil)
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

func TestAClientsMemberIDTravelsInsideTheSeal(t *testing.T) {
	member := strings.Repeat("b", 40)
	wire, err := sealAnnounce(testFrameKey, Announce{InstanceID: alphaID, Deployment: "extension", Client: true, Member: member})
	if err != nil {
		t.Fatalf("sealAnnounce: %v", err)
	}
	frame, err := Encode(TypeAnnounce, wire)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if bytes.Contains(frame, []byte(member)) {
		t.Errorf("the encoded announce carries the member id in the clear:\n%s", frame)
	}
	if got := openAnnounce(testFrameKey, wire).Member; got != member {
		t.Fatalf("member arrived as %q, want %q", got, member)
	}

	// Only a client is known by a member id; an instance is addressed by the
	// id it routes on.
	wire, err = sealAnnounce(testFrameKey, Announce{InstanceID: alphaID, Deployment: "container", Member: member})
	if err != nil {
		t.Fatalf("sealAnnounce: %v", err)
	}
	if got := openAnnounce(testFrameKey, wire).Member; got != "" {
		t.Fatalf("an instance arrived with member %q", got)
	}
}

func TestTheLargestClientHelloFitsTheLimit(t *testing.T) {
	wire, err := sealAnnounce(testFrameKey, Announce{
		InstanceID: strings.Repeat("f", maxClientIDBytes),
		Name:       strings.Repeat("<", MaxNameBytes),
		Deployment: "extension",
		Client:     true,
		Member:     strings.Repeat("<", maxClientIDBytes),
	})
	if err != nil {
		t.Fatalf("sealAnnounce: %v", err)
	}
	browser := identityOf(member.KindExtension, bytes.Repeat([]byte{0x2a}, 32))
	proof := browser.ProveHello(strings.Repeat("k", 64), strings.Repeat("r", 253), make([]byte, challengeSize))
	frame, err := Encode(TypeHello, Hello{Key: strings.Repeat("k", 64), Announce: wire, Proof: proof})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(frame) > helloLimit {
		t.Fatalf("the largest client hello is %d bytes, over the %d the relay reads", len(frame), helloLimit)
	}
}

// TestAHelloIsReadAsTheAppWritesIt decodes the hello of the vectors as a phone
// writes it, by hand rather than through Encode, so a renamed tag on Hello or
// Proof cannot slip past both sides of a round trip.
func TestAHelloIsReadAsTheAppWritesIt(t *testing.T) {
	v := loadVectors(t)
	h := v.Member.Hello
	id := v.Member.IDs[h.Kind]
	frame := `{"type":"hello","data":{"key":"` + h.RelayKey + `","proof":{"kind":"` + h.Kind + `","relay":"` + h.RelayHost +
		`","key":"` + v.Member.PublicKey + `","sig":"` + h.Signature +
		`"},"announce":{"instanceId":"` + id + `","sealed":"AAAA"}}}`
	env, err := Decode([]byte(frame))
	if err != nil {
		t.Fatal(err)
	}
	var hello Hello
	if err := env.Into(&hello); err != nil {
		t.Fatal(err)
	}
	if !hello.proves(decoded(t, h.Challenge), []string{h.RelayHost}) {
		t.Fatal("the app's hello does not prove its id")
	}
}
