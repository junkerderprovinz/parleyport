package relay

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/keys"
)

func TestSealedCallRoundTrips(t *testing.T) {
	key := frameKeyFor("a secret")
	want := ProxyCall{
		Method: http.MethodPost,
		Path:   "/api/links",
		Body:   []byte(`{"url":"https://example.invalid/holiday-photos.zip"}`),
		From:   "phone-a-real-looking-member",
	}
	sealed, err := SealCall(key, "r1", "bravo", want)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := OpenCall(key, testSigning, "r1", "bravo", sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got.Method != want.Method || got.Path != want.Path || got.From != want.From {
		t.Errorf("opened %+v, want %+v", got, want)
	}
	if !bytes.Equal(got.Body, want.Body) {
		t.Errorf("body opened as %s, want it byte for byte", got.Body)
	}
	if got.ID != "r1" || time.Since(time.Unix(got.Sent, 0)) > time.Minute {
		t.Errorf("opened id %q sent at %d, want r1 stamped now", got.ID, got.Sent)
	}
}

// TestSealedFrameHidesItsContents checks that nothing a relay operator would
// want appears in the bytes crossing the relay.
func TestSealedFrameHidesItsContents(t *testing.T) {
	key := frameKeyFor("a secret")
	sealed, err := SealCall(key, "r1", "bravo", ProxyCall{
		Method: http.MethodPost,
		Path:   "/api/links",
		Body:   []byte(`{"url":"https://example.invalid/holiday-photos.zip"}`),
		From:   "phone-a-real-looking-member",
	})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	for _, secret := range []string{
		"/api/links",
		"holiday-photos",
		"example.invalid",
		"a-real-looking-member",
		http.MethodPost,
	} {
		if bytes.Contains(sealed, []byte(secret)) {
			t.Errorf("the sealed frame contains %q in the clear", secret)
		}
	}
}

// TestSealIsBoundToItsRouting: RequestID and Target travel in the clear, and
// binding them into the AEAD stops a relay from delivering a sealed call to
// another instance and having it open there.
func TestSealIsBoundToItsRouting(t *testing.T) {
	key := frameKeyFor("a secret")
	sealed, err := SealCall(key, "r1", "bravo", ProxyCall{Method: "GET", Path: "/api/tasks"})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := OpenCall(key, testSigning, "r1", "charlie", sealed); err == nil {
		t.Error("a call addressed to bravo opened as one addressed to charlie")
	}
	if _, err := OpenCall(key, testSigning, "r2", "bravo", sealed); err == nil {
		t.Error("a call opened under a request id it was not sealed with")
	}
}

// TestSealedResultIsNotAcceptedAsACall: the directions use different labels in
// their additional data, so a relay cannot replay a peer's reply as a request
// addressed back at it.
func TestSealedResultIsNotAcceptedAsACall(t *testing.T) {
	key := frameKeyFor("a secret")
	sealed, err := SealResult(key, "r1", ProxyResult{Status: 200, Body: []byte("ok")})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := OpenCall(key, testSigning, "r1", "bravo", sealed); err == nil {
		t.Error("a sealed result opened as a sealed call")
	}
}

// TestWrongKeyAndTamperingFail: a peer without the group's secret and a relay
// that edits a frame in flight both produce nothing that opens.
func TestWrongKeyAndTamperingFail(t *testing.T) {
	key := frameKeyFor("a secret")
	other := frameKeyFor("a different secret")
	sealed, err := SealCall(key, "r1", "bravo", ProxyCall{Method: "GET", Path: "/api/tasks"})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	if _, err := OpenCall(other, testSigning, "r1", "bravo", sealed); err == nil {
		t.Error("a frame opened under a key it was not sealed with")
	}

	for _, at := range []int{0, nonceLen, len(sealed) - 1} {
		tampered := bytes.Clone(sealed)
		tampered[at] ^= 0xff
		if _, err := OpenCall(key, testSigning, "r1", "bravo", tampered); err == nil {
			t.Errorf("a frame with byte %d flipped still opened", at)
		}
	}

	if _, err := OpenCall(key, testSigning, "r1", "bravo", sealed[:nonceLen-1]); err == nil {
		t.Error("a frame too short to hold a nonce still opened")
	}
	if _, err := OpenCall(key, testSigning, "r1", "bravo", nil); err == nil {
		t.Error("an absent frame opened; an unsealed call must never look like a valid one")
	}
}

// TestNonceIsNotReused: a repeated nonce under AES-GCM repeats the keystream
// and leaks the authentication key.
func TestNonceIsNotReused(t *testing.T) {
	key := frameKeyFor("a secret")
	call := ProxyCall{Method: "GET", Path: "/api/tasks"}
	seen := map[string]bool{}
	for i := 0; i < 128; i++ {
		sealed, err := SealCall(key, "r1", "bravo", call)
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		nonce := string(sealed[:nonceLen])
		if seen[nonce] {
			t.Fatal("the same nonce was used twice for the same key")
		}
		seen[nonce] = true
	}
}

// Another implementation sealed this frame, so the test fails if either side
// changes the framing, the additional data or the JSON field names.
func TestOpensAFrameSealedByAnotherImplementation(t *testing.T) {
	v := loadVectors(t).Sealed
	key := keys.Domain(v.Domain).FrameKey([]byte(v.Secret))
	call, err := OpenCall(key, testSigning, v.Call.RequestID, v.Call.Target, decoded(t, v.Call.Sealed))
	if err != nil {
		t.Fatalf("could not open the vector frame: %v", err)
	}
	if call.Method != v.Call.Method || call.Path != v.Call.Path || call.ID != v.Call.RequestID || call.Sent != v.Call.Sent {
		t.Errorf("opened %+v, want %+v", call, v.Call)
	}
	if _, err := OpenCall(key, testSigning, v.Call.RequestID, "charlie", decoded(t, v.Call.Sealed)); err == nil {
		t.Error("the vector frame opened under a target it was not addressed to")
	}
}

func FuzzOpenCall(f *testing.F) {
	sealed, err := SealCall(testFrameKey, "r1", "bravo", ProxyCall{Method: "GET", Path: "/api/tasks"})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(sealed)
	f.Add([]byte{})
	f.Add(make([]byte, nonceLen+16))
	f.Fuzz(func(t *testing.T, b []byte) {
		call, err := OpenCall(testFrameKey, testSigning, "r1", "bravo", b)
		if err == nil && call.ID != "r1" {
			t.Fatalf("opened a call stamped %q under r1", call.ID)
		}
	})
}
