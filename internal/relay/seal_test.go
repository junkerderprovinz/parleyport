package relay

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"testing"
	"time"
)

func TestSealedCallRoundTrips(t *testing.T) {
	key := frameKeyFor("a secret")
	want := ProxyCall{
		Method:        http.MethodPost,
		Path:          "/api/links",
		Body:          []byte(`{"url":"https://example.invalid/holiday-photos.zip"}`),
		Authorization: "Bearer a-real-looking-token",
	}
	sealed, err := SealCall(key, "r1", "bravo", want)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := OpenCall(key, "r1", "bravo", sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got.Method != want.Method || got.Path != want.Path || got.Authorization != want.Authorization {
		t.Errorf("opened %+v, want %+v", got, want)
	}
	if !bytes.Equal(got.Body, want.Body) {
		t.Errorf("body opened as %s, want it byte for byte", got.Body)
	}
	if got.ID != "r1" || time.Since(time.Unix(got.Sent, 0)) > time.Minute {
		t.Errorf("opened id %q sent at %d, want r1 stamped now", got.ID, got.Sent)
	}
}

// TestSealedFrameHidesItsContents checks the claim the connection card makes:
// nothing a relay operator would want appears in the bytes crossing the relay.
func TestSealedFrameHidesItsContents(t *testing.T) {
	key := frameKeyFor("a secret")
	sealed, err := SealCall(key, "r1", "bravo", ProxyCall{
		Method:        http.MethodPost,
		Path:          "/api/links",
		Body:          []byte(`{"url":"https://example.invalid/holiday-photos.zip"}`),
		Authorization: "Bearer a-real-looking-token",
	})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	for _, secret := range []string{
		"/api/links",
		"holiday-photos",
		"example.invalid",
		"Bearer",
		"a-real-looking-token",
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
	if _, err := OpenCall(key, "r1", "charlie", sealed); err == nil {
		t.Error("a call addressed to bravo opened as one addressed to charlie")
	}
	if _, err := OpenCall(key, "r2", "bravo", sealed); err == nil {
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
	if _, err := OpenCall(key, "r1", "bravo", sealed); err == nil {
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

	if _, err := OpenCall(other, "r1", "bravo", sealed); err == nil {
		t.Error("a frame opened under a key it was not sealed with")
	}

	for _, at := range []int{0, nonceLen, len(sealed) - 1} {
		tampered := bytes.Clone(sealed)
		tampered[at] ^= 0xff
		if _, err := OpenCall(key, "r1", "bravo", tampered); err == nil {
			t.Errorf("a frame with byte %d flipped still opened", at)
		}
	}

	if _, err := OpenCall(key, "r1", "bravo", sealed[:nonceLen-1]); err == nil {
		t.Error("a frame too short to hold a nonce still opened")
	}
	if _, err := OpenCall(key, "r1", "bravo", nil); err == nil {
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

// crossImplementationKey is the frame key the cross-implementation vectors
// were sealed under, as a client derives it from the secret
// "cross-implementation vector".
var crossImplementationKey = hexKey("822dfcd6a000854bba57361cd2090c2a062e87db34f4996c232d000c522f1acf")

// TestOpensAFrameSealedByATypeScriptClient checks this package against a
// client's TypeScript implementation of the frame. The frame was sealed by
// that code, so the test fails if either side changes the framing, the
// additional data, the domain string or the JSON field names. Its nonce is a
// fixed run of 0x03 so the vector is reproducible.
func TestOpensAFrameSealedByATypeScriptClient(t *testing.T) {
	sealed, err := base64.StdEncoding.DecodeString(
		"AwMDAwMDAwMDAwMDAXqxEhwJlzwnjSCTaEIl6yMvi98geuQjUvrQqyH8fBq7GmILoC34oL2V8ZfcU3G2JuI/liRh+cyXI7fOVBKffbJbA+V7b5nzgkzepCne/45/VHY=")
	if err != nil {
		t.Fatalf("the vector itself is not valid base64: %v", err)
	}

	call, err := OpenCall(crossImplementationKey, "req-2", "alpha", sealed)
	if err != nil {
		t.Fatalf("could not open a frame the TypeScript client sealed: %v", err)
	}
	if call.Method != "GET" || call.Path != "/api/tasks" || call.ID != "req-2" || call.Sent != 1_800_000_000 {
		t.Errorf("opened %+v, want the GET /api/tasks the client sealed as req-2 at 1800000000", call)
	}

	if _, err := OpenCall(crossImplementationKey, "req-2", "charlie", sealed); err == nil {
		t.Error("a call sealed in TypeScript opened under a target it was not addressed to")
	}
}
