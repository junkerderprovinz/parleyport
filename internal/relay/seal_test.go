package relay

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"testing"
	"time"
)

func TestSealedCallRoundTrips(t *testing.T) {
	key := DeriveFrameKey([]byte("a secret"))
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
	key := DeriveFrameKey([]byte("a secret"))
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

// TestRelayKeyDoesNotYieldTheFrameKey: the relay receives DeriveKey's output
// in every hello, so the frame key must not be computable from it.
func TestRelayKeyDoesNotYieldTheFrameKey(t *testing.T) {
	secret := []byte("a secret")
	relayKey := DeriveKey(secret)
	frameKey := DeriveFrameKey(secret)

	// The same hash without a separate domain would give the same bytes.
	if hex.EncodeToString(frameKey) == relayKey {
		t.Fatal("the frame key and the relay key are the same value, so the relay would hold both")
	}
	if bytes.Equal(frameKey, FrameKeyFromRelayKey(relayKey)) {
		t.Fatal("the frame key is derivable from the relay key the relay is already given")
	}
	if len(frameKey) != 32 {
		t.Fatalf("frame key is %d bytes, want 32 for AES-256", len(frameKey))
	}
}

// TestSealIsBoundToItsRouting: RequestID and Target travel in the clear, and
// binding them into the AEAD stops a relay from delivering a sealed call to
// another instance and having it open there.
func TestSealIsBoundToItsRouting(t *testing.T) {
	key := DeriveFrameKey([]byte("a secret"))
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
	key := DeriveFrameKey([]byte("a secret"))
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
	key := DeriveFrameKey([]byte("a secret"))
	other := DeriveFrameKey([]byte("a different secret"))
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
	key := DeriveFrameKey([]byte("a secret"))
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

// TestOpensAFrameSealedByTheMobilePort checks this package against the phone's
// TypeScript implementation (mobile/src/api/relayFrame.ts). The frame was
// sealed by that code, so the test fails if either side changes the framing,
// the additional data, the domain string or the JSON field names. Its nonce
// is a fixed run of 0x03 so the vector is reproducible.
func TestOpensAFrameSealedByTheMobilePort(t *testing.T) {
	key := DeriveFrameKey([]byte("cross-implementation vector"))
	sealed, err := base64.StdEncoding.DecodeString(
		"AwMDAwMDAwMDAwMDAXqxEhwJlzwnjSCTaEIl6yMvi98geuQjUvrQqyH8fBq7GmILoC34oL2V8ZfcU3G2JuI/liRh+cyXI7fOVBKffbJbA+V7b5nzgkzepCne/45/VHY=")
	if err != nil {
		t.Fatalf("the vector itself is not valid base64: %v", err)
	}

	call, err := OpenCall(key, "req-2", "alpha", sealed)
	if err != nil {
		t.Fatalf("could not open a frame the mobile port sealed: %v", err)
	}
	if call.Method != "GET" || call.Path != "/api/tasks" || call.ID != "req-2" || call.Sent != 1_800_000_000 {
		t.Errorf("opened %+v, want the GET /api/tasks the phone sealed as req-2 at 1800000000", call)
	}

	if _, err := OpenCall(key, "req-2", "charlie", sealed); err == nil {
		t.Error("a mobile-sealed call opened under a target it was not addressed to")
	}
}

// TestFrameKeyVectors pins the derivation to fixed bytes, since the mobile
// app's TypeScript port (mobile/src/relay/) has to agree byte for byte. The
// values are the SHA-256 of the domain string followed by the secret,
// computed independently with sha256sum:
//
//	printf 'knightloader/relay/frame-key/v1' | sha256sum
//	printf 'knightloader/relay/frame-key/v1knightloader' | sha256sum
func TestFrameKeyVectors(t *testing.T) {
	cases := []struct {
		secret string
		want   string
	}{
		{"", "a94ace9821d4aa96f2f8c4bb250e2937a59655f53a14ba74c3e589d5f71f17b9"},
		{"knightloader", "e04113452443266a47195c6b866225201d6312a88a6cfc0e2af1ecf5a4beeb88"},
	}
	for _, tc := range cases {
		got := hex.EncodeToString(DeriveFrameKey([]byte(tc.secret)))
		if got != tc.want {
			t.Errorf("DeriveFrameKey(%q) = %s, want %s", tc.secret, got, tc.want)
		}
	}
}
