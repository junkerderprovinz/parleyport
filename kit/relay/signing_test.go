package relay

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/keys"
	"github.com/junkerderprovinz/parleyport/kit/member"
)

// vectorCall is the call of the vectors file, which every signing vector
// signs.
func vectorCall(t *testing.T) (string, ProxyCall) {
	t.Helper()
	c := loadVectors(t).Call
	return c.Target, ProxyCall{
		ID: c.ID, Method: c.Method, Path: c.Path, Body: []byte(c.Body),
		From: c.From, Kind: member.Kind(c.Kind), Sent: c.Sent,
	}
}

func vectorSigner(t *testing.T, kind member.Kind) member.Identity {
	t.Helper()
	seed, err := hex.DecodeString(loadVectors(t).Member.Seed)
	if err != nil {
		t.Fatal(err)
	}
	return identityOf(kind, seed)
}

// Every member of a group, and every phone and extension that calls it, signs
// these bytes, so a change to the layout locks them all out at once.
func TestCallAndAnswerSignaturesMatchTheVectors(t *testing.T) {
	v := loadVectors(t)
	if len(v.Signing) == 0 {
		t.Fatal("no signing vectors")
	}
	target, call := vectorCall(t)
	signer := vectorSigner(t, member.KindInstance)
	result := ProxyResult{Status: v.Result.Status, Body: []byte(v.Result.Body)}
	sealedCall := decoded(t, v.Result.SealedCall)
	for _, tc := range v.Signing {
		sg := keys.Signing{Call: tc.Call, Result: tc.Result}
		if got := base64.StdEncoding.EncodeToString(signer.Sign(CallMessage(sg, target, call))); got != tc.CallSignature {
			t.Errorf("call signature under %s = %s, want %s", tc.Call, got, tc.CallSignature)
		}
		signed := SignResult(sg, &signer, call.ID, sealedCall, result)
		if got := base64.StdEncoding.EncodeToString(signed.Sig); got != tc.ResultSignature {
			t.Errorf("answer signature under %s = %s, want %s", tc.Result, got, tc.ResultSignature)
		}
		if !VerifyResult(sg, call.ID, signer.ID(), sealedCall, signed) {
			t.Errorf("the vector answer under %s does not verify", tc.Result)
		}
	}
}

func TestEveryFieldOfACallIsSigned(t *testing.T) {
	target, call := vectorCall(t)
	base := CallMessage(testSigning, target, call)
	changed := map[string]func(*ProxyCall){
		"id":     func(c *ProxyCall) { c.ID = "req-8" },
		"method": func(c *ProxyCall) { c.Method = "GET" },
		"path":   func(c *ProxyCall) { c.Path = "/api/tasks" },
		"body":   func(c *ProxyCall) { c.Body = []byte(`{}`) },
		"from":   func(c *ProxyCall) { c.From = "phone-other" },
		"kind":   func(c *ProxyCall) { c.Kind = member.KindInstance },
		"time":   func(c *ProxyCall) { c.Sent++ },
		// A byte moved from one field to the next must not give the same
		// message.
		"boundary": func(c *ProxyCall) { c.Method, c.Path = c.Method+"/", c.Path[1:] },
	}
	for name, change := range changed {
		c := call
		change(&c)
		if bytes.Equal(CallMessage(testSigning, target, c), base) {
			t.Errorf("changing the %s leaves the signed message as it was", name)
		}
	}
	if bytes.Equal(CallMessage(testSigning, "bravo", call), base) {
		t.Error("the target is not part of the signed message")
	}
	if bytes.Equal(CallMessage(keys.Domain("other").Signing(), target, call), base) {
		t.Error("another app's label gives the same message")
	}
}

func TestASignedCallSpeaksForItsIdentity(t *testing.T) {
	phone := vectorSigner(t, member.KindMobile)
	call := SignCall(testSigning, &phone, "r1", alphaID, ProxyCall{Method: "GET", Path: "/api/tasks", From: "somebody else"})
	if call.From != phone.ID() || call.Kind != member.KindMobile {
		t.Errorf("signed as %q, %q; want the phone's own id and kind", call.From, call.Kind)
	}
	if unsigned := SignCall(testSigning, nil, "r1", alphaID, ProxyCall{Method: "GET"}); unsigned.Signed() {
		t.Error("a call without an identity was signed")
	}
}

func TestASignedCallOpensAndAnAlteredOneDoesNot(t *testing.T) {
	phone := vectorSigner(t, member.KindMobile)
	sealed, err := SealSignedCall(testFrameKey, testSigning, &phone, "r1", alphaID, ProxyCall{Method: "GET", Path: "/api/tasks"})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenCall(testFrameKey, testSigning, "r1", alphaID, sealed)
	if err != nil || !opened.Signed() || !bytes.Equal(opened.Key, phone.Public()) {
		t.Fatalf("opened %+v, %v; want the call with its key", opened, err)
	}
	if _, err := OpenCall(testFrameKey, keys.Domain("other").Signing(), "r1", alphaID, sealed); !errors.Is(err, ErrSignature) {
		t.Errorf("a call signed for another app opened with %v, want ErrSignature", err)
	}

	// Anybody holding the phrase can seal a call again, so an altered copy
	// with the old signature is what a member would try.
	altered := opened
	altered.Path = "/api/settings"
	if _, err := OpenCall(testFrameKey, testSigning, "r1", alphaID, mustSeal(t, "r1", alphaID, altered)); !errors.Is(err, ErrSignature) {
		t.Errorf("an altered signed call opened with %v, want ErrSignature", err)
	}
	other := opened
	other.Key = identityFrom(1).Public()
	if _, err := OpenCall(testFrameKey, testSigning, "r1", alphaID, mustSeal(t, "r1", alphaID, other)); !errors.Is(err, ErrSignature) {
		t.Errorf("a signature presented with another key opened with %v, want ErrSignature", err)
	}
	short := opened
	short.Key = short.Key[:10]
	if _, err := OpenCall(testFrameKey, testSigning, "r1", alphaID, mustSeal(t, "r1", alphaID, short)); !errors.Is(err, ErrSignature) {
		t.Errorf("a key of the wrong length opened with %v, want ErrSignature", err)
	}
}

func TestACallWithoutItsIDAndTimeIsRefused(t *testing.T) {
	plain, err := json.Marshal(struct {
		Method string `json:"method"`
		Path   string `json:"path"`
	}{http.MethodGet, "/api/tasks"})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := seal(testFrameKey, requestAAD("r1", alphaID), plain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCall(testFrameKey, testSigning, "r1", alphaID, sealed); err == nil {
		t.Fatal("a call sealed without its request id opened")
	}
}

func TestABrokenSignatureIsAnsweredAndNeverServed(t *testing.T) {
	addr, _ := relayOn(t, "127.0.0.1:0")
	served := make(chan string, 2)
	alpha := startClient(t, addr, "shared-relay-test-key-0123456789ab", alphaID, func(_ context.Context, call ProxyCall) (int, []byte) {
		served <- call.Path
		return http.StatusOK, nil
	})
	waitFor(t, "alpha to connect", alpha.Connected)
	bravo := dialInstance(t, "ws://"+addr+connectPath, "shared-relay-test-key-0123456789ab", bravoID)
	readFrame(t, bravo, TypeAnnounce)

	sealed, err := SealSignedCall(testFrameKey, testSigning, &bravoKey, "r1", alphaID, ProxyCall{Method: http.MethodGet, Path: "/api/tasks"})
	if err != nil {
		t.Fatal(err)
	}
	call := openFrom(t, "r1", alphaID, sealed)
	call.Path = "/api/queue/stop"
	writeFrame(t, bravo, TypeProxyRequest, ProxyRequest{RequestID: "r1", Target: alphaID, Sealed: mustSeal(t, "r1", alphaID, call)})

	var resp ProxyResponse
	if err := readFrame(t, bravo, TypeProxyResponse).Into(&resp); err != nil {
		t.Fatal(err)
	}
	res := openResultFrom(t, "r1", resp.Sealed)
	if res.Status != http.StatusForbidden || !bytes.Contains(res.Body, []byte(`"memberSignature"`)) {
		t.Fatalf("a broken signature got %d %s, want 403 with its code", res.Status, res.Body)
	}
	select {
	case path := <-served:
		t.Fatalf("the altered call to %s was served", path)
	case <-time.After(100 * time.Millisecond):
	}
}

// The instance serving a call learns which relay connection it came through as
// the relay says, not as the call claims.
func TestACallIsServedWithTheConnectionThatSentIt(t *testing.T) {
	addr, _ := relayOn(t, "127.0.0.1:0")
	sources := make(chan string, 1)
	alpha := startClient(t, addr, "shared-relay-test-key-0123456789ab", alphaID, func(ctx context.Context, _ ProxyCall) (int, []byte) {
		sources <- SourceOf(ctx)
		return http.StatusOK, nil
	})
	waitFor(t, "alpha to connect", alpha.Connected)
	bravo := dialInstance(t, "ws://"+addr+connectPath, "shared-relay-test-key-0123456789ab", bravoID)
	readFrame(t, bravo, TypeAnnounce)
	call := ProxyCall{Method: http.MethodGet, Path: "/api/tasks", ID: "r1", Sent: time.Now().Unix()}
	writeFrame(t, bravo, TypeProxyRequest, ProxyRequest{RequestID: "r1", Target: alphaID, Sender: charlieID, Sealed: mustSeal(t, "r1", alphaID, call)})
	select {
	case got := <-sources:
		if got != "relay\x00"+bravoID {
			t.Errorf("the call was served as from %q, want bravo's connection", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the call was never served")
	}
}

// Whoever holds the phrase can seal an answer, such as a "removed" that makes a
// device forget its group, but only the target can sign one.
func TestAnAnswerCountsOnlySignedByTheTargetsKey(t *testing.T) {
	v := loadVectors(t)
	target := vectorSigner(t, member.KindInstance)
	forger := identityFrom(9)
	result := ProxyResult{Status: v.Result.Status, Body: []byte(v.Result.Body)}
	call := decoded(t, v.Result.SealedCall)
	alteredCall := bytes.Clone(call)
	alteredCall[len(alteredCall)-1] ^= 1
	signed := SignResult(testSigning, &target, "r1", call, result)
	if !VerifyResult(testSigning, "r1", target.ID(), call, signed) {
		t.Fatal("the target's own answer does not verify")
	}
	restated := signed
	restated.Status = http.StatusOK
	borrowed := SignResult(testSigning, &forger, "r1", call, result)
	borrowed.Key = target.Public()
	for name, r := range map[string]ProxyResult{
		"unsigned":                     result,
		"signed by another key":        SignResult(testSigning, &forger, "r1", call, result),
		"signed with the key borrowed": borrowed,
		"with its status changed":      restated,
		"to another request":           SignResult(testSigning, &target, "r2", call, result),
		"to another call":              SignResult(testSigning, &target, "r1", []byte("another call"), result),
		"to the call altered":          SignResult(testSigning, &target, "r1", alteredCall, result),
		"for another app":              SignResult(keys.Domain("other").Signing(), &target, "r1", call, result),
	} {
		if VerifyResult(testSigning, "r1", target.ID(), call, r) {
			t.Errorf("an answer %s verifies as the target's", name)
		}
	}
}
