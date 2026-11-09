package relay

// Some clients write their hello the moment the socket opens, never prove
// their id and skip every frame type they do not know. The tests here speak to
// the relay exactly that way, with frames spelled the way such a client
// spells them, so a change to the relay that would leave it behind fails here.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/coder/websocket"
)

// helloFirstRelayKey is a client's relay key for the all-zero group secret.
const helloFirstRelayKey = "c1d52cbdb3cf9da68feb37b64543669aeb532e80e81c84390582f8e8dd70a4ee"

// helloFirstFrameKey is the frame key that client derives from the same secret.
var helloFirstFrameKey = hexKey("b963fcbcace874083a9215283d6d807b2d7a05749ea9633858efccd4b7bc77e8")

// These ids are 16 random bytes in hex.
const (
	unprovenA = "0123456789abcdef0123456789abcdef"
	unprovenB = "fedcba9876543210fedcba9876543210"
)

// dialHelloFirst connects as a hello-first instance on key: the hello goes out
// before anything is read, with the identity such a client seals.
func dialHelloFirst(t *testing.T, url, key, id string) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wsTimeout)
	defer cancel()
	c, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("dial %s as %s: %v", url, id, err)
	}
	t.Cleanup(func() { _ = c.CloseNow() })
	identity, _ := json.Marshal(map[string]string{"name": "instance " + id[:4], "version": "2.4.0"})
	sealed, err := seal(helloFirstFrameKey, announceAAD(id), identity)
	if err != nil {
		t.Fatal(err)
	}
	hello := `{"type":"hello","data":{"key":"` + key + `","announce":{"instanceId":"` + id +
		`","sealed":"` + base64.StdEncoding.EncodeToString(sealed) + `"}}}`
	if err := c.Write(ctx, websocket.MessageText, []byte(hello)); err != nil {
		t.Fatalf("hello: %v", err)
	}
	return c
}

// readAsHelloFirst returns the next frame a hello-first client acts on, raw,
// skipping the types it does not know the way that client does.
func readAsHelloFirst(t *testing.T, c *websocket.Conn, want string) (Envelope, []byte) {
	t.Helper()
	for {
		ctx, cancel := context.WithTimeout(context.Background(), wsTimeout)
		_, frame, err := c.Read(ctx)
		cancel()
		if err != nil {
			t.Fatalf("waiting for a %s frame: %v", want, err)
		}
		env, err := Decode(frame)
		if err != nil {
			continue
		}
		switch env.Type {
		case TypeAnnounce, TypePresence, TypeProxyRequest, TypeProxyResponse:
		default:
			continue
		}
		if env.Type != want {
			t.Fatalf("got a %q frame, want %q", env.Type, want)
		}
		return env, frame
	}
}

func writeRaw(t *testing.T, c *websocket.Conn, frame string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wsTimeout)
	defer cancel()
	if err := c.Write(ctx, websocket.MessageText, []byte(frame)); err != nil {
		t.Fatal(err)
	}
}

func TestHelloFirstInstancesMeetAndCallEachOther(t *testing.T) {
	srv := httptest.NewServer(New())
	t.Cleanup(srv.Close)
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/relay/connect"
	a := dialHelloFirst(t, url, helloFirstRelayKey, unprovenA)
	b := dialHelloFirst(t, url, helloFirstRelayKey, unprovenB)

	var sib Announce
	if env, _ := readAsHelloFirst(t, b, TypeAnnounce); env.Into(&sib) != nil || sib.InstanceID != unprovenA {
		t.Fatalf("b was introduced to %+v, want a", sib)
	}
	plain, err := open(helloFirstFrameKey, announceAAD(unprovenA), sib.Sealed)
	if err != nil || !strings.Contains(string(plain), `"version":"2.4.0"`) {
		t.Fatalf("a's sealed identity arrived as %q (%v), want what a sealed", plain, err)
	}
	readAsHelloFirst(t, a, TypeAnnounce)

	// An Android client writes the call with org.json, in this key order.
	call := `{"method":"GET","path":"/api/peer/status","id":"r1","sent":1760000000}`
	sealedCall, err := seal(helloFirstFrameKey, requestAAD("r1", unprovenB), []byte(call))
	if err != nil {
		t.Fatal(err)
	}
	writeRaw(t, a, `{"type":"proxy-request","data":{"requestId":"r1","target":"`+unprovenB+
		`","sealed":"`+base64.StdEncoding.EncodeToString(sealedCall)+`"}}`)
	env, _ := readAsHelloFirst(t, b, TypeProxyRequest)
	var req ProxyRequest
	if err := env.Into(&req); err != nil || req.RequestID != "r1" || req.Target != unprovenB {
		t.Fatalf("b received %+v (%v), want a's call", req, err)
	}
	opened, err := open(helloFirstFrameKey, requestAAD("r1", unprovenB), req.Sealed)
	if err != nil || string(opened) != call {
		t.Fatalf("b opened %q (%v), want a's call byte for byte", opened, err)
	}
	if req.Sender != unprovenA {
		t.Errorf("the call came stamped from %q, want a", req.Sender)
	}

	sealedResult, err := seal(helloFirstFrameKey, responseAAD("r1"), []byte(`{"status":200,"body":"b2s="}`))
	if err != nil {
		t.Fatal(err)
	}
	answer := `{"type":"proxy-response","data":{"requestId":"r1","sealed":"` + base64.StdEncoding.EncodeToString(sealedResult) + `"}}`
	writeRaw(t, b, answer)
	if _, got := readAsHelloFirst(t, a, TypeProxyResponse); string(got) != answer {
		t.Fatalf("a got the answer as %s, want b's frame as it was sent", got)
	}

	_ = b.CloseNow()
	var gone Presence
	if env, _ := readAsHelloFirst(t, a, TypePresence); env.Into(&gone) != nil || gone.InstanceID != unprovenB || gone.Online {
		t.Fatalf("a was told %+v, want b offline", gone)
	}
}

// TestAHelloFirstInstanceReconnectsOverItsDeadSocket: the instance proves
// nothing, so it has no other way back than its reconnect taking the place of
// the socket the relay still holds.
func TestAHelloFirstInstanceReconnectsOverItsDeadSocket(t *testing.T) {
	relaySrv := New()
	srv := httptest.NewServer(relaySrv)
	t.Cleanup(srv.Close)
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/relay/connect"
	dead := dialHelloFirst(t, url, helloFirstRelayKey, unprovenA)
	b := dialHelloFirst(t, url, helloFirstRelayKey, unprovenB)
	readAsHelloFirst(t, b, TypeAnnounce)
	readAsHelloFirst(t, dead, TypeAnnounce)

	a := dialHelloFirst(t, url, helloFirstRelayKey, unprovenA)
	readAsHelloFirst(t, a, TypeAnnounce)
	readAsHelloFirst(t, b, TypeAnnounce)
	ctx, cancel := context.WithTimeout(context.Background(), wsTimeout)
	defer cancel()
	for {
		if _, _, err := dead.Read(ctx); err != nil {
			break
		}
	}
	if relaySrv.Len() != 2 {
		t.Errorf("%d connections registered, want the dead socket replaced", relaySrv.Len())
	}

	sealedCall, err := seal(helloFirstFrameKey, requestAAD("r1", unprovenA), []byte(`{"method":"GET","path":"/","id":"r1","sent":1}`))
	if err != nil {
		t.Fatal(err)
	}
	writeRaw(t, b, `{"type":"proxy-request","data":{"requestId":"r1","target":"`+unprovenA+
		`","sealed":"`+base64.StdEncoding.EncodeToString(sealedCall)+`"}}`)
	readAsHelloFirst(t, a, TypeProxyRequest)
}

// TestTwoClientAppsShareOneRelay: a hello-first group and a group of members
// that prove their ids each work on the same relay as if alone, and neither
// sees the other.
func TestTwoClientAppsShareOneRelay(t *testing.T) {
	srv := httptest.NewServer(New())
	t.Cleanup(srv.Close)
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/relay/connect"
	const provenKey = "shared-relay-test-key-0123456789ab"

	first := dialHelloFirst(t, url, helloFirstRelayKey, unprovenA)
	alpha := dialInstance(t, url, provenKey, alphaID)
	bravo := dialInstance(t, url, provenKey, bravoID)
	other := dialHelloFirst(t, url, helloFirstRelayKey, unprovenB)

	if env, _ := readAsHelloFirst(t, other, TypeAnnounce); !strings.Contains(string(env.Data), unprovenA) {
		t.Fatalf("the second hello-first instance was introduced to %s, want the first", env.Data)
	}
	readAsHelloFirst(t, first, TypeAnnounce)
	readFrame(t, bravo, TypeAnnounce)
	readFrame(t, alpha, TypeAnnounce)

	writeFrame(t, alpha, TypeProxyRequest, ProxyRequest{RequestID: "r1", Target: bravoID, Sealed: sealFor(t, "r1", bravoID, ProxyCall{Method: "GET", Path: "/api/tasks"})})
	readFrame(t, bravo, TypeProxyRequest)

	writeFrame(t, first, TypeProxyRequest, ProxyRequest{RequestID: "r2", Target: alphaID})
	var refusal ProxyResponse
	if env, _ := readAsHelloFirst(t, first, TypeProxyResponse); env.Into(&refusal) != nil || refusal.Error == "" {
		t.Fatalf("a hello-first instance calling a member of another group got %+v, want the relay's refusal", refusal)
	}
}

// TestInstancesMeetOnTheRelayKeysClientsDerive: the relay groups by the key a
// hello carries, as sent. These are keys a client derives from fixed secrets,
// the all-zero secret and a walk over the byte range, and pins in its own
// tests, so the relay is held to the same values.
func TestInstancesMeetOnTheRelayKeysClientsDerive(t *testing.T) {
	srv := httptest.NewServer(New())
	t.Cleanup(srv.Close)
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/relay/connect"

	for _, key := range []string{
		"293fa85653adb9e7195717c1a6f34e3f433f0a610cd247bb9ff73b8642e7fc15",
		"57d28da6bdc93397c9a3a8355b9c3e322a7e134b9985ae7e76c3667d240b5b52",
	} {
		a := dialHelloFirst(t, url, key, unprovenA)
		b := dialHelloFirst(t, url, key, unprovenB)
		var sib Announce
		if env, _ := readAsHelloFirst(t, b, TypeAnnounce); env.Into(&sib) != nil || sib.InstanceID != unprovenA {
			t.Fatalf("on %s, b was introduced to %+v, want a", key[:8], sib)
		}
		readAsHelloFirst(t, a, TypeAnnounce)
	}
}
