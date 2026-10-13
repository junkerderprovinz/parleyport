package relay

// A BombVault instance, the Go client from 9.2.0 on and the Android app from
// 9.7.0 on, writes its hello the moment the socket opens, never proves its id
// and skips every frame type it does not know. The tests here speak to the
// relay exactly that way, with frames spelled as BombVault spells them, so a
// change to the relay that would leave BombVault behind fails here.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/coder/websocket"
)

// bombVaultRelayKey is BombVault's relay key for the all-zero group secret,
// pinned in its own key tests (TestDeriveKeyMatchesItsPinnedVectors).
const bombVaultRelayKey = "c1d52cbdb3cf9da68feb37b64543669aeb532e80e81c84390582f8e8dd70a4ee"

// bombVaultFrameKey is the frame key BombVault derives from the same secret.
var bombVaultFrameKey = func() []byte {
	sum := sha256.Sum256(append([]byte("bombvault/relay/frame-key/v1"), make([]byte, 16)...))
	return sum[:]
}()

// BombVault ids are 16 random bytes in hex.
const (
	vaultA = "0123456789abcdef0123456789abcdef"
	vaultB = "fedcba9876543210fedcba9876543210"
)

// dialBombVault connects as a BombVault instance: the hello goes out before
// anything is read, with the identity BombVault seals.
func dialBombVault(t *testing.T, url, id string) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wsTimeout)
	defer cancel()
	c, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("dial %s as %s: %v", url, id, err)
	}
	t.Cleanup(func() { _ = c.CloseNow() })
	identity, _ := json.Marshal(map[string]string{"name": "vault " + id[:4], "version": "9.9.5"})
	sealed, err := seal(bombVaultFrameKey, announceAAD(id), identity)
	if err != nil {
		t.Fatal(err)
	}
	hello := `{"type":"hello","data":{"key":"` + bombVaultRelayKey + `","announce":{"instanceId":"` + id +
		`","sealed":"` + base64.StdEncoding.EncodeToString(sealed) + `"}}}`
	if err := c.Write(ctx, websocket.MessageText, []byte(hello)); err != nil {
		t.Fatalf("hello: %v", err)
	}
	return c
}

// readAsBombVault returns the next frame BombVault acts on, raw, skipping the
// types it does not know the way its client does.
func readAsBombVault(t *testing.T, c *websocket.Conn, want string) (Envelope, []byte) {
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

func TestBombVaultInstancesMeetAndCallEachOther(t *testing.T) {
	srv := httptest.NewServer(New())
	t.Cleanup(srv.Close)
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/relay/connect"
	a := dialBombVault(t, url, vaultA)
	b := dialBombVault(t, url, vaultB)

	var sib Announce
	if env, _ := readAsBombVault(t, b, TypeAnnounce); env.Into(&sib) != nil || sib.InstanceID != vaultA {
		t.Fatalf("b was introduced to %+v, want a", sib)
	}
	plain, err := open(bombVaultFrameKey, announceAAD(vaultA), sib.Sealed)
	if err != nil || !strings.Contains(string(plain), `"version":"9.9.5"`) {
		t.Fatalf("a's sealed identity arrived as %q (%v), want what a sealed", plain, err)
	}
	readAsBombVault(t, a, TypeAnnounce)

	// The Android app writes the call with org.json, in this key order.
	call := `{"method":"GET","path":"/api/peer/status","id":"r1","sent":1760000000}`
	sealedCall, err := seal(bombVaultFrameKey, requestAAD("r1", vaultB), []byte(call))
	if err != nil {
		t.Fatal(err)
	}
	writeRaw(t, a, `{"type":"proxy-request","data":{"requestId":"r1","target":"`+vaultB+
		`","sealed":"`+base64.StdEncoding.EncodeToString(sealedCall)+`"}}`)
	env, _ := readAsBombVault(t, b, TypeProxyRequest)
	var req ProxyRequest
	if err := env.Into(&req); err != nil || req.RequestID != "r1" || req.Target != vaultB {
		t.Fatalf("b received %+v (%v), want a's call", req, err)
	}
	opened, err := open(bombVaultFrameKey, requestAAD("r1", vaultB), req.Sealed)
	if err != nil || string(opened) != call {
		t.Fatalf("b opened %q (%v), want a's call byte for byte", opened, err)
	}
	if req.Sender != vaultA {
		t.Errorf("the call came stamped from %q, want a", req.Sender)
	}

	sealedResult, err := seal(bombVaultFrameKey, responseAAD("r1"), []byte(`{"status":200,"body":"b2s="}`))
	if err != nil {
		t.Fatal(err)
	}
	answer := `{"type":"proxy-response","data":{"requestId":"r1","sealed":"` + base64.StdEncoding.EncodeToString(sealedResult) + `"}}`
	writeRaw(t, b, answer)
	if _, got := readAsBombVault(t, a, TypeProxyResponse); string(got) != answer {
		t.Fatalf("a got the answer as %s, want b's frame as it was sent", got)
	}

	_ = b.CloseNow()
	var gone Presence
	if env, _ := readAsBombVault(t, a, TypePresence); env.Into(&gone) != nil || gone.InstanceID != vaultB || gone.Online {
		t.Fatalf("a was told %+v, want b offline", gone)
	}
}

// TestABombVaultInstanceReconnectsOverItsDeadSocket: BombVault proves nothing,
// so it has no other way back than its reconnect taking the place of the
// socket the relay still holds.
func TestABombVaultInstanceReconnectsOverItsDeadSocket(t *testing.T) {
	relaySrv := New()
	srv := httptest.NewServer(relaySrv)
	t.Cleanup(srv.Close)
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/relay/connect"
	dead := dialBombVault(t, url, vaultA)
	b := dialBombVault(t, url, vaultB)
	readAsBombVault(t, b, TypeAnnounce)
	readAsBombVault(t, dead, TypeAnnounce)

	a := dialBombVault(t, url, vaultA)
	readAsBombVault(t, a, TypeAnnounce)
	readAsBombVault(t, b, TypeAnnounce)
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

	sealedCall, err := seal(bombVaultFrameKey, requestAAD("r1", vaultA), []byte(`{"method":"GET","path":"/","id":"r1","sent":1}`))
	if err != nil {
		t.Fatal(err)
	}
	writeRaw(t, b, `{"type":"proxy-request","data":{"requestId":"r1","target":"`+vaultA+
		`","sealed":"`+base64.StdEncoding.EncodeToString(sealedCall)+`"}}`)
	readAsBombVault(t, a, TypeProxyRequest)
}

// TestBothAppsShareOneRelay: a BombVault group and a KnightLoader 1.9 group on
// the same relay each work as if alone, and neither sees the other.
func TestBothAppsShareOneRelay(t *testing.T) {
	srv := httptest.NewServer(New())
	t.Cleanup(srv.Close)
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/relay/connect"
	const klKey = "shared-relay-test-key-0123456789ab"

	vault := dialBombVault(t, url, vaultA)
	alpha := dialInstance(t, url, klKey, alphaID)
	bravo := dialInstance(t, url, klKey, bravoID)
	other := dialBombVault(t, url, vaultB)

	if env, _ := readAsBombVault(t, other, TypeAnnounce); !strings.Contains(string(env.Data), vaultA) {
		t.Fatalf("the second vault was introduced to %s, want the first", env.Data)
	}
	readAsBombVault(t, vault, TypeAnnounce)
	readFrame(t, bravo, TypeAnnounce)
	readFrame(t, alpha, TypeAnnounce)

	writeFrame(t, alpha, TypeProxyRequest, ProxyRequest{RequestID: "r1", Target: bravoID, Sealed: sealFor(t, "r1", bravoID, ProxyCall{Method: "GET", Path: "/api/tasks"})})
	readFrame(t, bravo, TypeProxyRequest)

	writeFrame(t, vault, TypeProxyRequest, ProxyRequest{RequestID: "r2", Target: alphaID})
	var refusal ProxyResponse
	if env, _ := readAsBombVault(t, vault, TypeProxyResponse); env.Into(&refusal) != nil || refusal.Error == "" {
		t.Fatalf("a vault calling a KnightLoader instance got %+v, want the relay's refusal", refusal)
	}
}
