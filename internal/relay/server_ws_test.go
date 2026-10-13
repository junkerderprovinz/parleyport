package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/coder/websocket"
)

// The member keys of the KnightLoader 1.9 instances in these tests, and the
// ids they make. dialInstance proves an id only when it knows the key behind
// it, so "bravo" and the like join unproven, as BombVault and older
// KnightLoader releases do.
var (
	alphaKey   = memberKeyFrom('a')
	bravoKey   = memberKeyFrom('b')
	charlieKey = memberKeyFrom('c')
	alphaID    = MemberID(KindInstance, alphaKey.Public().(ed25519.PublicKey))
	bravoID    = MemberID(KindInstance, bravoKey.Public().(ed25519.PublicKey))
	charlieID  = MemberID(KindInstance, charlieKey.Public().(ed25519.PublicKey))
	memberKeys = map[string]ed25519.PrivateKey{alphaID: alphaKey, bravoID: bravoKey, charlieID: charlieKey}
)

func memberKeyFrom(b byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, ed25519.SeedSize))
}

func TestAnOversizedFrameBeforeTheHelloIsRefused(t *testing.T) {
	relaySrv := New()
	srv := httptest.NewServer(relaySrv)
	t.Cleanup(srv.Close)
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/relay/connect"

	ctx, cancel := context.WithTimeout(context.Background(), wsTimeout)
	defer cancel()
	c, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.CloseNow() })
	readFrame(t, c, TypeChallenge)

	frame, _ := Encode(TypeHello, Hello{Key: strings.Repeat("k", 5<<10), Announce: Announce{InstanceID: alphaID}})
	_ = c.Write(ctx, websocket.MessageText, frame)
	if _, _, err := c.Read(ctx); websocket.CloseStatus(err) != websocket.StatusMessageTooBig {
		t.Fatalf("a 5 KiB first frame got %v, want the connection closed as too big", err)
	}
	if relaySrv.Len() != 0 {
		t.Errorf("%d connections registered, want none", relaySrv.Len())
	}
}

func TestFramesAfterTheHelloMayBeLarge(t *testing.T) {
	srv := httptest.NewServer(New())
	t.Cleanup(srv.Close)
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/relay/connect"
	alpha := dialInstance(t, url, "shared-relay-test-key-0123456789ab", alphaID)
	bravo := dialInstance(t, url, "shared-relay-test-key-0123456789ab", bravoID)
	bravo.SetReadLimit(readLimit)
	readFrame(t, alpha, TypeAnnounce)
	readFrame(t, bravo, TypeAnnounce)

	big := ProxyRequest{RequestID: "r1", Target: bravoID, Sealed: make([]byte, 64<<10)}
	writeFrame(t, alpha, TypeProxyRequest, big)
	var got ProxyRequest
	if err := readFrame(t, bravo, TypeProxyRequest).Into(&got); err != nil || len(got.Sealed) != len(big.Sealed) {
		t.Fatalf("bravo got %d sealed bytes (%v), want the whole 64 KiB call", len(got.Sealed), err)
	}
}

func TestAVeryLongNameStillFitsTheHello(t *testing.T) {
	addr, _ := relayOn(t, "127.0.0.1:0")
	c, err := NewClient(ClientOptions{
		URL:      "http://" + addr,
		Key:      "shared-relay-test-key-0123456789ab",
		FrameKey: testFrameKey,
		Self:     Announce{InstanceID: "alpha", Name: strings.Repeat("é", 5000)},
	})
	if err != nil {
		t.Fatal(err)
	}
	c.minBackoff, c.maxBackoff = testBackoff, 4*testBackoff
	c.Start()
	t.Cleanup(func() { _ = c.Close() })
	bravo := startClient(t, addr, "shared-relay-test-key-0123456789ab", "bravo", nil)

	waitFor(t, "bravo to see alpha", func() bool { return len(bravo.Siblings()) == 1 })
	name := bravo.Siblings()[0].Name
	if name == "" || len(name) > MaxNameBytes || !utf8.ValidString(name) {
		t.Fatalf("alpha arrived as %q, want its name cut to whole characters within %d bytes", name, MaxNameBytes)
	}
}

// wsTimeout bounds every step of the end-to-end test, so a protocol mistake
// fails the run instead of hanging it.
const wsTimeout = 10 * time.Second

// dialInstance opens a real WebSocket to the relay and completes the hello
// handshake as a KnightLoader 1.9 instance does: it waits for the challenge
// and, when it holds the key behind id, proves the id for the host it dialled.
func dialInstance(t *testing.T, url, key, id string) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wsTimeout)
	defer cancel()
	c, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("dial %s as %s: %v", url, id, err)
	}
	t.Cleanup(func() { _ = c.CloseNow() })
	var ch Challenge
	if err := readFrame(t, c, TypeChallenge).Into(&ch); err != nil {
		t.Fatalf("challenge: %v", err)
	}
	hello := Hello{
		Key:      key,
		Announce: Announce{InstanceID: id, Name: id, Deployment: "container"},
	}
	if member, ok := memberKeys[id]; ok {
		hello.Proof = ProveID(member, KindInstance, key, RelayHost(url), id, ch.Nonce)
	}
	writeFrame(t, c, TypeHello, hello)
	return c
}

func writeFrame(t *testing.T, c *websocket.Conn, typ string, data any) {
	t.Helper()
	frame, err := Encode(typ, data)
	if err != nil {
		t.Fatalf("encode %s: %v", typ, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), wsTimeout)
	defer cancel()
	if err := c.Write(ctx, websocket.MessageText, frame); err != nil {
		t.Fatalf("write %s: %v", typ, err)
	}
}

func readFrame(t *testing.T, c *websocket.Conn, want string) Envelope {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wsTimeout)
	defer cancel()
	_, frame, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("waiting for a %s frame: %v", want, err)
	}
	env, err := Decode(frame)
	if err != nil {
		t.Fatalf("waiting for a %s frame: %s is not an envelope (%v)", want, frame, err)
	}
	if env.Type != want {
		t.Fatalf("got a %q frame, want %q", env.Type, want)
	}
	return env
}

// TestEndToEndOverRealWebSockets runs two real coder/websocket clients against
// the relay's http.Handler. The registry tests drive Join and Route directly
// and cannot catch a frame no real client can parse or a handshake the
// library rejects.
func TestEndToEndOverRealWebSockets(t *testing.T) {
	srv := httptest.NewServer(New())
	t.Cleanup(srv.Close)
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/relay/connect"

	alpha := dialInstance(t, url, "shared-relay-test-key-0123456789ab", alphaID)
	bravo := dialInstance(t, url, "shared-relay-test-key-0123456789ab", bravoID)

	// bravo joined last, so it hears about alpha; alpha hears bravo arrive.
	var sib Announce
	if err := readFrame(t, bravo, TypeAnnounce).Into(&sib); err != nil {
		t.Fatalf("sibling announce: %v", err)
	}
	if sib.InstanceID != alphaID || sib.Deployment != "container" {
		t.Errorf("bravo was introduced to %+v, want alpha", sib)
	}
	var arrival Announce
	if err := readFrame(t, alpha, TypeAnnounce).Into(&arrival); err != nil {
		t.Fatalf("arrival announce: %v", err)
	}
	if arrival.InstanceID != bravoID {
		t.Errorf("alpha was told about %+v, want bravo", arrival)
	}

	// Unlike server_test.go, both payloads are really sealed, so the round
	// trip through base64 in the JSON envelope is covered.
	call := ProxyCall{
		Method: "POST", Path: "/api/links",
		Body: []byte(`{"url":"https://example.invalid/file.bin"}`),
	}
	writeFrame(t, alpha, TypeProxyRequest, ProxyRequest{
		RequestID: "r1", Target: bravoID, Sender: charlieID,
		Sealed: sealFor(t, "r1", bravoID, call),
	})
	var req ProxyRequest
	if err := readFrame(t, bravo, TypeProxyRequest).Into(&req); err != nil {
		t.Fatalf("proxy-request: %v", err)
	}
	if req.RequestID != "r1" || req.Target != bravoID {
		t.Fatalf("bravo received %+v, want alpha's request unchanged", req)
	}
	if req.Sender != alphaID {
		t.Errorf("bravo was told the call came from %q, want %q whatever alpha claimed", req.Sender, alphaID)
	}
	got := openFrom(t, "r1", bravoID, req.Sealed)
	if got.Method != "POST" || got.Path != "/api/links" {
		t.Fatalf("bravo opened %+v, want alpha's request unchanged", got)
	}
	if string(got.Body) != `{"url":"https://example.invalid/file.bin"}` {
		t.Errorf("body arrived as %s, want it byte for byte", got.Body)
	}

	writeFrame(t, bravo, TypeProxyResponse, ProxyResponse{
		RequestID: req.RequestID,
		Sealed:    sealResultFor(t, req.RequestID, ProxyResult{Status: 201, Body: []byte(`{"added":1}`)}),
	})
	var resp ProxyResponse
	if err := readFrame(t, alpha, TypeProxyResponse).Into(&resp); err != nil {
		t.Fatalf("proxy-response: %v", err)
	}
	if resp.RequestID != "r1" {
		t.Fatalf("alpha received %+v, want bravo's own answer", resp)
	}
	res := openResultFrom(t, "r1", resp.Sealed)
	if res.Status != 201 || string(res.Body) != `{"added":1}` {
		t.Errorf("alpha opened %+v, want bravo's own answer", res)
	}

	// The Instances page's live status depends on a real socket closing, not
	// only on Leave.
	_ = bravo.CloseNow()
	var gone Presence
	if err := readFrame(t, alpha, TypePresence).Into(&gone); err != nil {
		t.Fatalf("presence: %v", err)
	}
	if gone.InstanceID != bravoID || gone.Online {
		t.Errorf("got %+v, want bravo offline", gone)
	}
}

func TestConnectionWithoutAKeyIsRejected(t *testing.T) {
	relaySrv := New()
	srv := httptest.NewServer(relaySrv)
	t.Cleanup(srv.Close)
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/relay/connect"

	ctx, cancel := context.WithTimeout(context.Background(), wsTimeout)
	defer cancel()
	c, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.CloseNow() })
	readFrame(t, c, TypeChallenge)

	writeFrame(t, c, TypeHello, Hello{Announce: Announce{InstanceID: alphaID}})
	if _, _, err := c.Read(ctx); err == nil {
		t.Fatal("a hello without a relay key was accepted")
	}
	if relaySrv.Len() != 0 {
		t.Errorf("%d connections registered, want the keyless one rejected", relaySrv.Len())
	}
}

func TestConnectionWithATooShortKeyIsRejected(t *testing.T) {
	relaySrv := New()
	srv := httptest.NewServer(relaySrv)
	t.Cleanup(srv.Close)
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/relay/connect"

	ctx, cancel := context.WithTimeout(context.Background(), wsTimeout)
	defer cancel()
	c, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.CloseNow() })
	readFrame(t, c, TypeChallenge)

	writeFrame(t, c, TypeHello, Hello{Key: "too-short", Announce: Announce{InstanceID: alphaID}})
	if _, _, err := c.Read(ctx); err == nil {
		t.Fatal("a hello with a key shorter than minKeyLength was accepted")
	}
	if relaySrv.Len() != 0 {
		t.Errorf("%d connections registered, want the short-keyed one rejected", relaySrv.Len())
	}
}

// TestNoSpellingOfTheSenderFieldOutlivesTheRelaysStamp: encoding/json takes
// "ſender" and "Sender" for "sender", and the last of two equal keys. A frame
// that names the field in any such way is not passed on, and every frame that
// is carries the id the sending connection announced.
func TestNoSpellingOfTheSenderFieldOutlivesTheRelaysStamp(t *testing.T) {
	srv := httptest.NewServer(New())
	t.Cleanup(srv.Close)
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/relay/connect"
	alpha := dialInstance(t, url, "shared-relay-test-key-0123456789ab", alphaID)
	bravo := dialInstance(t, url, "shared-relay-test-key-0123456789ab", bravoID)
	readFrame(t, bravo, TypeAnnounce)
	readFrame(t, alpha, TypeAnnounce)

	sealed, err := json.Marshal(sealFor(t, "r1", bravoID, ProxyCall{Method: "GET", Path: "/api/tasks"}))
	if err != nil {
		t.Fatal(err)
	}
	head := `{"type":"proxy-request","data":{"requestId":"r1","target":"` + bravoID + `","sealed":` + string(sealed)
	for _, frame := range []string{
		head + `,"ſender":"` + charlieID + `"}}`,
		head + `,"Sender":"` + charlieID + `"}}`,
		head + `,"sender":"x","sender":"` + charlieID + `"}}`,
		head + `,"requestId":"r1"}}`,
	} {
		ctx, cancel := context.WithTimeout(context.Background(), wsTimeout)
		if err := alpha.Write(ctx, websocket.MessageText, []byte(frame)); err != nil {
			t.Fatal(err)
		}
		cancel()
	}
	writeFrame(t, alpha, TypeProxyRequest, ProxyRequest{RequestID: "r2", Target: bravoID, Sealed: sealFor(t, "r2", bravoID, ProxyCall{Method: "GET", Path: "/api/tasks"})})
	var req ProxyRequest
	if err := readFrame(t, bravo, TypeProxyRequest).Into(&req); err != nil {
		t.Fatal(err)
	}
	if req.RequestID != "r2" || req.Sender != alphaID {
		t.Errorf("bravo was handed %s from %q, want only r2, from %q", req.RequestID, req.Sender, alphaID)
	}
}

// TestAHelloPlayedBackOnAnotherConnectionTakesNoPlace: whoever saw an
// instance's hello, the relay's operator or anybody on a plain ws:// link,
// sends it again on a connection of their own. It proved the id on the
// connection it was made for and proves nothing on this one, so the instance
// keeps its place and its calls.
func TestAHelloPlayedBackOnAnotherConnectionTakesNoPlace(t *testing.T) {
	srv := httptest.NewServer(New())
	t.Cleanup(srv.Close)
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/relay/connect"
	const key = "shared-relay-test-key-0123456789ab"
	dial := func() *websocket.Conn {
		ctx, cancel := context.WithTimeout(context.Background(), wsTimeout)
		defer cancel()
		c, _, err := websocket.Dial(ctx, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.CloseNow() })
		return c
	}

	alpha := dial()
	var ch Challenge
	if err := readFrame(t, alpha, TypeChallenge).Into(&ch); err != nil {
		t.Fatal(err)
	}
	hello := Hello{Key: key, Announce: Announce{InstanceID: alphaID}, Proof: ProveID(alphaKey, KindInstance, key, RelayHost(url), alphaID, ch.Nonce)}
	writeFrame(t, alpha, TypeHello, hello)
	bravo := dialInstance(t, url, key, bravoID)
	readFrame(t, bravo, TypeAnnounce)
	readFrame(t, alpha, TypeAnnounce)

	thief := dial()
	readFrame(t, thief, TypeChallenge)
	writeFrame(t, thief, TypeHello, hello)
	ctx, cancel := context.WithTimeout(context.Background(), wsTimeout)
	defer cancel()
	if _, _, err := thief.Read(ctx); websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("a hello played back on another connection got %v, want it turned away", err)
	}
	writeFrame(t, bravo, TypeProxyRequest, ProxyRequest{RequestID: "r1", Target: alphaID})
	readFrame(t, alpha, TypeProxyRequest)
}

// TestAKnightLoaderInstanceReconnectsWithItsProof: an instance whose socket
// died reconnects before the relay noticed, and its proof takes the place of
// the dead socket.
func TestAKnightLoaderInstanceReconnectsWithItsProof(t *testing.T) {
	relaySrv := New()
	srv := httptest.NewServer(relaySrv)
	t.Cleanup(srv.Close)
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/relay/connect"
	const key = "shared-relay-test-key-0123456789ab"
	dead := dialInstance(t, url, key, alphaID)
	bravo := dialInstance(t, url, key, bravoID)
	readFrame(t, bravo, TypeAnnounce)
	readFrame(t, dead, TypeAnnounce)

	alpha := dialInstance(t, url, key, alphaID)
	readFrame(t, alpha, TypeAnnounce)
	readFrame(t, bravo, TypeAnnounce)
	if relaySrv.Len() != 2 {
		t.Errorf("%d connections registered, want the dead socket replaced", relaySrv.Len())
	}
	writeFrame(t, bravo, TypeProxyRequest, ProxyRequest{RequestID: "r1", Target: alphaID})
	readFrame(t, alpha, TypeProxyRequest)
}

// TestAHelloSignedForAnotherRelayTakesNoPlace: a relay the instance dialled
// with the same key opens a connection here, passes this relay's challenge on
// to the instance and hands back the hello the instance signed. The proof
// names the relay the instance dialled, so here it proves nothing and the
// instance keeps its place. Without Names the relay goes by the Host header the
// connection arrived with.
func TestAHelloSignedForAnotherRelayTakesNoPlace(t *testing.T) {
	const key = "shared-relay-test-key-0123456789ab"
	for _, tc := range []struct {
		name      string
		names     func(*http.Request) []string
		signedFor func(url string) string
		takes     bool
	}{
		{"for this relay by its name", func(*http.Request) []string { return []string{"relay.example.com"} }, func(string) string { return "relay.example.com" }, true},
		{"for another relay", func(*http.Request) []string { return []string{"relay.example.com"} }, func(string) string { return "other-relay.example.net" }, false},
		{"for the host it was dialled at", nil, RelayHost, true},
		{"for another relay than the host it was dialled at", nil, func(string) string { return "other-relay.example.net" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			relaySrv := New()
			relaySrv.Names = tc.names
			srv := httptest.NewServer(relaySrv)
			t.Cleanup(srv.Close)
			url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/relay/connect"
			dialAs := func(signedFor string) *websocket.Conn {
				ctx, cancel := context.WithTimeout(context.Background(), wsTimeout)
				defer cancel()
				c, _, err := websocket.Dial(ctx, url, nil)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = c.CloseNow() })
				var ch Challenge
				if err := readFrame(t, c, TypeChallenge).Into(&ch); err != nil {
					t.Fatal(err)
				}
				writeFrame(t, c, TypeHello, Hello{Key: key, Announce: Announce{InstanceID: alphaID}, Proof: ProveID(alphaKey, KindInstance, key, signedFor, alphaID, ch.Nonce)})
				return c
			}

			// alpha first joins with a proof this relay takes. A holder that
			// proved nothing would give way to any hello, signed or not.
			own := RelayHost(url)
			if tc.names != nil {
				own = tc.names(nil)[0]
			}
			first := dialAs(own)
			bravo := dialInstance(t, url, key, bravoID)
			readFrame(t, bravo, TypeAnnounce)
			readFrame(t, first, TypeAnnounce)

			next := dialAs(tc.signedFor(url))
			if !tc.takes {
				ctx, cancel := context.WithTimeout(context.Background(), wsTimeout)
				defer cancel()
				if _, _, err := next.Read(ctx); websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
					t.Fatalf("a hello signed for another relay got %v, want it turned away", err)
				}
				writeFrame(t, bravo, TypeProxyRequest, ProxyRequest{RequestID: "r1", Target: alphaID})
				readFrame(t, first, TypeProxyRequest)
				return
			}
			readFrame(t, next, TypeAnnounce)
			writeFrame(t, bravo, TypeProxyRequest, ProxyRequest{RequestID: "r1", Target: alphaID})
			readFrame(t, next, TypeProxyRequest)
		})
	}
}
