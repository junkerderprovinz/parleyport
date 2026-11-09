package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/junkerderprovinz/parleyport/kit/internal/vectors"
	"github.com/junkerderprovinz/parleyport/kit/keys"
	"github.com/junkerderprovinz/parleyport/kit/member"
)

// testDomain is the app every client and hand-rolled peer in these tests
// belongs to.
const testDomain = keys.Domain("test")

// testFrameKey and testSigning are what every member in these tests seals and
// signs with, as if they had entered the same phrase.
var (
	testFrameKey = frameKeyFor("relay package tests")
	testSigning  = testDomain.Signing()
)

func frameKeyFor(secret string) []byte {
	return testDomain.FrameKey([]byte(secret))
}

func hexKey(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// The identities of the instances in these tests and the ids they make. A
// client drops an instance's announce under an id of any other shape, and
// takes an answer only when the target's key signed it. nasID has no key, so
// it joins unproven.
var (
	alphaKey   = identityFrom('a')
	bravoKey   = identityFrom('b')
	charlieKey = identityFrom('c')
	alphaID    = alphaKey.ID()
	bravoID    = bravoKey.ID()
	charlieID  = charlieKey.ID()
	nasID      = strings.Repeat("d", 40)
	identities = map[string]*member.Identity{alphaID: &alphaKey, bravoID: &bravoKey, charlieID: &charlieKey}
)

func identityFrom(b byte) member.Identity {
	return identityOf(member.KindInstance, bytes.Repeat([]byte{b}, ed25519.SeedSize))
}

func identityOf(kind member.Kind, seed []byte) member.Identity {
	id, err := member.FromSeed(kind, seed)
	if err != nil {
		panic(err)
	}
	return id
}

// keyNumber is a distinct 32-byte value for each n, which is all the replay
// guard reads of a key.
func keyNumber(n int) []byte {
	k := make([]byte, ed25519.PublicKeySize)
	binary.BigEndian.PutUint64(k, uint64(n))
	return k
}

func loadVectors(t *testing.T) *vectors.File {
	t.Helper()
	v, err := vectors.Load()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func decoded(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// sealFor, sealResultFor, openFrom and openResultFrom seal and open payloads
// for the hand-rolled peers.
func sealFor(t *testing.T, requestID, target string, call ProxyCall) []byte {
	t.Helper()
	sealed, err := SealCall(testFrameKey, requestID, target, call)
	if err != nil {
		t.Fatalf("seal call: %v", err)
	}
	return sealed
}

func sealResultFor(t *testing.T, requestID string, res ProxyResult) []byte {
	t.Helper()
	sealed, err := SealResult(testFrameKey, requestID, res)
	if err != nil {
		t.Fatalf("seal result: %v", err)
	}
	return sealed
}

func openFrom(t *testing.T, requestID, target string, sealed []byte) ProxyCall {
	t.Helper()
	call, err := OpenCall(testFrameKey, testSigning, requestID, target, sealed)
	if err != nil {
		t.Fatalf("open call: %v", err)
	}
	return call
}

func openResultFrom(t *testing.T, requestID string, sealed []byte) ProxyResult {
	t.Helper()
	res, err := OpenResult(testFrameKey, requestID, sealed)
	if err != nil {
		t.Fatalf("open result: %v", err)
	}
	return res
}

// mustSeal seals call as it is, signature and all, the way a member that
// alters a call it captured would.
func mustSeal(t *testing.T, requestID, target string, call ProxyCall) []byte {
	t.Helper()
	plain, err := json.Marshal(call)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := seal(testFrameKey, requestAAD(requestID, target), plain)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

// testBackoff is the reconnect cadence the tests run at.
const testBackoff = 20 * time.Millisecond

// wsTimeout bounds every step of a test against a real socket, so a protocol
// mistake fails the run instead of hanging it.
const wsTimeout = 10 * time.Second

// tracking remembers every connection it accepted so they can all be killed at
// once. http.Server.Close cannot, because an upgraded WebSocket is hijacked out
// of the server's bookkeeping.
type tracking struct {
	net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func (l *tracking) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.mu.Lock()
		l.conns = append(l.conns, c)
		l.mu.Unlock()
	}
	return c, err
}

func (l *tracking) closeAll() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.conns {
		_ = c.Close()
	}
	l.conns = nil
}

// relayOn serves a real relay on addr ("127.0.0.1:0" for a fresh port) and
// returns the address it landed on and a stop that drops the listener and every
// live connection, as if the relay process died. Calling relayOn again on the
// same address then looks like a restarted relay.
func relayOn(t *testing.T, addr string) (string, func()) {
	t.Helper()
	raw, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen on %s: %v", addr, err)
	}
	l := &tracking{Listener: raw}
	srv := &http.Server{Handler: New(), ReadHeaderTimeout: wsTimeout}
	go func() { _ = srv.Serve(l) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = srv.Close()
			l.closeAll()
		})
	}
	t.Cleanup(stop)
	return raw.Addr().String(), stop
}

// startClient builds a Client against addr with the fast test backoff and
// starts it. The http:// form of the address makes every test go through the
// scheme and path rewriting too.
func startClient(t *testing.T, addr, key, id string, serve ProxyHandler) *Client {
	t.Helper()
	c, err := NewClient(ClientOptions{
		URL:      "http://" + addr,
		Key:      key,
		FrameKey: testFrameKey,
		Signing:  testSigning,
		Self:     Announce{InstanceID: id, Name: id, Deployment: "desktop"},
		Identity: identities[id],
		Serve:    serve,
	})
	if err != nil {
		t.Fatalf("new client %s: %v", id, err)
	}
	c.minBackoff, c.maxBackoff = testBackoff, 4*testBackoff
	c.Start()
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// waitFor polls until cond holds, failing the test if it never does.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(wsTimeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// dialInstance opens a real WebSocket to the relay and completes the hello as
// a member does: it waits for the challenge and, when it holds the key behind
// id, proves the id for the host it dialled.
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
	if ident, ok := identities[id]; ok {
		hello.Proof = ident.ProveHello(key, RelayHost(url), ch.Nonce)
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
