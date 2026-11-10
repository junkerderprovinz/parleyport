package group

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/junkerderprovinz/parleyport/kit/keys"
	"github.com/junkerderprovinz/parleyport/kit/lan"
	"github.com/junkerderprovinz/parleyport/kit/member"
	"github.com/junkerderprovinz/parleyport/kit/relay"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

const testDomain = keys.Domain("test")

var testSecret = []byte("0123456789abcdef")

// memStore is an app's sealed store as far as a group can tell.
type memStore struct {
	mu   sync.Mutex
	data []byte
	fail bool
}

func (s *memStore) Load() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.data), nil
}

func (s *memStore) Save(b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errors.New("disk full")
	}
	s.data = bytes.Clone(b)
	return nil
}

// identity is the member key of the instance called name in these tests.
func identity(t testing.TB, name string) member.Identity {
	t.Helper()
	return device(t, member.KindInstance, name)
}

// device is the member key of the member of kind called name in these tests.
func device(t testing.TB, kind member.Kind, name string) member.Identity {
	t.Helper()
	seed := sha256.Sum256([]byte(name))
	id, err := member.FromSeed(kind, seed[:])
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// signedBy is a call to target's path signed by from under request id, as the
// guard sees it once it opened.
func signedBy(from member.Identity, id, target, path string) relay.ProxyCall {
	return relay.SignCall(testDomain.Signing(), &from, id, target, relay.ProxyCall{Method: http.MethodGet, Path: path})
}

// node is one instance in a test: its group, the app routes behind it and the
// server its direct calls arrive on.
type node struct {
	name    string
	id      string
	g       *Group
	srv     *httptest.Server
	store   *memStore
	removed atomic.Int32
}

type setup struct {
	relay    string
	lan      *lan.Service
	store    *memStore
	secret   []byte
	previous []byte
	onRemove func(id string)
	onChange func()
	// keysOnly opens the group on the keys derived from the secret instead.
	keysOnly  bool
	byPhrase  bool
	maxAnswer int
	kinds     []member.Kind
	ports     []int
	// noListener opens the instance the way a desktop app runs: it calls
	// others directly but takes no direct calls itself.
	noListener bool
}

// open starts an instance called name. Its app answers GET /api/whoami with
// the member it was called by and echoes POST /api/echo.
func open(t *testing.T, name string, s setup) *node {
	t.Helper()
	n := &node{name: name, id: identity(t, name).ID(), store: s.store}
	if n.store == nil {
		n.store = &memStore{}
	}
	var current atomic.Pointer[Group]
	n.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g := current.Load(); g != nil && r.URL.Path == DirectPath {
			g.DirectHandler().ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(n.srv.Close)
	n.g = openGroup(t, n, s)
	current.Store(n.g)
	return n
}

func openGroup(t *testing.T, n *node, s setup) *Group {
	t.Helper()
	secret := s.secret
	if secret == nil {
		secret = testSecret
	}
	mode, url := RelayOff, ""
	if s.relay != "" {
		mode, url = RelayOwn, s.relay
	}
	var set keys.Set
	if s.keysOnly {
		secret, set = nil, testDomain.Keys(secret)
	}
	direct := n.srv.URL
	if s.noListener {
		direct = ""
	}
	g, err := Open(Config{
		Domain:         testDomain,
		Secret:         secret,
		Keys:           set,
		Identity:       identity(t, n.name),
		Self:           Self{Name: n.name, Deployment: "container", DirectURL: direct},
		Relay:          mode,
		RelayURL:       url,
		LAN:            s.lan,
		Store:          n.store,
		Previous:       s.previous,
		JoinByPhrase:   s.byPhrase,
		MaxAnswerBytes: s.maxAnswer,
		Kinds:          s.kinds,
		Ports:          s.ports,
		OnRemoved:      func() { n.removed.Add(1) },
		OnRemove:       s.onRemove,
		OnChange:       s.onChange,
	}, appRoutes())
	if err != nil {
		t.Fatalf("open %s: %v", n.name, err)
	}
	t.Cleanup(func() { _ = g.Close() })
	return g
}

func appRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/whoami", func(w http.ResponseWriter, r *http.Request) {
		c, ok := CallerOf(r.Context())
		if !ok {
			http.Error(w, "no caller", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id": c.ID, "kind": string(c.Kind)})
	})
	mux.HandleFunc("POST /api/echo", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(w, r.Body)
	})
	mux.HandleFunc("GET /api/panic", func(http.ResponseWriter, *http.Request) { panic("boom") })
	mux.HandleFunc("GET /api/big", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, maxAnswerBytes+1))
	})
	mux.HandleFunc("GET /api/size/{n}", func(w http.ResponseWriter, r *http.Request) {
		n, err := strconv.Atoi(r.PathValue("n"))
		if err != nil {
			http.Error(w, "no size", http.StatusBadRequest)
			return
		}
		_, _ = w.Write(bytes.Repeat([]byte("x"), n))
	})
	return mux
}

// relayServer runs a relay on the loopback for the instances of one test.
func relayServer(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(relay.New())
	t.Cleanup(srv.CloseClientConnections)
	t.Cleanup(srv.Close)
	return srv.URL
}

// lanService is a multicast group no app uses on a port free right now, so
// tests neither meet real instances nor each other.
func lanService(t *testing.T, port uint16) *lan.Service {
	t.Helper()
	s := lan.New(lan.Config{Group: netip.AddrPortFrom(netip.MustParseAddr("239.255.77.251"), port)})
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func freePort(t *testing.T) uint16 {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	return c.LocalAddr().(*net.UDPAddr).AddrPort().Port()
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func memberOf(g *Group, id string) (Member, bool) {
	for _, m := range g.Members() {
		if m.ID == id {
			return m, true
		}
	}
	return Member{}, false
}

func call(t *testing.T, from, to *node, method, path string, body []byte) (int, []byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return from.g.Call(ctx, to.id, method, path, body)
}

// meet lets a and b sign in on each other and approves both, as two owners
// would on their instance pages.
func meet(t *testing.T, a, b *node) {
	t.Helper()
	_, _, _ = call(t, a, b, http.MethodGet, "/api/whoami", nil)
	_, _, _ = call(t, b, a, http.MethodGet, "/api/whoami", nil)
	if err := a.g.Approve(b.id); err != nil {
		t.Fatalf("%s approves %s: %v", a.name, b.name, err)
	}
	if err := b.g.Approve(a.id); err != nil {
		t.Fatalf("%s approves %s: %v", b.name, a.name, err)
	}
}

// tagged is p as a member of g's group announces it now.
func tagged(g *Group, p lan.Peer) lan.Peer {
	p.Sent = time.Now().Unix()
	p.Tag = announceTag(g.peerAuth, p)
	return p
}

// testPort is the port of a test server's address.
func testPort(t *testing.T, addr string) int {
	t.Helper()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(addr, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// httpDeadAddress is an address on the loopback that nothing answers on.
func httpDeadAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return "http://" + addr
}

// whoami calls GET /api/whoami and returns the id the app saw.
func whoami(t *testing.T, from, to *node) string {
	t.Helper()
	status, body, err := call(t, from, to, http.MethodGet, "/api/whoami", nil)
	if err != nil || status != http.StatusOK {
		t.Fatalf("%s calls %s: %d %s %v", from.name, to.name, status, body, err)
	}
	var out map[string]string
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	return out["id"]
}
