package fortress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/junkerderprovinz/parleyport/kit/group"
	"github.com/junkerderprovinz/parleyport/kit/lan"
	"github.com/junkerderprovinz/parleyport/kit/member"
	"github.com/junkerderprovinz/parleyport/kit/relay"
	"github.com/junkerderprovinz/parleyport/kit/status"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

var (
	testSecret = []byte("0123456789abcdef")
	oldSecret  = []byte("the app's own...")
)

type memStore struct {
	mu   sync.Mutex
	data []byte
}

func (s *memStore) Load() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.data), nil
}

func (s *memStore) Save(b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = bytes.Clone(b)
	return nil
}

func identity(t testing.TB, name string) member.Identity {
	t.Helper()
	seed := sha256.Sum256([]byte(name))
	id, err := member.FromSeed(member.KindInstance, seed[:])
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// source is an app's status as the fortress serves it to the others.
type source struct{ app, instance string }

func (s source) Report(_ context.Context, lang string) (status.Report, error) {
	text := "The copy is old."
	if lang == "de" {
		text = "Die Kopie ist alt."
	}
	return status.Report{
		App:      status.App{ID: s.app, Name: s.app, Version: "1.0.0"},
		Instance: status.Instance{ID: s.instance, Name: s.instance},
		State:    status.StateOK,
		NeedsYou: []status.Need{{ID: "copy-old", Severity: status.SeverityWarn, Code: "copy.old", Text: text}},
	}, nil
}

func (s source) Log(_ context.Context, q status.LogQuery) (status.LogPage, error) {
	return status.LogPage{
		Entries: []status.LogEntry{{ID: "1", At: time.Unix(1700000000, 0).UTC(), Level: status.SeverityInfo, Code: "run.done", Text: s.app + " ran"}},
		Next:    "1",
	}, nil
}

// node is one instance of an app in a test: its fortress and the server its
// direct calls arrive on. Its app offers the action "files.drop", which
// records what it was given, and uses "jobs.run".
type node struct {
	name      string
	app       string
	id        string
	f         *Fortress
	srv       *httptest.Server
	store     *memStore
	pairStore *memStore
	removed   atomic.Int32

	mu      sync.Mutex
	dropped []string
}

func (n *node) drops() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.dropped...)
}

type setup struct {
	relay    string
	lan      *lan.Service
	pairLAN  *lan.Service
	secret   []byte
	previous []byte
	noPair   bool
}

// open starts the instance name of app in the fortress s describes.
func open(t *testing.T, app, name string, s setup) *node {
	t.Helper()
	n := &node{name: name, app: app, id: identity(t, name).ID(), store: &memStore{}, pairStore: &memStore{}}
	var current atomic.Pointer[Fortress]
	n.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f := current.Load(); f != nil && r.URL.Path == group.DirectPath {
			f.DirectHandler().ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(n.srv.Close)
	n.f = reopen(t, n, s)
	current.Store(n.f)
	return n
}

func reopen(t *testing.T, n *node, s setup) *Fortress {
	t.Helper()
	f, err := Open(config(t, n, s))
	if err != nil {
		t.Fatalf("open %s: %v", n.name, err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func config(t *testing.T, n *node, s setup) Config {
	t.Helper()
	secret := s.secret
	if secret == nil {
		secret = testSecret
	}
	mode, url := group.RelayOff, ""
	if s.relay != "" {
		mode, url = group.RelayOwn, s.relay
	}
	direct := ""
	if n.srv != nil {
		direct = n.srv.URL
	}
	cfg := Config{
		App:      App{ID: n.app, Name: "App " + n.app, Version: "1.0.0"},
		Secret:   secret,
		Identity: identity(t, n.name),
		Self:     group.Self{Name: n.name, Deployment: "container", DirectURL: direct},
		Relay:    mode,
		RelayURL: url,
		LAN:      s.lan,
		Store:    n.store,
		Status:   source{app: n.app, instance: n.name},
		Actions: []Action{{Name: "files.drop", Run: func(_ context.Context, from Caller, body []byte) ([]byte, error) {
			if string(body) == `"full"` {
				return nil, &Refusal{Code: "disk_full"}
			}
			n.mu.Lock()
			n.dropped = append(n.dropped, from.App+":"+string(body))
			n.mu.Unlock()
			return []byte(`{"ok":true}`), nil
		}}},
		Uses:      []string{"files.drop"},
		OnRemoved: func() { n.removed.Add(1) },
	}
	if !s.noPair {
		cfg.Pairing = &Pairing{LAN: s.pairLAN, Store: n.pairStore, Serve: appRoutes(), Previous: s.previous}
	}
	return cfg
}

// appRoutes are the routes an app's own instances call each other on.
func appRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/whoami", func(w http.ResponseWriter, r *http.Request) {
		c, _ := group.CallerOf(r.Context())
		_, _ = w.Write([]byte(c.ID))
	})
	return mux
}

func relayServer(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(relay.New())
	t.Cleanup(srv.CloseClientConnections)
	t.Cleanup(srv.Close)
	return srv.URL
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func memberOf(f *Fortress, id string) (Member, bool) {
	for _, m := range f.Members() {
		if m.ID == id {
			return m, true
		}
	}
	return Member{}, false
}

func pairedWith(g *group.Group, id string) (group.Member, bool) {
	for _, m := range g.Members() {
		if m.ID == id {
			return m, true
		}
	}
	return group.Member{}, false
}

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

// inRelay opens the given instances on a fresh relay and waits until each
// lists every other one in the fortress.
func inRelay(t *testing.T, apps ...string) []*node {
	t.Helper()
	url := relayServer(t)
	var nodes []*node
	for i := 0; i+1 < len(apps); i += 2 {
		nodes = append(nodes, open(t, apps[i], apps[i+1], setup{relay: url}))
	}
	for _, n := range nodes {
		waitFor(t, n.name+" to see everybody", func() bool { return len(n.f.Members()) == len(nodes)-1 })
	}
	return nodes
}

// meet approves a and b in each other's fortress, as their owners would.
func meet(t *testing.T, a, b *node) {
	t.Helper()
	for _, pair := range [][2]*node{{a, b}, {b, a}} {
		from, to := pair[0], pair[1]
		_, _ = to.f.Status(ctx(t), from.id, "")
		waitFor(t, from.name+" to see "+to.name+" ask", func() bool {
			m, ok := memberOf(from.f, to.id)
			return ok && m.State != ""
		})
		if err := from.f.Approve(to.id); err != nil {
			t.Fatalf("%s approves %s: %v", from.name, to.name, err)
		}
	}
	for _, pair := range [][2]*node{{a, b}, {b, a}} {
		from, to := pair[0], pair[1]
		waitFor(t, from.name+" to know "+to.name+"'s app", func() bool {
			m, _ := memberOf(from.f, to.id)
			return m.App.ID == to.app
		})
	}
}

func refusalCode(err error) string {
	var r *Refusal
	if errors.As(err, &r) {
		return r.Code
	}
	return ""
}

// multicast skips a test on a host that cannot join a multicast group.
func multicast(t *testing.T) {
	t.Helper()
	c, err := net.ListenMulticastUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(239, 255, 77, 251), Port: int(freePort(t))})
	if err != nil {
		t.Skipf("this host cannot join a multicast group: %v", err)
	}
	_ = c.Close()
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
