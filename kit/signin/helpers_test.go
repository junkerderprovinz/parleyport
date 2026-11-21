package signin_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/signin"
	"github.com/junkerderprovinz/parleyport/kit/signin/memstore"
)

const ownerPassword = "correct horse battery"

// clock is a time the test moves by hand.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// app is an app that uses the package: the contract under /api/signin/v1/
// and the browser routes, and a route /app that answers who the guard found.
type app struct {
	t     *testing.T
	auth  *signin.Auth
	store *memstore.Store
	clock *clock
	srv   *httptest.Server
	cfg   signin.Config
	// base is the path the app serves the package under, Config.Base.
	base  string
	ended []string
	mu    sync.Mutex
}

type option func(*signin.Config)

func newApp(t *testing.T, opts ...option) *app {
	t.Helper()
	a := &app{t: t, store: memstore.New(), clock: newClock()}
	a.srv = httptest.NewUnstartedServer(nil)
	a.srv.StartTLS()
	t.Cleanup(a.srv.Close)
	seal, err := signin.NewSealer(testKey())
	if err != nil {
		t.Fatal(err)
	}
	public, _ := url.Parse(strings.Replace(a.srv.URL, "127.0.0.1", "localhost", 1))
	a.cfg = signin.Config{
		Domain:      "alpha",
		Name:        "Alpha",
		Store:       a.store,
		Seal:        seal,
		Owner:       true,
		TokenPrefix: "al",
		Public:      func() *url.URL { return public },
		Now:         a.clock.Now,
		Hooks: signin.Hooks{
			Ended: func(_ context.Context, account string, what signin.Ending) error {
				a.mu.Lock()
				a.ended = append(a.ended, account+":"+string(what))
				a.mu.Unlock()
				return nil
			},
		},
	}
	for _, o := range opts {
		o(&a.cfg)
	}
	a.open()
	return a
}

// open opens the package on the app's store, as a start of the app does.
func (a *app) open() {
	a.t.Helper()
	if a.auth != nil {
		_ = a.auth.Close()
	}
	auth, err := signin.Open(a.cfg)
	if err != nil {
		a.t.Fatal(err)
	}
	a.t.Cleanup(func() { _ = auth.Close() })
	a.auth = auth
	a.base = a.cfg.Base
	if a.base == "" {
		a.base = "/"
	}
	mux := http.NewServeMux()
	mux.Handle(a.base+"api/signin/v1/", auth.Handler())
	mux.Handle(a.base+"signin/", auth.Handler())
	for _, s := range a.cfg.Services {
		for _, path := range []string{s.StartPath, s.CallbackPath} {
			if path != "" {
				mux.Handle(a.base+strings.TrimPrefix(path, "/"), auth.Handler())
			}
		}
	}
	mux.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		v, ok := signin.From(r.Context())
		if !ok {
			http.Error(w, "nobody", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(v)
	})
	a.srv.Config.Handler = auth.Guard(mux)
}

func (a *app) endedWith() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.ended...)
}

// browser is one browser with its own cookies.
type browser struct {
	t      *testing.T
	a      *app
	c      *http.Client
	header http.Header
}

func (a *app) browser() *browser {
	jar, _ := cookiejar.New(nil)
	c := new(http.Client)
	*c = *a.srv.Client()
	c.Jar = jar
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &browser{t: a.t, a: a, c: c, header: http.Header{"Sec-Fetch-Site": {"same-origin"}}}
}

type reply struct {
	Status int
	Header http.Header
	Body   []byte
}

func (r reply) json(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.Body, &m); err != nil {
		t.Fatalf("body %q is not JSON: %v", r.Body, err)
	}
	return m
}

func (r reply) code() string {
	var m struct{ Error string }
	_ = json.Unmarshal(r.Body, &m)
	return m.Error
}

func (b *browser) do(method, path string, body any, header ...string) reply {
	b.t.Helper()
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			b.t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, b.a.srv.URL+path, rd)
	if err != nil {
		b.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range b.header {
		req.Header[k] = v
	}
	for i := 0; i+1 < len(header); i += 2 {
		if header[i] == "Host" {
			req.Host = header[i+1]
			continue
		}
		req.Header.Set(header[i], header[i+1])
	}
	res, err := b.c.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(res.Body)
	return reply{Status: res.StatusCode, Header: res.Header, Body: raw}
}

func (b *browser) api(method, path string, body any, header ...string) reply {
	b.t.Helper()
	return b.do(method, b.a.base+"api/signin/v1/"+path, body, header...)
}

// visitor asks /app who the guard found, or returns an empty visitor.
func (b *browser) visitor() signin.Visitor {
	b.t.Helper()
	r := b.do("GET", "/app", nil)
	var v signin.Visitor
	if r.Status == http.StatusOK {
		if err := json.Unmarshal(r.Body, &v); err != nil {
			b.t.Fatal(err)
		}
	}
	return v
}

func want(t *testing.T, r reply, status int, code string) {
	t.Helper()
	if r.Status != status || r.code() != code {
		t.Fatalf("got %d %s, want %d %q", r.Status, r.Body, status, code)
	}
}

// owner sets the first password from a browser and returns that browser,
// signed in.
func (a *app) owner() *browser {
	a.t.Helper()
	b := a.browser()
	want(a.t, b.api("PUT", "me/password", map[string]string{"next": ownerPassword}), 200, "")
	return b
}

// signIn signs a new browser in with the owner's password.
func (a *app) signIn() *browser {
	a.t.Helper()
	b := a.browser()
	want(a.t, b.api("POST", "login", map[string]string{"password": ownerPassword}), 200, "")
	return b
}

func mustURL(a *app) *url.URL {
	u, _ := url.Parse(a.srv.URL)
	return u
}

// requestTo builds the request this browser would send and runs it through
// the guard, for calling the package from app code.
func (b *browser) requestTo(path string) *http.Request {
	b.t.Helper()
	req := httptest.NewRequest("GET", b.a.srv.URL+path, nil)
	req.TLS = &tls.ConnectionState{}
	req.RemoteAddr = "127.0.0.1:40000"
	for k, v := range b.header {
		req.Header[k] = v
	}
	for _, c := range b.c.Jar.Cookies(req.URL) {
		req.AddCookie(c)
	}
	var got *http.Request
	b.a.auth.Guard(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = r })).ServeHTTP(httptest.NewRecorder(), req)
	return got
}

func (b *browser) cookie(name string) *http.Cookie {
	u, _ := url.Parse(b.a.srv.URL)
	for _, c := range b.c.Jar.Cookies(u) {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func withOption(c signin.Config, o option) signin.Config {
	o(&c)
	return c
}

// freshStore gives the app an empty store, as a first start with the
// package on an app's old data.
func freshStore(a *app) *memstore.Store {
	s := memstore.New()
	a.cfg.Store = s
	return s
}
