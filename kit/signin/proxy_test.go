package signin_test

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/signin"
)

const proxyAddr = "10.0.0.5"

// from sends a request as b from peer, with b's cookies and the given
// headers, straight into the app, so a test can pick the address it comes
// from.
func (b *browser) from(peer, method, path string, body any, header ...string) reply {
	b.t.Helper()
	var rd io.Reader = http.NoBody
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, b.a.srv.URL+path, rd)
	req.TLS = &tls.ConnectionState{}
	req.RemoteAddr = peer + ":41000"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range b.header {
		req.Header[k] = v
	}
	for _, c := range b.c.Jar.Cookies(mustURL(b.a)) {
		req.AddCookie(c)
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Add(header[i], header[i+1])
	}
	rec := httptest.NewRecorder()
	b.a.srv.Config.Handler.ServeHTTP(rec, req)
	return reply{Status: rec.Code, Header: rec.Header(), Body: rec.Body.Bytes()}
}

func (b *browser) visitorFrom(peer string, header ...string) signin.Visitor {
	b.t.Helper()
	r := b.from(peer, "GET", "/app", nil, header...)
	var v signin.Visitor
	if r.Status == http.StatusOK {
		_ = json.Unmarshal(r.Body, &v)
	}
	return v
}

// setUpProxy points the app at a proxy and returns its secret. The proxy is
// still off.
func setUpProxy(t *testing.T, owner *browser, extra map[string]any) string {
	t.Helper()
	settings := map[string]any{"preset": "authelia", "address": proxyAddr, "userHeader": "Remote-User", "groupsHeader": "Remote-Groups", "logout": "https://auth.example/logout"}
	for k, v := range extra {
		settings[k] = v
	}
	want(t, owner.api("PUT", "methods/proxy", settings), 200, "")
	r := owner.api("POST", "methods/proxy/secret", map[string]any{})
	want(t, r, 200, "")
	return r.json(t)["secret"].(string)
}

// turnOnProxy switches the proxy on from the owner's own request through it.
func turnOnProxy(t *testing.T, owner *browser, secret string) {
	t.Helper()
	want(t, owner.from(proxyAddr, "PATCH", "/api/signin/v1/methods/proxy", map[string]any{"on": true, "probe": "probe-7f3a91c2e5d84b06"},
		"X-Proxy-Secret", secret, "Remote-User", "owner-at-proxy"), 200, "")
}

func TestTheProxyNamesTheVisitor(t *testing.T) {
	a := newApp(t)
	owner := a.owner()
	secret := setUpProxy(t, owner, nil)
	turnOnProxy(t, owner, secret)
	want(t, owner.from(proxyAddr, "POST", "/api/signin/v1/me/identities/proxy", map[string]any{}, "X-Proxy-Secret", secret, "Remote-User", "owner-at-proxy"), 200, "")

	stranger := a.browser()
	v := stranger.visitorFrom(proxyAddr, "X-Proxy-Secret", secret, "Remote-User", "owner-at-proxy")
	if v.Via != signin.ViaProxy || v.Account != owner.visitor().Account || v.Service != "authelia" {
		t.Fatalf("visitor %+v", v)
	}
	r := stranger.from(proxyAddr, "POST", "/api/signin/v1/logout", nil, "X-Proxy-Secret", secret, "Remote-User", "owner-at-proxy")
	if r.json(t)["logout"] != "https://auth.example/logout" {
		t.Fatalf("logout %s", r.Body)
	}
}

func TestTheHeaderCountsOnlyFromTheProxyWithItsSecret(t *testing.T) {
	a := newApp(t)
	owner := a.owner()
	secret := setUpProxy(t, owner, nil)
	turnOnProxy(t, owner, secret)
	owner.from(proxyAddr, "POST", "/api/signin/v1/me/identities/proxy", map[string]any{}, "X-Proxy-Secret", secret, "Remote-User", "owner-at-proxy")
	b := a.browser()
	tests := []struct {
		name   string
		peer   string
		header []string
	}{
		{"another address", "10.0.0.6", []string{"X-Proxy-Secret", secret, "Remote-User", "owner-at-proxy"}},
		{"the proxy without the secret", proxyAddr, []string{"Remote-User", "owner-at-proxy"}},
		{"the proxy with a wrong secret", proxyAddr, []string{"X-Proxy-Secret", "guess", "Remote-User", "owner-at-proxy"}},
		{"two names", proxyAddr, []string{"X-Proxy-Secret", secret, "Remote-User", "owner-at-proxy", "Remote-User", "someone"}},
		{"a forwarded address", "10.0.0.6", []string{"X-Forwarded-For", proxyAddr, "X-Proxy-Secret", secret, "Remote-User", "owner-at-proxy"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if v := b.visitorFrom(tt.peer, tt.header...); v.Via != "" {
				t.Fatalf("visitor %+v", v)
			}
		})
	}
}

func TestTheGuardDropsProxyHeadersTheAppMustNotBelieve(t *testing.T) {
	a := newApp(t)
	owner := a.owner()
	setUpProxy(t, owner, nil)
	var seen http.Header
	app := a.srv.Config.Handler
	a.srv.Config.Handler = a.auth.Guard(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { seen = r.Header.Clone() }))
	a.browser().from("10.0.0.6", "GET", "/", nil, "Remote-User", "admin", "Remote-Groups", "admins", "X-Proxy-Secret", "x")
	a.srv.Config.Handler = app
	for _, h := range []string{"Remote-User", "Remote-Groups", "X-Proxy-Secret"} {
		if seen.Get(h) != "" {
			t.Errorf("the app saw %s", h)
		}
	}
	log := owner.api("GET", "log", nil)
	if !strings.Contains(string(log.Body), "headerDropped") {
		t.Fatalf("the log does not show it: %s", log.Body)
	}
}

func TestTheProxyTurnsOnOnlyThroughItself(t *testing.T) {
	a := newApp(t)
	owner := a.owner()
	secret := setUpProxy(t, owner, nil)
	path := "/api/signin/v1/methods/proxy"
	on := map[string]any{"on": true, "probe": "probe-7f3a91c2e5d84b06"}
	want(t, owner.from("10.0.0.6", "PATCH", path, on, "X-Proxy-Secret", secret, "Remote-User", "owner-at-proxy"), 409, "proxyNotThrough")
	want(t, owner.from(proxyAddr, "PATCH", path, on, "Remote-User", "owner-at-proxy"), 409, "proxyNotThrough")
	want(t, owner.from(proxyAddr, "PATCH", path, on, "X-Proxy-Secret", secret, "Remote-User", "probe-7f3a91c2e5d84b06"), 409, "proxyPassesClientHeader")
	want(t, owner.from(proxyAddr, "PATCH", path, map[string]any{"on": true}, "X-Proxy-Secret", secret, "Remote-User", "owner-at-proxy"), 400, "probeMissing")
	turnOnProxy(t, owner, secret)
	if !strings.Contains(string(owner.api("GET", "methods/proxy", nil).Body), `"on":true`) {
		t.Fatal("the proxy is not on")
	}
}

func TestTheCheckShowsWhatTheOwnRequestCarried(t *testing.T) {
	a := newApp(t)
	owner := a.owner()
	secret := setUpProxy(t, owner, nil)
	r := owner.from(proxyAddr, "POST", "/api/signin/v1/methods/proxy/check", map[string]any{"probe": "probe-7f3a91c2e5d84b06"},
		"X-Proxy-Secret", secret, "Remote-User", "probe-7f3a91c2e5d84b06", "Remote-Groups", "admins, family")
	want(t, r, 200, "")
	m := r.json(t)
	if m["from"] != proxyAddr || m["viaProxy"] != true || m["secret"] != true || m["passesClientHeader"] != true {
		t.Fatalf("check %v", m)
	}
	if g := m["groups"].([]any); len(g) != 2 || g[1] != "family" {
		t.Fatalf("groups %v", g)
	}
}

func TestTheSecretShowsOnce(t *testing.T) {
	a := newApp(t)
	owner := a.owner()
	secret := setUpProxy(t, owner, nil)
	if body := string(owner.api("GET", "methods/proxy", nil).Body); strings.Contains(body, secret) || !strings.Contains(body, `"secretSet":true`) {
		t.Fatalf("settings %s", body)
	}
}

func TestOnlyOneAddressCanBeTheProxy(t *testing.T) {
	a := newApp(t)
	owner := a.owner()
	for _, addr := range []string{"10.0.0.0/8", "0.0.0.0", "::", "192.0.2.1", "proxy.local", ""} {
		r := owner.api("PUT", "methods/proxy", map[string]any{"preset": "authelia", "address": addr, "userHeader": "Remote-User"})
		want(t, r, 400, "proxyAddressInvalid")
	}
	want(t, owner.api("PUT", "methods/proxy", map[string]any{"preset": "authelia", "address": proxyAddr, "userHeader": "Remote User"}), 400, "headerInvalid")
}

func TestTheProxyMakesAnAdminAccountForEveryNameItSends(t *testing.T) {
	a := newApp(t, manyAccounts)
	owner := a.owner()
	secret := setUpProxy(t, owner, nil)
	turnOnProxy(t, owner, secret)
	b := a.browser()
	for _, name := range []string{"ben", "clara"} {
		v := b.visitorFrom(proxyAddr, "X-Proxy-Secret", secret, "Remote-User", name, "Remote-Groups", "neighbours")
		if v.Via != signin.ViaProxy || v.Name != name || v.Role != "admin" {
			t.Fatalf("%s is %+v", name, v)
		}
	}
}

func TestTheProxyWaitsForAPassword(t *testing.T) {
	a := newApp(t)
	want(t, a.browser().api("PUT", "methods/proxy", map[string]any{"preset": "authelia", "address": proxyAddr, "userHeader": "Remote-User"}), 409, "setPasswordFirst")
}

func TestTheResetPausesTheProxy(t *testing.T) {
	log := &logBuffer{}
	a := newApp(t, withLog(log))
	owner := a.owner()
	secret := setUpProxy(t, owner, nil)
	turnOnProxy(t, owner, secret)
	code := resetCode(t, a, log)
	r := a.browser().api("POST", "reset", map[string]string{"code": code, "password": "a brand new password"})
	if r.json(t)["removed"].(map[string]any)["proxy"] != true {
		t.Fatalf("reset %s", r.Body)
	}
	if v := a.browser().visitorFrom(proxyAddr, "X-Proxy-Secret", secret, "Remote-User", "owner-at-proxy"); v.Via != "" {
		t.Fatalf("the proxy still lets in %+v", v)
	}
}

func TestForwardedAddressesCountOnlyFromKnownProxies(t *testing.T) {
	a := newApp(t)
	a.owner()
	b := a.browser()
	for i := range 10 {
		a.clock.Add(time.Minute)
		b.from("10.0.0.6", "POST", "/api/signin/v1/login", map[string]string{"password": "wrong password"}, "X-Forwarded-For", "203.0.113."+string(rune('1'+i)))
	}
	a.clock.Add(61 * time.Second)
	want(t, b.from("10.0.0.6", "POST", "/api/signin/v1/login", map[string]string{"password": ownerPassword}, "X-Forwarded-For", "203.0.113.99"), 429, "throttled")

	c := newApp(t, func(c *signin.Config) { c.Proxies = []netip.Prefix{netip.MustParsePrefix("10.0.0.7/32")} })
	c.owner()
	d := c.browser()
	for range 10 {
		c.clock.Add(time.Minute)
		d.from("10.0.0.7", "POST", "/api/signin/v1/login", map[string]string{"password": "wrong password"}, "X-Forwarded-For", "203.0.113.1")
	}
	c.clock.Add(61 * time.Second)
	want(t, d.from("10.0.0.7", "POST", "/api/signin/v1/login", map[string]string{"password": ownerPassword}, "X-Forwarded-For", "203.0.113.2"), 200, "")
}
