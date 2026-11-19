package signin_test

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/signin"
)

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

func TestProxyHeadersSignNobodyIn(t *testing.T) {
	a := newApp(t, func(c *signin.Config) { c.Proxies = []netip.Prefix{netip.MustParsePrefix("10.0.0.5/32")} })
	owner := a.owner()
	for _, peer := range []string{"10.0.0.5", "127.0.0.1"} {
		if v := a.browser().visitorFrom(peer, "Remote-User", "junker", "Remote-Groups", "admins", "X-Forwarded-User", "junker"); v.Via != "" {
			t.Fatalf("headers from %s signed in %+v", peer, v)
		}
	}
	want(t, owner.api("GET", "methods/proxy", nil), 404, "notFound")
	want(t, owner.api("POST", "me/identities/proxy", map[string]any{}), 404, "notFound")
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
