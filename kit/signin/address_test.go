package signin_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/signin"
	"github.com/junkerderprovinz/parleyport/kit/signin/signintest"
)

func TestRequestsWithoutAPeerAddressAreNotCountedTogether(t *testing.T) {
	a := newApp(t, manyAccounts)
	a.owner()
	b := a.browser()
	for i := range 10 {
		b.from("@", "POST", "/api/signin/v1/login", map[string]string{"name": "guess " + string(rune('a'+i)), "password": "wrong password"})
	}
	want(t, b.from("@", "POST", "/api/signin/v1/login", map[string]string{"name": "admin", "password": ownerPassword}), 200, "")
}

// socketPeers trusts every request that came over the app's Unix socket.
func socketPeers(c *signin.Config) {
	c.TrustedPeer = func(r *http.Request) bool { return strings.HasPrefix(r.RemoteAddr, "@") }
}

func TestATrustedPeerCountsLikeAKnownProxy(t *testing.T) {
	a := newApp(t, manyAccounts, socketPeers)
	a.owner()
	b := a.browser()
	for i := range 10 {
		b.from("@", "POST", "/api/signin/v1/login", map[string]string{"name": "guess " + string(rune('a'+i)), "password": "wrong password"}, "X-Forwarded-For", "203.0.113.5")
	}
	want(t, b.from("@", "POST", "/api/signin/v1/login", map[string]string{"name": "admin", "password": ownerPassword}, "X-Forwarded-For", "203.0.113.5"), 429, "throttled")
	want(t, b.from("@", "POST", "/api/signin/v1/login", map[string]string{"name": "admin", "password": ownerPassword}, "X-Forwarded-For", "203.0.113.6"), 200, "")
}

func TestATrustedPeerSaysWhenTheBrowserUsedHTTPS(t *testing.T) {
	for _, tt := range []struct {
		name   string
		opts   []option
		cookie string
	}{
		{"trusted", []option{socketPeers}, "__Host-alpha-session="},
		{"not trusted", nil, "alpha_session="},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := newApp(t, append(tt.opts, func(c *signin.Config) { c.Public = nil })...)
			req := httptest.NewRequest("PUT", "http://alpha.example"+signin.APIPrefix+"me/password", strings.NewReader(`{"next":"`+ownerPassword+`"}`))
			req.RemoteAddr = "@"
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			req.Header.Set("X-Forwarded-Proto", "https")
			rec := httptest.NewRecorder()
			a.auth.Handler().ServeHTTP(rec, req)
			if set := rec.Header().Get("Set-Cookie"); !strings.HasPrefix(set, tt.cookie) {
				t.Fatalf("cookie %q, want %s", set, tt.cookie)
			}
		})
	}
}

// direct sends a change straight to the package as a browser on host would,
// with only an Origin to say where it comes from.
func direct(a *app, host, origin string) int {
	req := httptest.NewRequest("POST", "http://"+host+signin.APIPrefix+"logout", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", origin)
	rec := httptest.NewRecorder()
	a.auth.Handler().ServeHTTP(rec, req)
	return rec.Code
}

func TestAPlainHTTPLANAddressCanSignInNextToAPublicAddress(t *testing.T) {
	a := newApp(t)
	public, _ := url.Parse("https://alpha.example")
	a.cfg.Public = func() *url.URL { return public }
	a.open()
	if got := direct(a, "192.168.1.5:8080", "http://192.168.1.5:8080"); got != http.StatusOK {
		t.Fatalf("a change from the LAN address got %d", got)
	}
	if got := direct(a, "192.168.1.5:8080", "http://evil.example"); got != http.StatusForbidden {
		t.Fatalf("a change from another site got %d", got)
	}
}

func TestThePublicAddressCountsWithoutItsDefaultPortOrCase(t *testing.T) {
	a := newApp(t)
	public, _ := url.Parse("https://Alpha.Example:443/")
	a.cfg.Public = func() *url.URL { return public }
	a.open()
	if got := direct(a, "10.0.0.2", "https://alpha.example"); got != http.StatusOK {
		t.Fatalf("a change from the public address got %d", got)
	}

	b := newApp(t)
	upper, _ := url.Parse(strings.Replace(b.cfg.Public().String(), "localhost", "LOCALHOST", 1))
	b.cfg.Public = func() *url.URL { return upper }
	b.open()
	auth := b.authenticator()
	auth.Origin = strings.ToLower(auth.Origin)
	addPasskey(t, b.owner(), auth)
}

func TestPasskeysAreOfferedOnlyAtThePublicAddress(t *testing.T) {
	a := newApp(t)
	addPasskey(t, a.owner(), a.authenticator())
	if a.browser().api("GET", "options", nil, "Host", a.cfg.Public().Host).json(t)["passkeys"] != true {
		t.Fatal("no passkeys offered at the public address")
	}
	if got := a.browser().api("GET", "options", nil).json(t)["passkeys"]; got != false {
		t.Fatalf("passkeys offered at another address: %v", got)
	}
}

// withBase serves the package under path, as an app behind a proxy that
// shares its host with others does.
func withBase(path string) option {
	return func(c *signin.Config) { c.Base = path }
}

func TestABasePathKeepsCookiesAndRedirectsUnderIt(t *testing.T) {
	a := newApp(t, withBase("/files/"))
	owner := a.owner()
	twoFactor(t, a, owner)
	r := a.browser().api("POST", "login", map[string]string{"password": ownerPassword})
	if set := strings.Join(r.Header.Values("Set-Cookie"), " "); !strings.Contains(set, "Path=/files/api/signin/v1/login") {
		t.Fatalf("the step cookie is not under the base: %s", set)
	}
	if me := owner.visitor(); me.Via != signin.ViaPassword {
		t.Fatalf("the session does not count under a base: %+v", me)
	}

	b := newApp(t, withBase("/files/"))
	admin := b.owner()
	p, id := addServiceAt(t, admin, "/files/settings")
	list := admin.api("GET", "methods/oidc", nil)
	if !strings.Contains(string(list.Body), `"redirect":"`+b.cfg.Public().String()+`/files/signin/oidc/callback"`) {
		t.Fatalf("the redirect is not under the base: %s", list.Body)
	}
	p.Next(ownerAtService)
	if got := b.browser().via(p, "/files/signin/oidc/"+id+"?return=/elsewhere"); got != "/files/" {
		t.Fatalf("a way back off the base ended at %s", got)
	}
	p.Next(ownerAtService)
	if got := b.browser().via(p, "/files/signin/oidc/"+id+"?return=/files/home"); got != "/files/home" {
		t.Fatalf("a way back under the base ended at %s", got)
	}
}

// addServiceAt adds a sign-in service and passes its test sign-in, coming
// back to ret.
func addServiceAt(t *testing.T, owner *browser, ret string) (*signintest.Provider, string) {
	t.Helper()
	p := signintest.NewProvider(t)
	return p, addProvider(t, owner, p, ret)
}

// addProvider adds p as a sign-in service and passes its test sign-in as
// ownerAtService, coming back to ret.
func addProvider(t *testing.T, owner *browser, p *signintest.Provider, ret string) string {
	t.Helper()
	r := owner.api("POST", "methods/oidc", map[string]any{
		"provider": "pocket-id", "issuer": p.URL, "clientId": p.ClientID, "secret": p.Secret, "ca": string(p.CA),
	})
	want(t, r, 200, "")
	id := r.json(t)["service"].(map[string]any)["id"].(string)
	p.Next(ownerAtService)
	r = owner.api("POST", "methods/oidc/"+id+"/test", map[string]string{"return": ret})
	want(t, r, 200, "")
	start := r.json(t)["url"].(string)
	if !strings.HasPrefix(start, owner.a.base+"signin/oidc/") {
		t.Fatalf("the test sign-in starts at %s", start)
	}
	if got := owner.via(p, start); got != ret+"?signin=testOk" {
		t.Fatalf("test sign-in ended at %s", got)
	}
	return id
}
