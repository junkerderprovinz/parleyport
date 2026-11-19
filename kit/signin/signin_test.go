package signin_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/signin"
	"github.com/junkerderprovinz/parleyport/kit/signin/memstore"
)

func TestWithoutAPasswordEveryoneIsAdmin(t *testing.T) {
	a := newApp(t)
	if !a.auth.Anyone() {
		t.Fatal("a new app is not open")
	}
	v, found := signin.From(a.browser().requestTo("/app").Context())
	if !found || v.Via != signin.ViaAnyone || v.Role != "admin" || !v.AtLeast("admin") {
		t.Fatalf("visitor %+v", v)
	}
	opts := a.browser().api("GET", "options", nil).json(t)
	if opts["open"] != true {
		t.Fatalf("options %v", opts)
	}
}

func TestOpenFailsOnAStoreThatDoesNotRead(t *testing.T) {
	s := memstore.New()
	s.Break(errors.New("disk gone"))
	seal, _ := signin.NewSealer(testKey())
	_, err := signin.Open(signin.Config{Domain: "alpha", Store: s, Seal: seal, Owner: true})
	if err == nil {
		t.Fatal("Open went on with a store it cannot read")
	}
}

func TestOpenChecksTheConfig(t *testing.T) {
	seal, _ := signin.NewSealer(testKey())
	tests := []struct {
		name string
		cfg  signin.Config
	}{
		{"no store", signin.Config{Domain: "alpha", Seal: seal}},
		{"no seal", signin.Config{Domain: "alpha", Store: memstore.New()}},
		{"domain with upper case", signin.Config{Domain: "Alpha", Store: memstore.New(), Seal: seal}},
		{"domain with a dash", signin.Config{Domain: "al-pha", Store: memstore.New(), Seal: seal}},
		{"bad token prefix", signin.Config{Domain: "alpha", Store: memstore.New(), Seal: seal, TokenPrefix: "A_"}},
		{"duplicate role", signin.Config{Domain: "alpha", Store: memstore.New(), Seal: seal, Roles: []string{"admin", "admin"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := signin.Open(tt.cfg); err == nil {
				t.Fatal("Open accepted it")
			}
		})
	}
}

func TestTheFirstPasswordClosesTheAppAndSignsIn(t *testing.T) {
	a := newApp(t)
	b := a.owner()
	if a.auth.Anyone() {
		t.Fatal("the app is still open")
	}
	v := b.visitor()
	if v.Via != signin.ViaPassword || v.Role != "admin" || v.Account == "" {
		t.Fatalf("visitor %+v", v)
	}
	if got := a.browser().visitor(); got.Via != "" {
		t.Fatalf("a stranger is %+v", got)
	}
	if got := a.endedWith(); len(got) != 1 || !strings.HasSuffix(got[0], ":firstPassword") {
		t.Fatalf("Ended = %v", got)
	}
}

func TestPasswordLength(t *testing.T) {
	a := newApp(t)
	b := a.browser()
	want(t, b.api("PUT", "me/password", map[string]string{"next": "short"}), 400, "passwordShort")
	want(t, b.api("PUT", "me/password", map[string]string{"next": strings.Repeat("x", 1025)}), 400, "passwordLong")
}

func TestSignInWithThePassword(t *testing.T) {
	a := newApp(t)
	a.owner()
	b := a.browser()
	want(t, b.api("POST", "login", map[string]string{"password": "wrong password"}), 401, "wrongPassword")
	if b.visitor().Via != "" {
		t.Fatal("a wrong password signed in")
	}
	want(t, b.api("POST", "login", map[string]string{"password": ownerPassword}), 200, "")
	if v := b.visitor(); v.Via != signin.ViaPassword {
		t.Fatalf("visitor %+v", v)
	}
	want(t, b.api("POST", "logout", nil), 200, "")
	if b.visitor().Via != "" {
		t.Fatal("still signed in after logout")
	}
}

func TestTheSessionCookie(t *testing.T) {
	a := newApp(t)
	b := a.owner()
	r := b.api("POST", "login", map[string]string{"password": ownerPassword})
	var set string
	for _, c := range r.Header.Values("Set-Cookie") {
		if strings.HasPrefix(c, "__Host-alpha-session=") {
			set = c
		}
	}
	if set == "" {
		t.Fatalf("no __Host-alpha-session cookie in %v", r.Header.Values("Set-Cookie"))
	}
	for _, part := range []string{"HttpOnly", "Secure", "SameSite=Lax", "Path=/"} {
		if !strings.Contains(set, part) {
			t.Errorf("cookie %q lacks %s", set, part)
		}
	}
	if strings.Contains(strings.ToLower(set), "domain=") {
		t.Errorf("cookie %q names a domain", set)
	}
}

func TestEverySignInGetsANewSession(t *testing.T) {
	a := newApp(t)
	b := a.owner()
	first := *b.cookie("__Host-alpha-session")
	want(t, b.api("POST", "login", map[string]string{"password": ownerPassword}), 200, "")
	second := b.cookie("__Host-alpha-session")
	if second == nil || second.Value == first.Value {
		t.Fatal("the session stayed the same across a sign-in")
	}
	old := a.browser()
	old.c.Jar.SetCookies(mustURL(a), []*http.Cookie{&first})
	if old.visitor().Via != "" {
		t.Fatal("the session before the sign-in still counts")
	}
	sessions := b.api("GET", "me/sessions", nil)
	if n := strings.Count(string(sessions.Body), `"id"`); n != 1 {
		t.Fatalf("%d sessions listed: %s", n, sessions.Body)
	}
}

func TestSessionsEndAfterAWeekUnusedOrAMonthInAll(t *testing.T) {
	a := newApp(t)
	b := a.owner()
	a.clock.Add(6 * 24 * time.Hour)
	if b.visitor().Via == "" {
		t.Fatal("a session used six days ago ended")
	}
	a.clock.Add(6 * 24 * time.Hour)
	if b.visitor().Via == "" {
		t.Fatal("a session used six days ago ended")
	}
	a.clock.Add(8 * 24 * time.Hour)
	if b.visitor().Via != "" {
		t.Fatal("a session unused for eight days still counts")
	}

	c := a.signIn()
	for range 5 {
		a.clock.Add(6 * 24 * time.Hour)
		c.visitor()
	}
	if c.visitor().Via != "" {
		t.Fatal("a session older than 30 days still counts")
	}
}

func TestChangingThePasswordEndsTheOtherSessions(t *testing.T) {
	a := newApp(t)
	b := a.owner()
	other := a.signIn()
	want(t, b.api("PUT", "me/password", map[string]string{"current": "wrong password", "next": "another good password"}), 401, "wrongPassword")
	want(t, b.api("PUT", "me/password", map[string]string{"next": "another good password"}), 401, "wrongPassword")
	want(t, b.api("PUT", "me/password", map[string]string{"current": ownerPassword, "next": "another good password"}), 200, "")
	if b.visitor().Via != signin.ViaPassword {
		t.Fatal("the browser that changed the password was signed out")
	}
	if other.visitor().Via != "" {
		t.Fatal("another session survived the change")
	}
	want(t, a.browser().api("POST", "login", map[string]string{"password": "another good password"}), 200, "")
}

func TestChangesFromAnotherSiteAreRefused(t *testing.T) {
	a := newApp(t)
	b := a.owner()
	for _, site := range []string{"cross-site", "same-site"} {
		r := b.api("POST", "logout", map[string]string{}, "Sec-Fetch-Site", site)
		want(t, r, 403, "crossSite")
	}
	if b.visitor().Via == "" {
		t.Fatal("a cross-site logout went through")
	}
	r := b.api("POST", "logout", map[string]string{}, "Origin", "https://evil.example")
	want(t, r, 403, "crossSite")
	r = b.api("POST", "logout", map[string]string{}, "Content-Type", "text/plain")
	want(t, r, 415, "notJSON")
	want(t, b.api("POST", "logout", map[string]string{}, "Sec-Fetch-Site", "same-origin"), 200, "")
}

func TestManyWrongPasswordsFromOneAddressWait(t *testing.T) {
	a := newApp(t)
	a.owner()
	b := a.browser()
	for range 10 {
		b.api("POST", "login", map[string]string{"password": "wrong password"})
	}
	r := b.api("POST", "login", map[string]string{"password": ownerPassword})
	want(t, r, 429, "throttled")
	if r.json(t)["retryAfter"] == nil {
		t.Fatalf("no retryAfter in %s", r.Body)
	}
	a.clock.Add(16 * time.Minute)
	want(t, b.api("POST", "login", map[string]string{"password": ownerPassword}), 200, "")
}

func TestUnknownNamesStayOutOfTheLog(t *testing.T) {
	a := newApp(t, func(c *signin.Config) { c.Owner = false })
	b := a.owner()
	a.browser().api("POST", "login", map[string]string{"name": "my secret password", "password": "x"})
	log := b.api("GET", "log", nil)
	if log.Status != 200 {
		t.Fatalf("log %d %s", log.Status, log.Body)
	}
	if strings.Contains(string(log.Body), "my secret password") {
		t.Fatalf("the log holds the typed name: %s", log.Body)
	}
	if !strings.Contains(string(log.Body), "wrongPassword") {
		t.Fatalf("the log misses the attempt: %s", log.Body)
	}
}

func TestNewWaysInWaitForAPassword(t *testing.T) {
	a := newApp(t)
	b := a.browser()
	want(t, b.api("POST", "me/tokens", map[string]any{"name": "script", "scopes": []string{"read"}}), 409, "setPasswordFirst")
	want(t, b.api("POST", "me/passkeys/options", map[string]any{}), 409, "setPasswordFirst")
}

func TestMintWantsAFreshSignIn(t *testing.T) {
	a := newApp(t)
	b := a.owner()
	minted := false
	mint := func() error { minted = true; return nil }
	req := b.requestTo("/app")
	if err := a.auth.Mint(req, mint); err != nil || !minted {
		t.Fatalf("Mint right after sign-in = %v, %v", err, minted)
	}
	a.clock.Add(11 * time.Minute)
	minted = false
	if err := a.auth.Mint(b.requestTo("/app"), mint); !errors.Is(err, signin.ErrNotFresh) || minted {
		t.Fatalf("Mint after 11 minutes = %v, %v", err, minted)
	}
	want(t, b.api("POST", "me/confirm", map[string]string{"password": "wrong password"}), 401, "wrongPassword")
	want(t, b.api("POST", "me/confirm", map[string]string{"password": ownerPassword}), 200, "")
	if err := a.auth.Mint(b.requestTo("/app"), mint); err != nil || !minted {
		t.Fatalf("Mint after confirming = %v, %v", err, minted)
	}
}
