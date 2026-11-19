package signin_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/signin"
	"github.com/junkerderprovinz/parleyport/kit/signin/signintest"
)

// startTrip begins a trip to the service in b and returns where the
// service sends the browser back, without following it yet.
func (b *browser) startTrip(p *signintest.Provider, path string) string {
	b.t.Helper()
	start := b.do("GET", path, nil)
	if start.Status != http.StatusFound {
		b.t.Fatalf("start %s: %d %s", path, start.Status, start.Body)
	}
	res, err := p.Client().Get(start.Header.Get("Location"))
	if err != nil {
		b.t.Fatal(err)
	}
	_ = res.Body.Close()
	back, _ := url.Parse(res.Header.Get("Location"))
	back.Host = mustURL(b.a).Host
	return back.RequestURI()
}

func TestATripStartedBeforeAResetCountsForNothing(t *testing.T) {
	log := &logBuffer{}
	a := newApp(t, withLog(log))
	owner := a.owner()
	p, id := addService(t, a, owner, "pocket-id")
	insider := a.signIn()
	r := insider.api("POST", "methods/oidc/"+id+"/test", map[string]string{"return": "/settings"})
	want(t, r, 200, "")
	p.Next(signintest.Person{Subject: "sub-insider", Name: "insider"})
	testBack := insider.startTrip(p, r.json(t)["url"].(string))
	p.Next(ownerAtService)
	stranger := a.browser()
	signInBack := stranger.startTrip(p, "/signin/oidc/"+id+"?return=/home")

	code := resetCode(t, a, log)
	want(t, a.browser().api("POST", "reset", map[string]string{"code": code, "password": "a brand new password"}), 200, "")

	if got := insider.do("GET", testBack, nil).Header.Get("Location"); got != "/settings?signin=signInFirst" {
		t.Fatalf("a test sign-in from before the reset ended at %s", got)
	}
	if got := stranger.do("GET", signInBack, nil).Header.Get("Location"); got != "/home?signin=serviceOff" {
		t.Fatalf("a sign-in from before the reset ended at %s", got)
	}
	if svcs := a.browser().api("GET", "options", nil).json(t)["services"].([]any); len(svcs) != 0 {
		t.Fatalf("the service is on again after the reset: %v", svcs)
	}
}

func TestAfterAResetTheServiceNeedsANewTestAndForgetsItsBindings(t *testing.T) {
	log := &logBuffer{}
	a := newApp(t, withLog(log))
	p, id := addService(t, a, a.owner(), "pocket-id")
	code := resetCode(t, a, log)
	want(t, a.browser().api("POST", "reset", map[string]string{"code": code, "password": "a brand new password"}), 200, "")
	b := a.browser()
	want(t, b.api("POST", "login", map[string]string{"password": "a brand new password"}), 200, "")
	want(t, setService(t, b, id, map[string]any{"on": true}), 409, "serviceUntested")
	p.Next(signintest.Person{Subject: "sub-new", Name: "new"})
	if got := b.testService(p, id); got != "/settings?signin=testOk" {
		t.Fatalf("test sign-in ended at %s", got)
	}
	p.Next(ownerAtService)
	c := a.browser()
	c.serviceSignIn(p, id)
	if v := c.visitor(); v.Account == b.visitor().Account {
		t.Fatalf("the binding from before the reset still signs in as the owner: %+v", v)
	}
}

func TestSwitchingAServiceOffEndsItsSessions(t *testing.T) {
	a := newApp(t)
	owner := a.owner()
	p, id := addService(t, a, owner, "pocket-id")
	b := a.browser()
	p.Next(ownerAtService)
	b.serviceSignIn(p, id)
	want(t, setService(t, owner, id, map[string]any{"on": false}), 200, "")
	if b.visitor().Via != "" {
		t.Fatal("a session through a service that is off still counts")
	}
	want(t, setService(t, owner, id, map[string]any{"on": true}), 200, "")
	c := a.browser()
	p.Next(ownerAtService)
	c.serviceSignIn(p, id)
	want(t, owner.api("DELETE", "methods/oidc/"+id, nil), 200, "")
	if c.visitor().Via != "" {
		t.Fatal("a session through a removed service still counts")
	}
}

func TestAnOldSessionCountsOnceEvenAfterASignOut(t *testing.T) {
	old := &oldApp{}
	a := newApp(t)
	old.issued = a.clock.Now().Add(-time.Hour)
	a.cfg = withOption(a.cfg, old.option(oldOwner()))
	a.store = freshStore(a)
	a.open()
	b := a.browser()
	b.c.Jar.SetCookies(mustURL(a), []*http.Cookie{{Name: "old_session", Value: "valid", Path: "/"}})
	if v := b.visitor(); v.Account != "7" {
		t.Fatalf("the old session does not count: %+v", v)
	}
	want(t, b.api("POST", "logout", map[string]any{}), 200, "")
	if v := b.visitor(); v.Via != "" {
		t.Fatalf("the old session came back after the sign-out: %+v", v)
	}
}

func TestSigningOutEverywhereEndsOldSessionsToo(t *testing.T) {
	old := &oldApp{}
	a := newApp(t)
	old.issued = a.clock.Now().Add(-time.Hour)
	a.cfg = withOption(a.cfg, old.option(oldOwner()))
	a.store = freshStore(a)
	a.open()
	b := a.browser()
	b.c.Jar.SetCookies(mustURL(a), []*http.Cookie{{Name: "old_session", Value: "valid", Path: "/"}})
	want(t, a.signIn().api("DELETE", "me/sessions", nil), 200, "")
	if v := b.visitor(); v.Via != "" {
		t.Fatalf("an old session outlived signing out everywhere: %+v", v)
	}
	if old.drops.Load() != 1 {
		t.Fatalf("Drop ran %d times", old.drops.Load())
	}
}

func TestAnAppWithOneOwnerImportsOneOwner(t *testing.T) {
	a := newApp(t)
	freshStore(a)
	a.cfg.Import = func(context.Context) ([]signin.Imported, error) {
		return []signin.Imported{{ID: "1", Name: "anna", Password: "old:x"}, {ID: "2", Name: "ben", Password: "old:y"}}, nil
	}
	if _, err := signin.Open(a.cfg); err == nil {
		t.Fatal("two accounts without an owner imported into an app with one owner")
	}
}

func TestAPasskeyAnswerWithoutAHandleIsRefused(t *testing.T) {
	a := newApp(t)
	key := a.authenticator()
	addPasskey(t, a.owner(), key)
	b := a.browser()
	r := b.api("POST", "login/passkey/options", map[string]any{})
	assertion, err := key.Get(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(assertion, &m); err != nil {
		t.Fatal(err)
	}
	m["response"].(map[string]any)["userHandle"] = ""
	want(t, b.api("POST", "login/passkey", m), 401, "passkeyRefused")
}

func TestACookieWithoutAnySiteHeaderChangesNothing(t *testing.T) {
	a := newApp(t)
	b := a.owner()
	b.header.Del("Sec-Fetch-Site")
	want(t, b.api("POST", "logout", map[string]string{}), 403, "crossSite")
	public := a.cfg.Public()
	want(t, b.api("POST", "logout", map[string]string{}, "Origin", public.Scheme+"://"+public.Host), 200, "")
}

func TestARequestForTheHTTPSAddressGetsSecureCookies(t *testing.T) {
	a := newApp(t)
	public, _ := url.Parse("https://alpha.example")
	a.cfg.Public = func() *url.URL { return public }
	a.open()
	req := httptest.NewRequest("PUT", "http://alpha.example"+signin.APIPrefix+"me/password", strings.NewReader(`{"next":"`+ownerPassword+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	a.auth.Handler().ServeHTTP(rec, req)
	if set := rec.Header().Get("Set-Cookie"); !strings.HasPrefix(set, "__Host-alpha-session=") || !strings.Contains(set, "Secure") {
		t.Fatalf("cookie %q", set)
	}
}
