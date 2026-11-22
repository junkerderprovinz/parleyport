package signin_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/signin"
	"github.com/junkerderprovinz/parleyport/kit/signin/signintest"
)

// openToken makes a token in b while the app is open and returns its value.
func openToken(t *testing.T, b *browser) string {
	t.Helper()
	r := b.api("POST", "me/tokens", map[string]any{"name": "script", "scopes": []string{"read"}})
	want(t, r, 200, "")
	if r.json(t)["token"].(map[string]any)["endsWhenClosed"] != true {
		t.Fatalf("a token made while open does not say it ends: %s", r.Body)
	}
	return r.json(t)["value"].(string)
}

func TestAnOpenAppMakesTokensThatEndWhenItCloses(t *testing.T) {
	a := newApp(t)
	b := a.browser()
	tok := openToken(t, b)
	var list struct{ Tokens []struct{ ID string } }
	if err := jsonOf(b.api("GET", "me/tokens", nil), &list); err != nil || len(list.Tokens) != 1 {
		t.Fatalf("tokens of an open app %+v %v", list, err)
	}
	owner := a.owner()
	script := a.browser()
	script.header.Set("Authorization", "Bearer "+tok)
	if v := script.visitor(); v.Via != "" {
		t.Fatalf("a token made while open outlived the first password: %+v", v)
	}
	if err := jsonOf(owner.api("GET", "me/tokens", nil), &list); err != nil || len(list.Tokens) != 0 {
		t.Fatalf("tokens after the first password %+v %v", list, err)
	}
}

func TestAnOpenAppDeletesItsTokens(t *testing.T) {
	a := newApp(t)
	b := a.browser()
	openToken(t, b)
	var list struct{ Tokens []struct{ ID string } }
	if err := jsonOf(b.api("GET", "me/tokens", nil), &list); err != nil || len(list.Tokens) != 1 {
		t.Fatalf("tokens %+v %v", list, err)
	}
	want(t, b.api("DELETE", "me/tokens/"+list.Tokens[0].ID, nil), 200, "")
}

// closeWithService adds p as a sign-in service in an open app and passes
// its test sign-in as ownerAtService, which closes the app. It returns the
// service and the browser that did it.
func closeWithService(t *testing.T, a *app, p *signintest.Provider) (string, *browser) {
	t.Helper()
	b := a.browser()
	r := b.api("POST", "methods/oidc", map[string]any{"issuer": p.URL, "clientId": p.ClientID, "secret": p.Secret, "ca": string(p.CA)})
	want(t, r, 200, "")
	id := r.json(t)["service"].(map[string]any)["id"].(string)
	p.Next(ownerAtService)
	if got := b.testService(p, id); got != "/settings?signin=testOk" {
		t.Fatalf("the test sign-in in an open app ended at %s", got)
	}
	return id, b
}

func TestATestedServiceClosesAnOpenApp(t *testing.T) {
	log := &logBuffer{}
	a := newApp(t, withLog(log))
	tok := openToken(t, a.browser())
	p := signintest.NewProvider(t)
	id, tester := closeWithService(t, a, p)
	if a.auth.Anyone() {
		t.Fatal("the app is still open after its service passed the test")
	}
	if v := a.browser().visitor(); v.Via != "" {
		t.Fatalf("a stranger walked into the closed app: %+v", v)
	}
	me := tester.visitor()
	if me.Via != signin.ViaService || me.Role != "admin" {
		t.Fatalf("the tester is %+v", me)
	}
	script := a.browser()
	script.header.Set("Authorization", "Bearer "+tok)
	if v := script.visitor(); v.Via != "" {
		t.Fatalf("a token made while open outlived the closing: %+v", v)
	}
	if !slices.Contains(a.endedWith(), me.Account+":firstPassword") {
		t.Fatalf("Ended = %v", a.endedWith())
	}
	p.Next(ownerAtService)
	c := a.browser()
	c.serviceSignIn(p, id)
	if v := c.visitor(); v.Account != me.Account {
		t.Fatalf("the owner's next sign-in is %+v", v)
	}
	code := resetCode(t, a, log)
	want(t, a.browser().api("POST", "reset", map[string]string{"code": code, "password": "a brand new password"}), 200, "")
	want(t, a.browser().api("POST", "login", map[string]string{"password": "a brand new password"}), 200, "")
}

func TestTurningTheLastServiceOffOpensTheAppAgain(t *testing.T) {
	a := newApp(t)
	id, tester := closeWithService(t, a, signintest.NewProvider(t))
	want(t, setService(t, tester, id, map[string]any{"on": false}), 200, "")
	if !a.auth.Anyone() {
		t.Fatal("the app stayed closed with no password and no service")
	}
}

func TestTwoFactorAndPasskeysStayWithThePassword(t *testing.T) {
	a := newApp(t)
	_, tester := closeWithService(t, a, signintest.NewProvider(t))
	want(t, tester.api("POST", "me/totp", map[string]any{}), 403, "notLocal")
	want(t, tester.api("POST", "me/passkeys/options", map[string]any{}), 403, "notLocal")
	if strings.Contains(string(a.browser().api("GET", "options", nil).Body), `"passkeys":true`) {
		t.Fatal("passkeys are offered without a password")
	}
}

func TestATestSignInStartedOpenCountsForNothingOnceTheAppClosed(t *testing.T) {
	a := newApp(t)
	p := signintest.NewProvider(t)
	stranger := a.browser()
	r := stranger.api("POST", "methods/oidc", map[string]any{"issuer": p.URL, "clientId": p.ClientID, "secret": p.Secret, "ca": string(p.CA)})
	want(t, r, 200, "")
	id := r.json(t)["service"].(map[string]any)["id"].(string)
	r = stranger.api("POST", "methods/oidc/"+id+"/test", map[string]string{"return": "/settings"})
	want(t, r, 200, "")
	p.Next(signintest.Person{Subject: "sub-stranger", Name: "stranger"})
	back := stranger.startTrip(p, r.json(t)["url"].(string))
	owner := a.owner()
	if got := stranger.do("GET", back, nil).Header.Get("Location"); got != "/settings?signin=signInFirst" {
		t.Fatalf("a test sign-in from the open app ended at %s after the first password", got)
	}
	var idents struct{ Identities []struct{ ID string } }
	if err := jsonOf(owner.api("GET", "me/identities", nil), &idents); err != nil || len(idents.Identities) != 0 {
		t.Fatalf("the stranger's identity was bound to the owner: %+v %v", idents, err)
	}
}
