package signin_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/signin"
	"github.com/junkerderprovinz/parleyport/kit/signin/signintest"
)

func TestAnOpenTokenEndsWhenATestedServiceClosesTheAppAgain(t *testing.T) {
	a := newApp(t)
	p := signintest.NewProvider(t)
	id, tester := closeWithService(t, a, p)
	want(t, setService(t, tester, id, map[string]any{"on": false}), 200, "")
	anyone := a.browser()
	tok := openToken(t, anyone)
	want(t, setService(t, anyone, id, map[string]any{"on": true}), 200, "")
	if a.auth.Anyone() {
		t.Fatal("the service did not close the app")
	}
	script := a.browser()
	script.header.Set("Authorization", "Bearer "+tok)
	if v := script.visitor(); v.Via != "" {
		t.Fatalf("a token made while open outlived the service coming back: %+v", v)
	}
	n := 0
	for _, e := range a.endedWith() {
		if strings.HasSuffix(e, ":firstPassword") {
			n++
		}
	}
	if n < 2 {
		t.Fatalf("the second closing did not reach the app: %v", a.endedWith())
	}
}

func TestAnOpenTokenEndsWhenTheConfigClosesTheApp(t *testing.T) {
	p := signintest.NewProvider(t)
	a := newApp(t, fromConfig(p, false))
	tok := openToken(t, a.browser())
	checkedJustNow(t, a)
	a.cfg = withOption(a.cfg, closed)
	a.open()
	if _, ok := a.auth.TokenVisitor(t.Context(), tok); ok {
		t.Fatal("a token made while open counts in the app the config closed")
	}
}

func TestTheLastServiceOfAnAppWithoutPasswordsNeedsItsOwner(t *testing.T) {
	a := newApp(t, manyAccounts)
	p := signintest.NewProvider(t)
	id, owner := closeWithService(t, a, p)
	p.Next(signintest.Person{Subject: "sub-ben", Name: "ben"})
	ben := a.browser()
	ben.serviceSignIn(p, id)
	if v := ben.visitor(); v.Role != "admin" {
		t.Fatalf("ben is %+v", v)
	}
	want(t, setService(t, ben, id, map[string]any{"on": false}), 409, "lastWayIn")
	want(t, ben.api("DELETE", "methods/oidc/"+id, nil), 409, "lastWayIn")
	a.clock.Add(6 * time.Minute)
	want(t, owner.api("DELETE", "methods/oidc/"+id, nil), 403, "signInAgain")
	if a.auth.Anyone() {
		t.Fatal("the app opened")
	}
	p.Next(ownerAtService)
	fresh := a.browser()
	fresh.serviceSignIn(p, id)
	want(t, fresh.api("DELETE", "methods/oidc/"+id, nil), 200, "")
	if !a.auth.Anyone() {
		t.Fatal("the owner's removal of the last service left the app closed")
	}
}

func TestWrongGuessesForANameCountAcrossBuckets(t *testing.T) {
	a := newApp(t, manyAccounts)
	owner := a.owner()
	addAccount(t, owner, "anna", "viewer")
	r := a.browser().requestTo("/dav")
	for range 6 {
		_, _ = a.auth.CheckPassword(r, "dav", "anna", "wrong password")
	}
	want(t, a.browser().api("POST", "login", map[string]string{"name": "anna", "password": "password of anna"}), 429, "throttled")
	for i := range 10 {
		_, _ = a.auth.CheckPassword(r, "dav", "guess "+string(rune('a'+i)), "wrong password")
	}
	want(t, a.browser().api("POST", "login", map[string]string{"name": "admin", "password": ownerPassword}), 200, "")
}

func TestATestSignInFailsWhenTheServiceRoleChangedMeanwhile(t *testing.T) {
	a := newApp(t, viewersByDefault)
	owner := a.owner()
	p := signintest.NewProvider(t)
	r := owner.api("POST", "methods/oidc", map[string]any{"issuer": p.URL, "clientId": p.ClientID, "secret": p.Secret, "ca": string(p.CA)})
	want(t, r, 200, "")
	id := r.json(t)["service"].(map[string]any)["id"].(string)
	want(t, owner.api("POST", "methods/oidc/"+id+"/test", map[string]string{"return": "/settings", "role": "admin"}), 409, "serviceChanged")
	r = owner.api("POST", "methods/oidc/"+id+"/test", map[string]string{"return": "/settings", "role": "viewer"})
	want(t, r, 200, "")
	p.Next(ownerAtService)
	back := owner.startTrip(p, r.json(t)["url"].(string))
	want(t, setService(t, owner, id, map[string]any{"role": "admin"}), 200, "")
	if got := owner.do("GET", back, nil).Header.Get("Location"); got != "/settings?signin=serviceChanged" {
		t.Fatalf("a test sign-in after a role change ended at %s", got)
	}
	if strings.Contains(string(owner.api("GET", "methods/oidc", nil).Body), `"on":true`) {
		t.Fatal("the service went on with a role the tester never saw")
	}
}

func TestAnOpenTokenEndsTheMomentTheAppCountsAsClosed(t *testing.T) {
	var shut bool
	a := newApp(t, func(c *signin.Config) { c.Closed = func() bool { return shut } })
	tok := openToken(t, a.browser())
	checkedJustNow(t, a)
	shut = true
	if _, ok := a.auth.TokenVisitor(t.Context(), tok); ok {
		t.Fatal("a token made while open counts the moment the app is closed")
	}
}

func TestOnlyTheLastServiceIsTheOwners(t *testing.T) {
	a := newApp(t, manyAccounts)
	p := signintest.NewProvider(t)
	id, owner := closeWithService(t, a, p)
	other := signintest.NewProvider(t)
	second := serviceWith(t, owner, other, nil)
	other.Next(signintest.Person{Subject: "sub-ben", Name: "ben"})
	ben := a.browser()
	ben.serviceSignIn(other, second)
	a.clock.Add(6 * time.Minute)
	want(t, ben.api("DELETE", "methods/oidc/"+id, nil), 200, "")
	want(t, ben.api("DELETE", "methods/oidc/"+second, nil), 409, "lastWayIn")
}

func TestWithAPasswordNoServiceIsTheLastWayIn(t *testing.T) {
	a := newApp(t, manyAccounts)
	owner := a.owner()
	p := signintest.NewProvider(t)
	id := serviceWith(t, owner, p, nil)
	p.Next(signintest.Person{Subject: "sub-ben", Name: "ben"})
	ben := a.browser()
	ben.serviceSignIn(p, id)
	want(t, setService(t, ben, id, map[string]any{"on": false}), 200, "")
}

// checkedJustNow marks the only account as let in by its sign-in service a
// moment ago, so its tokens do not rest for want of one.
func checkedJustNow(t *testing.T, a *app) {
	t.Helper()
	ctx := t.Context()
	docs, _ := a.store.List(ctx, "account")
	var acc map[string]any
	if len(docs) != 1 || json.Unmarshal(docs[0].Data, &acc) != nil {
		t.Fatalf("accounts %v", docs)
	}
	acc["checked"] = a.clock.Now()
	raw, _ := json.Marshal(acc)
	if err := a.store.Apply(ctx, signin.Doc{Kind: "account", ID: docs[0].ID, Data: raw}); err != nil {
		t.Fatal(err)
	}
}
