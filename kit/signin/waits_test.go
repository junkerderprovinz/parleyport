package signin_test

import (
	"context"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/signin"
	"github.com/junkerderprovinz/parleyport/kit/signin/signintest"
)

func TestAnAddedServiceLetsNobodyInWithoutAPassword(t *testing.T) {
	config := signintest.NewProvider(t)
	a := newApp(t, fromConfig(config, false))
	owner := a.owner()
	p, id := addService(t, a, owner, "pocket-id")
	ownerID := owner.visitor().Account
	raw, err := a.store.Get(context.Background(), "account", ownerID)
	if err != nil {
		t.Fatal(err)
	}
	var acc map[string]any
	if err := json.Unmarshal(raw, &acc); err != nil {
		t.Fatal(err)
	}
	delete(acc, "password")
	raw, _ = json.Marshal(acc)
	if err := a.store.Apply(context.Background(), signin.Doc{Kind: "account", ID: ownerID, Data: raw}); err != nil {
		t.Fatal(err)
	}
	a.cfg = withOption(a.cfg, closed)
	a.open()
	if svcs := a.browser().api("GET", "options", nil).json(t)["services"].([]any); len(svcs) != 1 || svcs[0].(map[string]any)["id"] != "config" {
		t.Fatalf("options offers %v without a password", svcs)
	}
	p.Next(ownerAtService)
	if got := a.browser().serviceSignIn(p, id); got != "/home?signin=serviceOff" {
		t.Fatalf("an added service without a password ended at %s", got)
	}
}

func TestAServiceFromTheConfigLetsNobodyInWhileTheAppIsOpen(t *testing.T) {
	p := signintest.NewProvider(t)
	a := newApp(t, fromConfig(p, false))
	if !a.auth.Anyone() {
		t.Fatal("the app is not open")
	}
	if svcs := a.browser().api("GET", "options", nil).json(t)["services"].([]any); len(svcs) != 0 {
		t.Fatalf("an open app offers %v", svcs)
	}
	p.Next(signintest.Person{Subject: "sub-anna", Name: "anna"})
	if got := a.browser().do("GET", "/signin/oidc/config?return=/home", nil).Header.Get("Location"); got != "/home?signin=serviceOff" {
		t.Fatalf("an open app started a sign-in, to %s", got)
	}
}

func TestAFlowEndsOnlyOnItsOwnServicesCallback(t *testing.T) {
	config := signintest.NewProvider(t)
	a := newApp(t, fromConfig(config, true))
	p, id := addService(t, a, a.owner(), "pocket-id")
	b := a.browser()
	start := b.do("GET", "/signin/oidc/"+id+"?return=/home", nil)
	var flow string
	for _, c := range start.Header.Values("Set-Cookie") {
		if strings.Contains(c, "-oidc=") {
			flow = strings.SplitN(c, ";", 2)[0]
		}
	}
	p.Next(signintest.Person{Subject: "sub-anna", Name: "anna"})
	res, err := p.Client().Get(start.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	back, _ := url.Parse(res.Header.Get("Location"))
	r := b.do("GET", "/api/auth/oidc/callback?"+back.RawQuery, nil, "Cookie", flow)
	if got := r.Header.Get("Location"); got != "/home?signin=serviceUnknown" || b.visitor().Via != "" {
		t.Fatalf("a flow of another service ended at %s on the config service's callback", got)
	}
}

func TestCheckPasswordRefusesWhileTheAppIsOpen(t *testing.T) {
	a := newApp(t)
	_, err := a.auth.CheckPassword(a.browser().requestTo("/dav"), "dav", "admin", ownerPassword)
	refusal(t, err, "setPasswordFirst")
}

func TestARemovedImportedAccountDropsItsOldFieldsBeforeTheAppCleansUp(t *testing.T) {
	old := &oldApp{}
	stuck := "8"
	a := newApp(t, importedPair(old))
	stuckFor(a, &stuck)
	want(t, a.signInOwner().api("DELETE", "accounts/8", nil), 200, "")
	if got := old.droppedWith(); !slices.Equal(got, []string{"8:removed"}) {
		t.Fatalf("Drop = %v while the app's own cleanup waits", got)
	}
	if strings.Contains(strings.Join(a.endedWith(), " "), "8:removed") {
		t.Fatal("the stuck removal reached the app")
	}
}
