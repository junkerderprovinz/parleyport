package signin_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/signin"
	"github.com/junkerderprovinz/parleyport/kit/signin/signintest"
)

// fromConfig gives the app the sign-in service p as one from its own
// configuration, with the id config, on the paths an older version of the
// app registered at the service when paths is set.
func fromConfig(p *signintest.Provider, paths bool) option {
	return func(c *signin.Config) {
		spec := signin.ServiceSpec{ID: "config", Provider: "custom", Name: "Company", Issuer: p.URL, ClientID: p.ClientID, Secret: p.Secret, CA: string(p.CA)}
		if paths {
			spec.StartPath, spec.CallbackPath = "/api/auth/oidc/login", "/api/auth/oidc/callback"
		}
		c.Services = []signin.ServiceSpec{spec}
	}
}

func closed(c *signin.Config) { c.Closed = func() bool { return true } }

func TestAClosedAppWithoutPasswordsStaysClosed(t *testing.T) {
	a := newApp(t, closed)
	if a.auth.Anyone() {
		t.Fatal("a closed app without a password is open")
	}
	if v := a.browser().visitor(); v.Via != "" {
		t.Fatalf("a stranger is %+v", v)
	}
	if got := a.browser().api("GET", "options", nil).json(t)["open"]; got != false {
		t.Fatalf("options open = %v", got)
	}
}

func TestNobodyBecomesOwnerOfAClosedApp(t *testing.T) {
	a := newApp(t, closed)
	want(t, a.browser().api("PUT", "me/password", map[string]string{"next": ownerPassword}), 401, "signInFirst")
}

func TestAServiceFromTheConfigIsOnWithoutATest(t *testing.T) {
	p := signintest.NewProvider(t)
	a := newApp(t, manyAccounts, closed, fromConfig(p, false))
	svcs := a.browser().api("GET", "options", nil).json(t)["services"].([]any)
	if len(svcs) != 1 || svcs[0].(map[string]any)["id"] != "config" {
		t.Fatalf("options services %v", svcs)
	}
	p.Next(signintest.Person{Subject: "sub-anna", Name: "anna"})
	b := a.browser()
	if got := b.serviceSignIn(p, "config"); got != "/home" {
		t.Fatalf("the sign-in ended at %s", got)
	}
	if v := b.visitor(); v.Via != signin.ViaService || v.Service != "config" || v.Name != "anna" {
		t.Fatalf("visitor %+v", v)
	}
}

func TestAClosedAppTakesNoOtherServiceWithoutAPassword(t *testing.T) {
	p := signintest.NewProvider(t)
	a := newApp(t, manyAccounts, closed, fromConfig(p, false))
	p.Next(signintest.Person{Subject: "sub-anna", Name: "anna"})
	b := a.browser()
	b.serviceSignIn(p, "config")
	other := signintest.NewProvider(t)
	want(t, b.api("POST", "methods/oidc", map[string]any{"provider": "pocket-id", "issuer": other.URL, "clientId": "x", "secret": "y"}), 409, "setPasswordFirst")
}

func TestAServiceFromTheConfigKeepsItsOwnPaths(t *testing.T) {
	p := signintest.NewProvider(t)
	a := newApp(t, manyAccounts, closed, fromConfig(p, true))
	p.Next(signintest.Person{Subject: "sub-anna", Name: "anna"})
	b := a.browser()
	if got := b.via(p, "/api/auth/oidc/login?redirect=/files"); got != "/files" {
		t.Fatalf("the old start path ended at %s", got)
	}
	if v := b.visitor(); v.Service != "config" {
		t.Fatalf("visitor %+v", v)
	}
	p.Next(signintest.Person{Subject: "sub-anna", Name: "anna"})
	if got := a.browser().via(p, "/api/auth/oidc/login?redirect=https://evil.example"); got != "/" {
		t.Fatalf("the old start path went off the app to %s", got)
	}
	list := b.api("GET", "methods/oidc", nil)
	if !strings.Contains(string(list.Body), `"redirect":"`+a.cfg.Public().String()+`/api/auth/oidc/callback"`) || !strings.Contains(string(list.Body), `"fromConfig":true`) {
		t.Fatalf("services %s", list.Body)
	}
}

func TestAServiceFromTheConfigCannotBeChangedOrRemoved(t *testing.T) {
	p := signintest.NewProvider(t)
	a := newApp(t, fromConfig(p, false))
	owner := a.owner()
	want(t, setService(t, owner, "config", map[string]any{"name": "Elsewhere"}), 409, "fromConfig")
	want(t, owner.api("DELETE", "methods/oidc/config", nil), 409, "fromConfig")
	want(t, owner.api("POST", "methods/oidc/config/test", map[string]string{}), 409, "fromConfig")
}

func TestAResetPausesTheServiceFromTheConfigUntilAnAdminTurnsItOn(t *testing.T) {
	log := &logBuffer{}
	p := signintest.NewProvider(t)
	a := newApp(t, fromConfig(p, false), withLog(log))
	a.owner()
	code := resetCode(t, a, log)
	want(t, a.browser().api("POST", "reset", map[string]string{"code": code, "password": "a brand new password"}), 200, "")
	a.open()
	if svcs := a.browser().api("GET", "options", nil).json(t)["services"].([]any); len(svcs) != 0 {
		t.Fatalf("the service is on again after a restart: %v", svcs)
	}
	owner := a.browser()
	want(t, owner.api("POST", "login", map[string]string{"password": "a brand new password"}), 200, "")
	want(t, setService(t, owner, "config", map[string]any{"on": true}), 200, "")
	if svcs := a.browser().api("GET", "options", nil).json(t)["services"].([]any); len(svcs) != 1 {
		t.Fatalf("the confirmed service is not offered: %v", svcs)
	}
}

func TestAServiceThatLeftTheConfigEndsItsSessions(t *testing.T) {
	p := signintest.NewProvider(t)
	a := newApp(t, fromConfig(p, false))
	a.owner()
	p.Next(ownerAtService)
	b := a.browser()
	b.serviceSignIn(p, "config")
	a.cfg.Services = nil
	a.open()
	if b.visitor().Via != "" {
		t.Fatal("a session of a service the config no longer names counts")
	}
}

// admits answers Hooks.Admit from a table by name: a role, or "away".
type admits struct {
	mu      sync.Mutex
	by      map[string]string
	arrived []signin.Arrival
}

func (ad *admits) set(name, answer string) {
	ad.mu.Lock()
	ad.by[name] = answer
	ad.mu.Unlock()
}

func (ad *admits) option(c *signin.Config) {
	c.Hooks.Admit = func(_ context.Context, in signin.Arrival) (string, error) {
		ad.mu.Lock()
		defer ad.mu.Unlock()
		ad.arrived = append(ad.arrived, in)
		if ad.by[in.Name] == "away" {
			return "", errors.New("not in the allowed groups")
		}
		return ad.by[in.Name], nil
	}
}

func TestAdmitDecidesTheRoleOfANewcomer(t *testing.T) {
	ad := &admits{by: map[string]string{"anna": "viewer"}}
	p := signintest.NewProvider(t)
	a := newApp(t, manyAccounts, closed, fromConfig(p, false), ad.option)
	p.Next(signintest.Person{Subject: "sub-anna", Name: "anna", Groups: []string{"family"}})
	b := a.browser()
	b.serviceSignIn(p, "config")
	if v := b.visitor(); v.Role != "viewer" {
		t.Fatalf("anna is %+v", v)
	}
	if in := ad.arrived[0]; in.Account != "" || in.Issuer != p.URL || in.Subject != "sub-anna" || !slices.Equal(in.Groups, []string{"family"}) {
		t.Fatalf("Admit heard %+v", in)
	}
}

func TestAdmitTurnsAwayAndEndsTheAccountsWaysIn(t *testing.T) {
	ad := &admits{by: map[string]string{}}
	p := signintest.NewProvider(t)
	a := newApp(t, manyAccounts, closed, fromConfig(p, false), ad.option)
	p.Next(signintest.Person{Subject: "sub-anna", Name: "anna"})
	b := a.browser()
	b.serviceSignIn(p, "config")
	tok := b.api("POST", "me/tokens", map[string]any{"name": "script", "scopes": []string{"read"}}).json(t)["value"].(string)
	id := b.visitor().Account
	ad.set("anna", "away")
	p.Next(signintest.Person{Subject: "sub-anna", Name: "anna"})
	if got := a.browser().serviceSignIn(p, "config"); got != "/home?signin=notAdmitted" {
		t.Fatalf("the refused sign-in ended at %s", got)
	}
	script := a.browser()
	script.header.Set("Authorization", "Bearer "+tok)
	if b.visitor().Via != "" || script.visitor().Via != "" {
		t.Fatal("a session or token outlived the refusal")
	}
	if !slices.Contains(a.endedWith(), id+":refused") {
		t.Fatalf("Ended = %v", a.endedWith())
	}
	p.Next(signintest.Person{Subject: "sub-ben", Name: "ben"})
	ad.set("ben", "away")
	if got := a.browser().serviceSignIn(p, "config"); got != "/home?signin=notAdmitted" {
		t.Fatalf("a refused newcomer ended at %s", got)
	}
}

func TestALowerRoleFromAdmitEndsTheHigherSessions(t *testing.T) {
	ad := &admits{by: map[string]string{}}
	p := signintest.NewProvider(t)
	a := newApp(t, manyAccounts, closed, fromConfig(p, false), ad.option)
	p.Next(signintest.Person{Subject: "sub-anna", Name: "anna"})
	b := a.browser()
	b.serviceSignIn(p, "config")
	id := b.visitor().Account
	ad.set("anna", "viewer")
	p.Next(signintest.Person{Subject: "sub-anna", Name: "anna"})
	c := a.browser()
	c.serviceSignIn(p, "config")
	if b.visitor().Via != "" {
		t.Fatal("the admin session outlived the lower role")
	}
	if v := c.visitor(); v.Role != "viewer" {
		t.Fatalf("the new session is %+v", v)
	}
	if !slices.Contains(a.endedWith(), id+":role") {
		t.Fatalf("Ended = %v", a.endedWith())
	}
}

func TestAdmitRunsOnEverySilentRenewal(t *testing.T) {
	var mu sync.Mutex
	var heard [][]string
	ad := &admits{by: map[string]string{}}
	p := signintest.NewProvider(t)
	a := newApp(t, manyAccounts, closed, fromConfig(p, false), ad.option, func(c *signin.Config) {
		c.Hooks.SignedIn = func(_ context.Context, _ signin.Visitor, groups []string) {
			mu.Lock()
			heard = append(heard, groups)
			mu.Unlock()
		}
	})
	p.Next(signintest.Person{Subject: "sub-anna", Name: "anna", Groups: []string{"family"}})
	b := a.browser()
	b.serviceSignIn(p, "config")
	a.clock.Add(25 * time.Hour)
	p.Next(signintest.Person{Subject: "sub-anna", Name: "anna", Groups: []string{"family", "admins"}})
	if got := b.via(p, "/signin/oidc/config?renew=1&return=/home"); got != "/home" {
		t.Fatalf("the renewal ended at %s", got)
	}
	mu.Lock()
	if len(heard) != 2 || !slices.Equal(heard[1], []string{"family", "admins"}) {
		t.Fatalf("SignedIn heard %v", heard)
	}
	mu.Unlock()
	if len(ad.arrived) != 2 || ad.arrived[1].Account == "" {
		t.Fatalf("Admit heard %+v", ad.arrived)
	}

	ad.set("anna", "away")
	a.clock.Add(25 * time.Hour)
	p.Next(signintest.Person{Subject: "sub-anna", Name: "anna"})
	if got := b.via(p, "/signin/oidc/config?renew=1&return=/home"); got != "/home?signin=notAdmitted" {
		t.Fatalf("a refused renewal ended at %s", got)
	}
	if b.visitor().Via != "" {
		t.Fatal("the session outlived a refused renewal")
	}
}

func TestAdmitNeverChangesTheOwner(t *testing.T) {
	ad := &admits{by: map[string]string{ownerAtService.Name: "viewer"}}
	p := signintest.NewProvider(t)
	a := newApp(t, manyAccounts, fromConfig(p, false), ad.option)
	owner := a.owner()
	link := owner.api("POST", "me/identities/config/link", map[string]string{"return": "/settings"}).json(t)["url"].(string)
	p.Next(ownerAtService)
	owner.via(p, link)
	p.Next(ownerAtService)
	b := a.browser()
	b.serviceSignIn(p, "config")
	if v := b.visitor(); v.Role != "admin" || v.Account != owner.visitor().Account {
		t.Fatalf("the owner came in as %+v", v)
	}
	ad.set(ownerAtService.Name, "away")
	p.Next(ownerAtService)
	a.browser().serviceSignIn(p, "config")
	if owner.visitor().Via == "" {
		t.Fatal("turning the owner away at the service signed the owner out")
	}
}
