package signin_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/signin"
	"github.com/junkerderprovinz/parleyport/kit/signin/signintest"
)

// viewersByDefault is an app with many accounts whose services bring in
// viewers unless a service names another role.
func viewersByDefault(c *signin.Config) {
	manyAccounts(c)
	c.ServiceRole = "viewer"
}

// serviceWith adds p as a sign-in service with the given extra fields and
// passes its test sign-in.
func serviceWith(t *testing.T, owner *browser, p *signintest.Provider, extra map[string]any) string {
	t.Helper()
	body := map[string]any{"provider": "pocket-id", "issuer": p.URL, "clientId": p.ClientID, "secret": p.Secret, "ca": string(p.CA)}
	for k, v := range extra {
		body[k] = v
	}
	r := owner.api("POST", "methods/oidc", body)
	want(t, r, 200, "")
	id := r.json(t)["service"].(map[string]any)["id"].(string)
	p.Next(ownerAtService)
	if got := owner.testService(p, id); got != "/settings?signin=testOk" {
		t.Fatalf("test sign-in ended at %s", got)
	}
	return id
}

func serviceRole(t *testing.T, owner *browser, id string) string {
	t.Helper()
	var list struct {
		Services []struct{ ID, Role string } `json:"services"`
	}
	if err := json.Unmarshal(owner.api("GET", "methods/oidc", nil).Body, &list); err != nil {
		t.Fatal(err)
	}
	for _, s := range list.Services {
		if s.ID == id {
			return s.Role
		}
	}
	t.Fatalf("no service %s", id)
	return ""
}

func TestOpenRefusesAServiceRoleItDoesNotKnow(t *testing.T) {
	a := newApp(t)
	a.cfg = withOption(a.cfg, func(c *signin.Config) { manyAccounts(c); c.ServiceRole = "boss" })
	if _, err := signin.Open(a.cfg); err == nil {
		t.Fatal("Open took a service role that is not one of the roles")
	}
}

func TestANewcomerGetsTheRoleOfItsService(t *testing.T) {
	a := newApp(t, viewersByDefault)
	owner := a.owner()
	p := signintest.NewProvider(t)
	id := serviceWith(t, owner, p, nil)
	if got := serviceRole(t, owner, id); got != "viewer" {
		t.Fatalf("a service made without a role has %q", got)
	}
	p.Next(signintest.Person{Subject: "sub-anna", Name: "anna"})
	anna := a.browser()
	anna.serviceSignIn(p, id)
	if v := anna.visitor(); v.Role != "viewer" {
		t.Fatalf("anna came in as %+v", v)
	}
	want(t, setService(t, owner, id, map[string]any{"role": "admin"}), 200, "")
	p.Next(signintest.Person{Subject: "sub-ben", Name: "ben"})
	ben := a.browser()
	ben.serviceSignIn(p, id)
	if v := ben.visitor(); v.Role != "admin" {
		t.Fatalf("ben came in as %+v", v)
	}
	if v := anna.visitor(); v.Role != "viewer" {
		t.Fatalf("the service's new role changed anna to %+v", v)
	}
}

func TestAServiceTakesOnlyAKnownRole(t *testing.T) {
	a := newApp(t, viewersByDefault)
	owner := a.owner()
	p := signintest.NewProvider(t)
	want(t, owner.api("POST", "methods/oidc", map[string]any{"provider": "pocket-id", "issuer": p.URL, "clientId": "x", "secret": "y", "role": "boss"}), 400, "roleUnknown")
	id := serviceWith(t, owner, p, map[string]any{"role": "admin"})
	if got := serviceRole(t, owner, id); got != "admin" {
		t.Fatalf("the service's role is %q", got)
	}
	want(t, setService(t, owner, id, map[string]any{"role": "boss"}), 400, "roleUnknown")
}

func TestRolesNameTheServiceRole(t *testing.T) {
	a := newApp(t, viewersByDefault)
	if got := a.owner().api("GET", "roles", nil).json(t)["serviceRole"]; got != "viewer" {
		t.Fatalf("serviceRole = %v", got)
	}
	b := newApp(t, manyAccounts)
	if got := b.owner().api("GET", "roles", nil).json(t)["serviceRole"]; got != "admin" {
		t.Fatalf("serviceRole without one set = %v", got)
	}
}

func TestANewcomerFromTheConfigGetsTheServiceRole(t *testing.T) {
	p := signintest.NewProvider(t)
	a := newApp(t, viewersByDefault, closed, fromConfig(p, false))
	p.Next(signintest.Person{Subject: "sub-anna", Name: "anna"})
	b := a.browser()
	b.serviceSignIn(p, "config")
	if v := b.visitor(); v.Role != "viewer" {
		t.Fatalf("anna came in as %+v", v)
	}
}

func TestAStoredServiceWithoutARoleUsesTheServiceRole(t *testing.T) {
	a := newApp(t, viewersByDefault)
	owner := a.owner()
	p := signintest.NewProvider(t)
	id := serviceWith(t, owner, p, map[string]any{"role": "admin"})
	ctx := context.Background()
	raw, err := a.store.Get(ctx, "service", id)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	delete(doc, "role")
	raw, _ = json.Marshal(doc)
	if err := a.store.Apply(ctx, signin.Doc{Kind: "service", ID: id, Data: raw}); err != nil {
		t.Fatal(err)
	}
	if got := serviceRole(t, owner, id); got != "viewer" {
		t.Fatalf("a stored service without a role shows %q", got)
	}
	p.Next(signintest.Person{Subject: "sub-anna", Name: "anna"})
	b := a.browser()
	b.serviceSignIn(p, id)
	if v := b.visitor(); v.Role != "viewer" {
		t.Fatalf("anna came in as %+v", v)
	}
}

func TestAServiceKeepsTheRoleItWasMadeWith(t *testing.T) {
	a := newApp(t, viewersByDefault)
	owner := a.owner()
	id := serviceWith(t, owner, signintest.NewProvider(t), nil)
	a.cfg.ServiceRole = "admin"
	a.open()
	if got := serviceRole(t, a.signInWith("admin", ownerPassword), id); got != "viewer" {
		t.Fatalf("a new default changed the service's role to %q", got)
	}
}
