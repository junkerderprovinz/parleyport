package signin_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/signin"
	"github.com/junkerderprovinz/parleyport/kit/signin/signintest"
)

type offered struct{ ID, Provider, Name string }

func offeredServices(t *testing.T, a *app) []offered {
	t.Helper()
	var o struct{ Services []offered }
	if err := json.Unmarshal(a.browser().api("GET", "options", nil).Body, &o); err != nil {
		t.Fatal(err)
	}
	return o.Services
}

func listedServices(t *testing.T, owner *browser) []offered {
	t.Helper()
	var o struct{ Services []offered }
	if err := json.Unmarshal(owner.api("GET", "methods/oidc", nil).Body, &o); err != nil {
		t.Fatal(err)
	}
	return o.Services
}

func TestTheKitNamesNoServiceOfItsOwn(t *testing.T) {
	a := newApp(t)
	owner := a.owner()
	serviceWith(t, owner, signintest.NewProvider(t), map[string]any{"provider": "custom"})
	if got := offeredServices(t, a); len(got) != 1 || got[0].Name != "" {
		t.Fatalf("options name a service nobody named: %+v", got)
	}
	if got := listedServices(t, owner); len(got) != 1 || got[0].Name != "" {
		t.Fatalf("the list names a service nobody named: %+v", got)
	}

	p := signintest.NewProvider(t)
	b := newApp(t, fromConfig(p, false), func(c *signin.Config) { c.Services[0].Name = "" })
	b.owner()
	if got := offeredServices(t, b); len(got) != 1 || got[0].Name != "" {
		t.Fatalf("options name a service from the config nobody named: %+v", got)
	}
	c := newApp(t, fromConfig(signintest.NewProvider(t), false))
	c.owner()
	if got := offeredServices(t, c); len(got) != 1 || got[0].Name != "Company" {
		t.Fatalf("the name from the config is lost: %+v", got)
	}
}

func TestAServiceIsRecognisedFromItsDiscovery(t *testing.T) {
	for _, id := range []string{"pocket-id", "authentik", "authelia", "keycloak", "kanidm", "zitadel", ""} {
		t.Run(id, func(t *testing.T) {
			a := newApp(t)
			owner := a.owner()
			p := signintest.NewProvider(t)
			p.Like(id)
			serviceWith(t, owner, p, map[string]any{"provider": "custom"})
			want := id
			if want == "" {
				want = "custom"
			}
			if got := offeredServices(t, a); len(got) != 1 || got[0].Provider != want {
				t.Fatalf("options %+v, want provider %s", got, want)
			}
			if got := listedServices(t, owner); got[0].Provider != want {
				t.Fatalf("services %+v, want provider %s", got, want)
			}
		})
	}
}

func TestAnExplicitProviderIsNeverOverridden(t *testing.T) {
	a := newApp(t)
	owner := a.owner()
	p := signintest.NewProvider(t)
	p.Like("keycloak")
	serviceWith(t, owner, p, map[string]any{"provider": "authelia"})
	if got := offeredServices(t, a); got[0].Provider != "authelia" {
		t.Fatalf("options %+v", got)
	}
}

func TestAServiceFromTheConfigIsRecognisedAtTheStart(t *testing.T) {
	p := signintest.NewProvider(t)
	p.Like("pocket-id")
	a := newApp(t, closed, fromConfig(p, false), func(c *signin.Config) { c.Services[0].Provider = "" })
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := offeredServices(t, a)
		if len(got) == 1 && got[0].Provider == "pocket-id" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("options %+v, want the config service recognised as pocket-id", got)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestRecognitionFollowsTheIssuer(t *testing.T) {
	a := newApp(t)
	owner := a.owner()
	p := signintest.NewProvider(t)
	p.Like("keycloak")
	id := serviceWith(t, owner, p, map[string]any{"provider": "custom"})
	other := signintest.NewProvider(t)
	other.Like("zitadel")
	want(t, setService(t, owner, id, map[string]any{"issuer": other.URL, "clientId": other.ClientID, "secret": other.Secret, "ca": string(other.CA)}), 200, "")
	if got := listedServices(t, owner); got[0].Provider != "custom" {
		t.Fatalf("a new issuer kept the old recognition: %+v", got)
	}
	other.Next(ownerAtService)
	owner.testService(other, id)
	if got := listedServices(t, owner); got[0].Provider != "zitadel" {
		t.Fatalf("services %+v, want zitadel", got)
	}
}

type serviceFields struct {
	ID, Provider, Scopes, NameClaim, GroupsClaim string
}

func fieldsOf(t *testing.T, owner *browser) serviceFields {
	t.Helper()
	var o struct{ Services []serviceFields }
	if err := json.Unmarshal(owner.api("GET", "methods/oidc", nil).Body, &o); err != nil || len(o.Services) != 1 {
		t.Fatalf("services %+v %v", o, err)
	}
	return o.Services[0]
}

func TestAServiceNeedsOnlyIssuerClientAndSecret(t *testing.T) {
	a := newApp(t)
	owner := a.owner()
	p := signintest.NewProvider(t)
	r := owner.api("POST", "methods/oidc", map[string]any{"issuer": p.URL, "clientId": p.ClientID, "secret": p.Secret})
	want(t, r, 200, "")
	if got := fieldsOf(t, owner); got.Provider != "custom" || got.Scopes != "openid profile email" || got.NameClaim != "preferred_username" || got.GroupsClaim != "groups" {
		t.Fatalf("a service with only the essentials is %+v", got)
	}
}

func TestAServiceTakesTheClaimsOfItsPreset(t *testing.T) {
	a := newApp(t)
	owner := a.owner()
	serviceWith(t, owner, signintest.NewProvider(t), nil)
	if got := fieldsOf(t, owner); got.Scopes != "openid profile email groups" {
		t.Fatalf("a chosen pocket-id service is %+v", got)
	}

	b := newApp(t)
	admin := b.owner()
	p := signintest.NewProvider(t)
	p.Like("zitadel")
	serviceWith(t, admin, p, map[string]any{"provider": "custom"})
	got := fieldsOf(t, admin)
	if got.Provider != "zitadel" || got.GroupsClaim != "urn:zitadel:iam:org:project:roles" || !strings.Contains(got.Scopes, "urn:zitadel") {
		t.Fatalf("a service recognised as zitadel is %+v", got)
	}
}

func TestAClaimGivenForAServiceWins(t *testing.T) {
	a := newApp(t)
	owner := a.owner()
	p := signintest.NewProvider(t)
	p.Like("zitadel")
	id := serviceWith(t, owner, p, map[string]any{"provider": "custom", "groupsClaim": "teams", "scopes": "openid teams"})
	if got := fieldsOf(t, owner); got.GroupsClaim != "teams" || got.Scopes != "openid teams" {
		t.Fatalf("the given claim and scopes were replaced: %+v", got)
	}
	want(t, setService(t, owner, id, map[string]any{"groupsClaim": "", "scopes": ""}), 200, "")
	if got := fieldsOf(t, owner); got.GroupsClaim != "urn:zitadel:iam:org:project:roles" {
		t.Fatalf("an emptied claim did not go back to the preset's: %+v", got)
	}
}
