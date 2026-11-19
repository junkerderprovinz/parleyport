package signin_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/signin"
	"github.com/junkerderprovinz/parleyport/kit/signin/signintest"
)

var ownerAtService = signintest.Person{Subject: "sub-owner", Name: "owner-at-service", Groups: []string{"admins"}}

// via goes from a browser route of the app to the provider and back, as a
// browser does, and returns where the app sends it in the end.
func (b *browser) via(p *signintest.Provider, path string) string {
	b.t.Helper()
	r := b.do("GET", path, nil)
	if r.Status != http.StatusFound {
		b.t.Fatalf("start %s: %d %s", path, r.Status, r.Body)
	}
	to := r.Header.Get("Location")
	if !strings.HasPrefix(to, p.URL) {
		return to
	}
	res, err := p.Client().Get(to)
	if err != nil {
		b.t.Fatal(err)
	}
	_ = res.Body.Close()
	back, _ := url.Parse(res.Header.Get("Location"))
	app := mustURL(b.a)
	back.Host = app.Host
	r = b.do("GET", back.RequestURI(), nil)
	if r.Status != http.StatusFound {
		b.t.Fatalf("callback: %d %s", r.Status, r.Body)
	}
	return r.Header.Get("Location")
}

// addService adds a sign-in service with preset and passes its test sign-in
// as the owner, which turns it on.
func addService(t *testing.T, a *app, owner *browser, preset string) (*signintest.Provider, string) {
	t.Helper()
	p := signintest.NewProvider(t)
	r := owner.api("POST", "methods/oidc", map[string]any{
		"provider": preset, "issuer": p.URL, "clientId": p.ClientID, "secret": p.Secret, "ca": string(p.CA),
	})
	want(t, r, 200, "")
	id := r.json(t)["service"].(map[string]any)["id"].(string)
	p.Next(ownerAtService)
	if got := owner.testService(p, id); got != "/settings?signin=testOk" {
		t.Fatalf("test sign-in ended at %s", got)
	}
	return p, id
}

func (b *browser) testService(p *signintest.Provider, id string) string {
	b.t.Helper()
	r := b.api("POST", "methods/oidc/"+id+"/test", map[string]string{"return": "/settings"})
	want(b.t, r, 200, "")
	return b.via(p, r.json(b.t)["url"].(string))
}

func (b *browser) serviceSignIn(p *signintest.Provider, id string) string {
	b.t.Helper()
	return b.via(p, "/signin/oidc/"+id+"?return=/home")
}

func setService(t *testing.T, b *browser, id string, patch map[string]any) reply {
	t.Helper()
	return b.api("PATCH", "methods/oidc/"+id, patch)
}

func TestTheTestSignInTurnsTheServiceOnAndBindsTheOwner(t *testing.T) {
	a := newApp(t)
	owner := a.owner()
	p, id := addService(t, a, owner, "pocket-id")
	opts := a.browser().api("GET", "options", nil).json(t)
	svcs := opts["services"].([]any)
	if len(svcs) != 1 || svcs[0].(map[string]any)["provider"] != "pocket-id" {
		t.Fatalf("options services %v", svcs)
	}
	b := a.browser()
	p.Next(ownerAtService)
	if got := b.serviceSignIn(p, id); got != "/home" {
		t.Fatalf("sign-in ended at %s", got)
	}
	v := b.visitor()
	if v.Via != signin.ViaService || v.Account != owner.visitor().Account || v.Service != id {
		t.Fatalf("visitor %+v", v)
	}
}

func TestServicesWaitForAPassword(t *testing.T) {
	a := newApp(t)
	want(t, a.browser().api("POST", "methods/oidc", map[string]any{"provider": "pocket-id", "issuer": "https://id.example", "clientId": "x", "secret": "y"}), 409, "setPasswordFirst")
}

func TestTheSecretNeverComesBack(t *testing.T) {
	a := newApp(t)
	owner := a.owner()
	p, _ := addService(t, a, owner, "pocket-id")
	list := owner.api("GET", "methods/oidc", nil)
	if strings.Contains(string(list.Body), p.Secret) || !strings.Contains(string(list.Body), `"secretSet":true`) {
		t.Fatalf("list %s", list.Body)
	}
}

func TestAStrangerWithoutAnAccountStaysOut(t *testing.T) {
	a := newApp(t)
	p, id := addService(t, a, a.owner(), "pocket-id")
	p.Next(signintest.Person{Subject: "sub-x", Name: "stranger", Groups: []string{"admins"}})
	if got := a.browser().serviceSignIn(p, id); got != "/home?signin=noAccount" {
		t.Fatalf("ended at %s", got)
	}
}

func TestAccountsOnFirstSignInNeedAGroupForTheAdmin(t *testing.T) {
	a := newApp(t)
	owner := a.owner()
	p, id := addService(t, a, owner, "authentik")
	want(t, setService(t, owner, id, map[string]any{"createOnFirst": true}), 400, "groupsMissing")
	want(t, setService(t, owner, id, map[string]any{"createOnFirst": true, "everyone": true}), 400, "everyoneWouldBeAdmin")
	want(t, setService(t, owner, id, map[string]any{"createOnFirst": true, "groups": []map[string]string{{"group": "family", "role": "admin"}}}), 200, "")

	p.Next(signintest.Person{Subject: "sub-anna", Name: "anna", Groups: []string{"family"}})
	anna := a.browser()
	if got := anna.serviceSignIn(p, id); got != "/home" {
		t.Fatalf("anna ended at %s", got)
	}
	if v := anna.visitor(); v.Name != "anna" || v.Role != "admin" || v.Via != signin.ViaService {
		t.Fatalf("anna is %+v", v)
	}
	p.Next(signintest.Person{Subject: "sub-ben", Name: "ben", Groups: []string{"neighbours"}})
	if got := a.browser().serviceSignIn(p, id); got != "/home?signin=noGroup" {
		t.Fatalf("ben ended at %s", got)
	}
}

func TestATakenNameIsNeverMerged(t *testing.T) {
	a := newApp(t, manyAccounts)
	owner := a.owner()
	addAccount(t, owner, "anna", "admin")
	p, id := addService(t, a, owner, "pocket-id")
	setService(t, owner, id, map[string]any{"createOnFirst": true, "groups": []map[string]string{{"group": "family", "role": "admin"}}})
	p.Next(signintest.Person{Subject: "sub-other-anna", Name: "Anna", Groups: []string{"family"}})
	b := a.browser()
	if got := b.serviceSignIn(p, id); got != "/home?signin=nameTaken" {
		t.Fatalf("ended at %s", got)
	}
	if b.visitor().Via != "" {
		t.Fatal("signed in as the local anna")
	}
}

func TestTheBindingGoesBySubjectNotName(t *testing.T) {
	a := newApp(t)
	owner := a.owner()
	p, id := addService(t, a, owner, "pocket-id")
	renamed := ownerAtService
	renamed.Name = "new name at the service"
	p.Next(renamed)
	b := a.browser()
	b.serviceSignIn(p, id)
	if b.visitor().Account != owner.visitor().Account {
		t.Fatal("a rename at the service lost the binding")
	}
}

func TestNewAccountsAreCappedPerHour(t *testing.T) {
	a := newApp(t)
	owner := a.owner()
	p, id := addService(t, a, owner, "pocket-id")
	setService(t, owner, id, map[string]any{"createOnFirst": true, "groups": []map[string]string{{"group": "family", "role": "admin"}}})
	for i := range 10 {
		p.Next(signintest.Person{Subject: "sub-" + string(rune('a'+i)), Name: "person " + string(rune('a'+i)), Groups: []string{"family"}})
		if got := a.browser().serviceSignIn(p, id); got != "/home" {
			t.Fatalf("person %d ended at %s", i, got)
		}
	}
	p.Next(signintest.Person{Subject: "sub-z", Name: "person z", Groups: []string{"family"}})
	if got := a.browser().serviceSignIn(p, id); got != "/home?signin=throttled" {
		t.Fatalf("the eleventh ended at %s", got)
	}
}

func TestAnEmailCountsAsNameOnlyWhenVerified(t *testing.T) {
	a := newApp(t)
	owner := a.owner()
	p, id := addService(t, a, owner, "custom")
	setService(t, owner, id, map[string]any{"nameClaim": "email", "createOnFirst": true, "groups": []map[string]string{{"group": "family", "role": "admin"}}})
	p.Next(signintest.Person{Subject: "sub-m", Name: "m", Email: "m@example.org", Groups: []string{"family"}})
	if got := a.browser().serviceSignIn(p, id); got != "/home?signin=nameMissing" {
		t.Fatalf("an unverified email ended at %s", got)
	}
	p.Next(signintest.Person{Subject: "sub-m", Name: "m", Email: "m@example.org", EmailVerified: true, Groups: []string{"family"}})
	b := a.browser()
	b.serviceSignIn(p, id)
	if v := b.visitor(); v.Name != "m@example.org" {
		t.Fatalf("visitor %+v", v)
	}
}

func TestTheCallbackRefusesWhatItDidNotAskFor(t *testing.T) {
	tests := []struct {
		name  string
		spoil func(p *signintest.Provider)
		ends  string
	}{
		{"an ID token for another client", func(p *signintest.Provider) {
			p.Tamper(func(c map[string]any) { c["aud"] = "someone else" })
		}, "serviceRefused"},
		{"an ID token for another sign-in", func(p *signintest.Provider) {
			p.Tamper(func(c map[string]any) { c["nonce"] = "other" })
		}, "serviceRefused"},
		{"an ID token from another issuer", func(p *signintest.Provider) {
			p.Tamper(func(c map[string]any) { c["iss"] = "https://evil.example" })
		}, "serviceRefused"},
		{"an ID token with a foreign signature", func(p *signintest.Provider) { p.SignWithAnotherKey() }, "serviceRefused"},
		{"a redirect naming another issuer", func(p *signintest.Provider) { p.SendIssuer("https://evil.example") }, "serviceRefused"},
		{"groups for another subject", func(p *signintest.Provider) {
			p.GroupsOnlyInUserInfo(&signintest.Person{Subject: "sub-other", Groups: []string{"admins"}})
		}, "noGroup"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newApp(t)
			owner := a.owner()
			p, id := addService(t, a, owner, "pocket-id")
			setService(t, owner, id, map[string]any{"groups": []map[string]string{{"group": "admins", "role": "admin"}}})
			adminAnna := signintest.Person{Subject: "sub-anna", Name: "anna", Groups: []string{"admins"}}
			setService(t, owner, id, map[string]any{"createOnFirst": true})
			tt.spoil(p)
			p.Next(adminAnna)
			b := a.browser()
			if got := b.serviceSignIn(p, id); got != "/home?signin="+tt.ends {
				t.Fatalf("ended at %s", got)
			}
			if b.visitor().Via != "" {
				t.Fatal("signed in anyway")
			}
		})
	}
}

func TestGroupsFromUserInfoOfTheSameSubjectCount(t *testing.T) {
	a := newApp(t)
	owner := a.owner()
	p, id := addService(t, a, owner, "pocket-id")
	setService(t, owner, id, map[string]any{"createOnFirst": true, "groups": []map[string]string{{"group": "admins", "role": "admin"}}})
	p.GroupsOnlyInUserInfo(nil)
	p.Next(signintest.Person{Subject: "sub-anna", Name: "anna", Groups: []string{"admins"}})
	if got := a.browser().serviceSignIn(p, id); got != "/home" {
		t.Fatalf("ended at %s", got)
	}
}

func TestACallbackWithoutTheFlowCookieIsRefused(t *testing.T) {
	a := newApp(t)
	p, id := addService(t, a, a.owner(), "pocket-id")
	start := a.browser().do("GET", "/signin/oidc/"+id, nil)
	res, err := p.Client().Get(start.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	back, _ := url.Parse(res.Header.Get("Location"))
	back.Host = mustURL(a).Host
	other := a.browser()
	r := other.do("GET", back.RequestURI(), nil)
	if got := r.Header.Get("Location"); got != "/?signin=flowExpired" || other.visitor().Via != "" {
		t.Fatalf("a callback in another browser ended at %q", got)
	}
}

func TestTheWayBackStaysOnTheApp(t *testing.T) {
	a := newApp(t)
	p, id := addService(t, a, a.owner(), "pocket-id")
	for _, ret := range []string{"https://evil.example/x", "//evil.example/x", "/\\evil.example", "javascript:alert(1)"} {
		p.Next(ownerAtService)
		if got := a.browser().via(p, "/signin/oidc/"+id+"?return="+url.QueryEscape(ret)); got != "/" {
			t.Errorf("return %q ended at %s", ret, got)
		}
	}
}

func TestAServiceSessionNeedsTheServiceAgainAfterADay(t *testing.T) {
	a := newApp(t)
	p, id := addService(t, a, a.owner(), "pocket-id")
	b := a.browser()
	p.Next(ownerAtService)
	b.serviceSignIn(p, id)
	a.clock.Add(25 * time.Hour)
	if b.visitor().Via != "" {
		t.Fatal("a day-old service session still counts")
	}
	opts := b.api("GET", "options", nil).json(t)
	if opts["renew"] != id {
		t.Fatalf("options %v", opts)
	}
	if got := b.via(p, "/signin/oidc/"+id+"?renew=1&return=/home"); got != "/home" {
		t.Fatalf("renewal ended at %s", got)
	}
	if b.visitor().Via != signin.ViaService {
		t.Fatal("the renewal did not bring the session back")
	}
	a.clock.Add(25 * time.Hour)
	p.SignOut()
	if got := b.via(p, "/signin/oidc/"+id+"?renew=1&return=/home"); got != "/home?signin=renewNeeded" {
		t.Fatalf("a failed renewal ended at %s", got)
	}
}

func TestLeavingTheGroupEndsSessionsAndTokens(t *testing.T) {
	a := newApp(t)
	owner := a.owner()
	p, id := addService(t, a, owner, "pocket-id")
	setService(t, owner, id, map[string]any{"createOnFirst": true, "groups": []map[string]string{{"group": "family", "role": "admin"}}})
	anna := signintest.Person{Subject: "sub-anna", Name: "anna", Groups: []string{"family"}}
	p.Next(anna)
	b := a.browser()
	b.serviceSignIn(p, id)
	want(t, b.api("POST", "me/tokens", map[string]any{"name": "script", "scopes": []string{"read"}}), 200, "")
	other := a.browser()
	p.Next(anna)
	other.serviceSignIn(p, id)

	anna.Groups = nil
	p.Next(anna)
	if got := a.browser().serviceSignIn(p, id); got != "/home?signin=noGroup" {
		t.Fatalf("ended at %s", got)
	}
	if b.visitor().Via != "" || other.visitor().Via != "" {
		t.Fatal("a session outlived leaving the group")
	}
}

func TestTokensOfAServiceAccountRestWithoutTheService(t *testing.T) {
	a := newApp(t)
	owner := a.owner()
	p, id := addService(t, a, owner, "pocket-id")
	setService(t, owner, id, map[string]any{"createOnFirst": true, "groups": []map[string]string{{"group": "family", "role": "admin"}}})
	p.Next(signintest.Person{Subject: "sub-anna", Name: "anna", Groups: []string{"family"}})
	b := a.browser()
	b.serviceSignIn(p, id)
	r := b.api("POST", "me/tokens", map[string]any{"name": "script", "scopes": []string{"read"}})
	want(t, r, 200, "")
	script := a.browser()
	script.header.Set("Authorization", "Bearer "+r.json(t)["value"].(string))
	if script.visitor().Via != signin.ViaToken {
		t.Fatal("the token does not work")
	}
	a.clock.Add(26 * time.Hour)
	if script.visitor().Via != "" {
		t.Fatal("the token works a day after the service last let anna in")
	}
}

func TestChangingTheIssuerWantsTheSecretAndATestAgain(t *testing.T) {
	a := newApp(t)
	owner := a.owner()
	p, id := addService(t, a, owner, "pocket-id")
	want(t, setService(t, owner, id, map[string]any{"issuer": "https://other.example"}), 400, "secretAgain")
	want(t, setService(t, owner, id, map[string]any{"issuer": p.URL + "/", "secret": "new secret"}), 200, "")
	list := owner.api("GET", "methods/oidc", nil)
	if !strings.Contains(string(list.Body), `"on":false`) {
		t.Fatalf("still on after the issuer changed: %s", list.Body)
	}
	want(t, setService(t, owner, id, map[string]any{"on": true}), 409, "serviceUntested")
}

func TestTheResetPausesEveryService(t *testing.T) {
	log := &logBuffer{}
	a := newApp(t, withLog(log))
	addService(t, a, a.owner(), "pocket-id")
	code := resetCode(t, a, log)
	r := a.browser().api("POST", "reset", map[string]string{"code": code, "password": "a brand new password"})
	want(t, r, 200, "")
	if paused := r.json(t)["removed"].(map[string]any)["services"]; paused != float64(1) {
		t.Fatalf("services paused %v", paused)
	}
	if svcs := a.browser().api("GET", "options", nil).json(t)["services"].([]any); len(svcs) != 0 {
		t.Fatalf("a sign-in service is still offered: %v", svcs)
	}
}

func TestAnUnreachableServiceSaysSo(t *testing.T) {
	a := newApp(t)
	owner := a.owner()
	r := owner.api("POST", "methods/oidc", map[string]any{"provider": "pocket-id", "issuer": "https://127.0.0.1:1", "clientId": "x", "secret": "y"})
	want(t, r, 200, "")
	id := r.json(t)["service"].(map[string]any)["id"].(string)
	want(t, owner.api("POST", "methods/oidc/"+id+"/check", map[string]any{}), 502, "serviceUnreachable")
}

func TestPresetsShareTheCatalogsIDs(t *testing.T) {
	a := newApp(t)
	r := a.owner().api("GET", "methods/presets", nil)
	var got struct {
		Presets []struct {
			ID          string `json:"id"`
			GroupsClaim string `json:"groupsClaim"`
		} `json:"presets"`
	}
	if err := json.Unmarshal(r.Body, &got); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, p := range got.Presets {
		ids = append(ids, p.ID)
	}
	if strings.Join(ids, " ") != "pocket-id authentik authelia keycloak kanidm zitadel custom" {
		t.Fatalf("presets %v", ids)
	}
}
