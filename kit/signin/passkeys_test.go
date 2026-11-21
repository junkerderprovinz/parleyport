package signin_test

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/signin"
	"github.com/junkerderprovinz/parleyport/kit/signin/signintest"
)

func (a *app) authenticator() *signintest.Authenticator {
	return signintest.NewAuthenticator(a.cfg.Public().Scheme + "://" + a.cfg.Public().Host)
}

// addPasskey registers a passkey for b's account through the contract.
func addPasskey(t *testing.T, b *browser, key *signintest.Authenticator) {
	t.Helper()
	r := b.api("POST", "me/passkeys/options", map[string]any{})
	want(t, r, 200, "")
	cred, err := key.Create(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	want(t, b.api("POST", "me/passkeys", map[string]any{"name": "laptop", "credential": json.RawMessage(cred)}), 200, "")
}

// passkeySignIn runs the conditional sign-in in b and returns the answer.
func passkeySignIn(t *testing.T, b *browser, key *signintest.Authenticator) reply {
	t.Helper()
	r := b.api("POST", "login/passkey/options", map[string]any{})
	want(t, r, 200, "")
	assertion, err := key.Get(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b.api("POST", "login/passkey", json.RawMessage(assertion))
}

func TestAPasskeySignsInFromThePasswordField(t *testing.T) {
	a := newApp(t)
	key := a.authenticator()
	owner := a.owner()
	twoFactor(t, a, owner)
	addPasskey(t, owner, key)

	b := a.browser()
	r := b.api("POST", "login/passkey/options", map[string]any{})
	want(t, r, 200, "")
	var opts struct {
		Mediation string `json:"mediation"`
		PublicKey struct {
			RPID             string `json:"rpId"`
			UserVerification string `json:"userVerification"`
			Allow            []any  `json:"allowCredentials"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(r.Body, &opts); err != nil {
		t.Fatal(err)
	}
	if opts.Mediation != "conditional" || opts.PublicKey.UserVerification != "required" || len(opts.PublicKey.Allow) != 0 || opts.PublicKey.RPID != "localhost" {
		t.Fatalf("options %s", r.Body)
	}
	assertion, _ := key.Get(r.Body)
	want(t, b.api("POST", "login/passkey", json.RawMessage(assertion)), 200, "")
	if v := b.visitor(); v.Via != signin.ViaPasskey || v.Name != owner.visitor().Name {
		t.Fatalf("visitor %+v", v)
	}
	if a.browser().api("GET", "options", nil, "Host", a.cfg.Public().Host).json(t)["passkeys"] != true {
		t.Fatal("options does not offer passkeys")
	}
}

func TestAPasskeyChallengeCountsOnce(t *testing.T) {
	a := newApp(t)
	key := a.authenticator()
	addPasskey(t, a.owner(), key)
	b := a.browser()
	r := b.api("POST", "login/passkey/options", map[string]any{})
	assertion, _ := key.Get(r.Body)
	want(t, b.api("POST", "login/passkey", json.RawMessage(assertion)), 200, "")
	b.api("POST", "logout", nil)
	again, _ := key.Get(r.Body)
	want(t, b.api("POST", "login/passkey", json.RawMessage(again)), 401, "passkeyRefused")
}

func TestAPasskeyChallengeEndsAfterFiveMinutes(t *testing.T) {
	a := newApp(t)
	key := a.authenticator()
	addPasskey(t, a.owner(), key)
	b := a.browser()
	r := b.api("POST", "login/passkey/options", map[string]any{})
	assertion, _ := key.Get(r.Body)
	a.clock.Add(6 * time.Minute)
	want(t, b.api("POST", "login/passkey", json.RawMessage(assertion)), 401, "passkeyRefused")
}

func TestAPasskeyWithoutUserVerificationIsRefused(t *testing.T) {
	a := newApp(t)
	key := a.authenticator()
	addPasskey(t, a.owner(), key)
	key.SkipVerification = true
	want(t, passkeySignIn(t, a.browser(), key), 401, "passkeyRefused")
}

func TestAPasskeyFromAnotherOriginIsRefused(t *testing.T) {
	a := newApp(t)
	key := a.authenticator()
	addPasskey(t, a.owner(), key)
	key.Origin = "https://evil.example"
	want(t, passkeySignIn(t, a.browser(), key), 401, "passkeyRefused")
}

func TestAnUnknownPasskeyIsRefused(t *testing.T) {
	a := newApp(t)
	addPasskey(t, a.owner(), a.authenticator())
	stranger := a.authenticator()
	if _, err := stranger.Passkey("localhost", []byte("someone else")); err != nil {
		t.Fatal(err)
	}
	want(t, passkeySignIn(t, a.browser(), stranger), 401, "passkeyUnknown")
}

func TestPasskeysWantADomainName(t *testing.T) {
	a := newApp(t)
	ip, _ := url.Parse("https://192.168.20.41")
	a.cfg.Public = func() *url.URL { return ip }
	a.open()
	owner := a.owner()
	want(t, owner.api("POST", "me/passkeys/options", map[string]any{}), 409, "passkeysUnavailable")
	want(t, a.browser().api("POST", "login/passkey/options", map[string]any{}), 409, "passkeysUnavailable")
}

func TestEachAccountGetsItsOwnRandomHandle(t *testing.T) {
	a := newApp(t, manyAccounts)
	owner := a.owner()
	addAccount(t, owner, "anna", "admin")
	anna := a.signInAs("anna")
	handle := func(b *browser) string {
		var o struct {
			PublicKey struct {
				User struct {
					ID string `json:"id"`
				} `json:"user"`
			} `json:"publicKey"`
		}
		if err := json.Unmarshal(b.api("POST", "me/passkeys/options", map[string]any{}).Body, &o); err != nil {
			t.Fatal(err)
		}
		return o.PublicKey.User.ID
	}
	h1, h2 := handle(owner), handle(anna)
	raw, _ := base64.RawURLEncoding.DecodeString(h1)
	if len(raw) != 32 || h1 == h2 {
		t.Fatalf("handles %q and %q", h1, h2)
	}
	if again := handle(owner); again != h1 {
		t.Fatal("the handle changed between two registrations")
	}
}

func TestAddingAPasskeyWantsAFreshSignIn(t *testing.T) {
	a := newApp(t)
	owner := a.owner()
	a.clock.Add(11 * time.Minute)
	want(t, owner.api("POST", "me/passkeys/options", map[string]any{}), 403, "signInAgain")
}

func TestRenamingAndRemovingPasskeys(t *testing.T) {
	a := newApp(t)
	key := a.authenticator()
	owner := a.owner()
	addPasskey(t, owner, key)
	list := owner.api("GET", "me/passkeys", nil)
	var got struct {
		Passkeys []struct{ ID, Name string } `json:"passkeys"`
	}
	if err := json.Unmarshal(list.Body, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Passkeys) != 1 || got.Passkeys[0].Name != "laptop" {
		t.Fatalf("passkeys %s", list.Body)
	}
	id := got.Passkeys[0].ID
	want(t, owner.api("PATCH", "me/passkeys/"+id, map[string]string{"name": "desk"}), 200, "")
	if !strings.Contains(string(owner.api("GET", "me/passkeys", nil).Body), `"desk"`) {
		t.Fatal("the name did not change")
	}
	want(t, owner.api("DELETE", "me/passkeys/"+id, nil), 200, "")
	want(t, passkeySignIn(t, a.browser(), key), 401, "passkeyUnknown")
}

func TestTheResetRemovesThePasskeys(t *testing.T) {
	log := &logBuffer{}
	a := newApp(t, withLog(log))
	key := a.authenticator()
	addPasskey(t, a.owner(), key)
	code := resetCode(t, a, log)
	r := a.browser().api("POST", "reset", map[string]string{"code": code, "password": "a brand new password"})
	if r.json(t)["removed"].(map[string]any)["passkeys"] != float64(1) {
		t.Fatalf("reset %s", r.Body)
	}
	want(t, passkeySignIn(t, a.browser(), key), 401, "passkeyUnknown")
}

func TestAnImportedPasskeyKeepsItsHandle(t *testing.T) {
	key := signintest.NewAuthenticator("")
	handle := []byte("handle the old app derived")
	pk, err := key.Passkey("localhost", handle)
	if err != nil {
		t.Fatal(err)
	}
	owner := oldOwner()
	owner.Handle, owner.Passkeys = handle, []signin.ImportedPasskey{pk}
	a := newApp(t, (&oldApp{}).option(owner))
	key.Origin = a.authenticator().Origin
	want(t, passkeySignIn(t, a.browser(), key), 200, "")
}
