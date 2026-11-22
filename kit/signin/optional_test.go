package signin_test

import (
	"context"
	"strings"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/signin"
)

func TestAPasswordOfAnyLengthIsTaken(t *testing.T) {
	a := newApp(t)
	b := a.browser()
	want(t, b.api("PUT", "me/password", map[string]string{"next": ""}), 400, "passwordMissing")
	want(t, b.api("PUT", "me/password", map[string]string{"next": strings.Repeat("x", 1025)}), 400, "passwordLong")
	r := b.api("PUT", "me/password", map[string]string{"next": "abc"})
	want(t, r, 200, "")
	if r.json(t)["short"] != true {
		t.Fatalf("a password under the minimum gives no hint: %s", r.Body)
	}
	want(t, a.browser().api("POST", "login", map[string]string{"password": "abc"}), 200, "")
	r = b.api("PUT", "me/password", map[string]string{"current": "abc", "next": ownerPassword})
	want(t, r, 200, "")
	if r.json(t)["short"] == true {
		t.Fatalf("a long password is called short: %s", r.Body)
	}
}

func TestAShortPasswordIsTakenForEveryAccount(t *testing.T) {
	log := &logBuffer{}
	a := newApp(t, manyAccounts, withLog(log))
	owner := a.owner()
	r := owner.api("POST", "accounts", map[string]string{"name": "anna", "password": "pw", "role": "viewer"})
	want(t, r, 200, "")
	if r.json(t)["short"] != true {
		t.Fatalf("a short password for a new account gives no hint: %s", r.Body)
	}
	a.signInWith("anna", "pw")
	code := resetCode(t, a, log)
	r = a.browser().api("POST", "reset", map[string]string{"code": code, "name": "anna", "password": "x"})
	want(t, r, 200, "")
	if r.json(t)["short"] != true {
		t.Fatalf("a short password from a reset gives no hint: %s", r.Body)
	}
	if err := a.auth.SetPassword(a.signInWith("admin", ownerPassword).requestTo("/app"), r.json(t)["visitor"].(map[string]any)["account"].(string), "y"); err != nil {
		t.Fatalf("SetPassword refused a short password: %v", err)
	}
}

// openWithAccounts is an open app with many accounts that came from
// outside and have no password.
func openWithAccounts(t *testing.T, ch *changes) *app {
	t.Helper()
	return newApp(t, manyAccounts, ch.option, func(c *signin.Config) {
		c.Import = func(context.Context) ([]signin.Imported, error) {
			return []signin.Imported{{ID: "8", Name: "anna", Role: "admin", Identities: []signin.ImportedIdentity{{Issuer: "https://id.example", Subject: "s", Name: "anna"}}}}, nil
		}
	})
}

func TestAnOpenAppManagesItsAccounts(t *testing.T) {
	ch := &changes{}
	a := openWithAccounts(t, ch)
	if !a.auth.Anyone() {
		t.Fatal("the app is not open")
	}
	b := a.browser()
	want(t, b.api("PATCH", "accounts/8", map[string]any{"name": "anna b", "role": "viewer", "blocked": true}), 200, "")
	want(t, b.api("PATCH", "settings", map[string]bool{"askPassword": false}), 200, "")
	r := b.requestTo("/app")
	if err := a.auth.SetBlocked(r, "8", false); err != nil {
		t.Fatalf("SetBlocked in an open app: %v", err)
	}
	if _, err := a.auth.Sessions(r, "8"); err != nil {
		t.Fatalf("Sessions in an open app: %v", err)
	}
	if got := strings.Join(ch.kinds(), " "); got != "rename:anna b role:anna b block:anna b block:anna b" {
		t.Fatalf("Changing heard %s", got)
	}
	want(t, b.api("DELETE", "accounts/8", nil), 200, "")
	want(t, b.api("POST", "accounts", map[string]string{"name": "ben", "password": "password of ben", "role": "viewer"}), 409, "setPasswordFirst")
	_, err := a.auth.CreateAccount(r, "ben", "password of ben", "viewer")
	refusal(t, err, "setPasswordFirst")
}

func TestADoorChangesNoAccount(t *testing.T) {
	var account string
	a := newApp(t, manyAccounts, phoneDoor(&account))
	owner := a.owner()
	account = addAccount(t, owner, "anna", "admin")
	phone := a.browser()
	phone.header.Set("X-Phone", "paired")
	want(t, phone.api("PATCH", "accounts/"+account, map[string]any{"name": "phone"}), 403, "forbidden")
	want(t, phone.api("PATCH", "settings", map[string]bool{"askPassword": false}), 403, "forbidden")
}
