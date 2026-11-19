package signin_test

import (
	"strings"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/signin"
)

func manyAccounts(c *signin.Config) {
	c.Owner = false
	c.Roles = []string{"admin", "viewer"}
}

func addAccount(t *testing.T, owner *browser, name, role string) string {
	t.Helper()
	r := owner.api("POST", "accounts", map[string]string{"name": name, "password": "password of " + name, "role": role})
	want(t, r, 200, "")
	return r.json(t)["account"].(map[string]any)["id"].(string)
}

func (a *app) signInAs(name string) *browser {
	a.t.Helper()
	b := a.browser()
	want(a.t, b.api("POST", "login", map[string]string{"name": name, "password": "password of " + name}), 200, "")
	return b
}

func TestAdminsAddAccountsWithAPassword(t *testing.T) {
	a := newApp(t, manyAccounts)
	owner := a.owner()
	addAccount(t, owner, "anna", "viewer")
	want(t, owner.api("POST", "accounts", map[string]string{"name": "ANNA", "password": "another password", "role": "admin"}), 409, "nameTaken")
	want(t, owner.api("POST", "accounts", map[string]string{"name": "ben", "password": "another password", "role": "boss"}), 400, "roleUnknown")
	anna := a.signInAs("anna")
	if v := anna.visitor(); v.Name != "anna" || v.Role != "viewer" {
		t.Fatalf("anna is %+v", v)
	}
	list := owner.api("GET", "accounts", nil)
	if n := strings.Count(string(list.Body), `"id"`); n != 2 {
		t.Fatalf("%d accounts: %s", n, list.Body)
	}
}

func TestAnAppWithOneOwnerAddsNoLocalAccounts(t *testing.T) {
	a := newApp(t)
	owner := a.owner()
	want(t, owner.api("POST", "accounts", map[string]string{"name": "anna", "password": "password of anna", "role": "admin"}), 409, "oneOwner")
}

func TestOnlyAdminsManageAccounts(t *testing.T) {
	a := newApp(t, manyAccounts)
	owner := a.owner()
	addAccount(t, owner, "anna", "viewer")
	anna := a.signInAs("anna")
	want(t, anna.api("GET", "accounts", nil), 403, "forbidden")
	want(t, anna.api("GET", "log", nil), 403, "forbidden")
}

func TestBlockingEndsTheAccountsWaysIn(t *testing.T) {
	a := newApp(t, manyAccounts)
	owner := a.owner()
	id := addAccount(t, owner, "anna", "admin")
	anna := a.signInAs("anna")
	want(t, owner.api("PATCH", "accounts/"+id, map[string]any{"blocked": true}), 200, "")
	if anna.visitor().Via != "" {
		t.Fatal("a blocked account is still signed in")
	}
	want(t, a.browser().api("POST", "login", map[string]string{"name": "anna", "password": "password of anna"}), 403, "blocked")
	if got := strings.Join(a.endedWith(), " "); !strings.Contains(got, id+":blocked") {
		t.Fatalf("Ended = %s", got)
	}
	want(t, owner.api("PATCH", "accounts/"+id, map[string]any{"blocked": false}), 200, "")
	a.signInAs("anna")
}

func TestALowerRoleEndsTheSessions(t *testing.T) {
	a := newApp(t, manyAccounts)
	owner := a.owner()
	id := addAccount(t, owner, "anna", "admin")
	anna := a.signInAs("anna")
	want(t, owner.api("PATCH", "accounts/"+id, map[string]any{"role": "viewer"}), 200, "")
	if anna.visitor().Via != "" {
		t.Fatal("a session kept the higher role")
	}
}

func TestTheOwnerStaysAsTheWayOut(t *testing.T) {
	a := newApp(t, manyAccounts)
	owner := a.owner()
	me := owner.visitor()
	want(t, owner.api("PATCH", "accounts/"+me.Account, map[string]any{"blocked": true}), 403, "accountOwner")
	want(t, owner.api("PATCH", "accounts/"+me.Account, map[string]any{"role": "viewer"}), 403, "accountOwner")
	want(t, owner.api("DELETE", "accounts/"+me.Account, nil), 403, "accountOwner")
}

func TestRemovingAnAccount(t *testing.T) {
	a := newApp(t, manyAccounts)
	owner := a.owner()
	id := addAccount(t, owner, "anna", "admin")
	anna := a.signInAs("anna")
	want(t, owner.api("DELETE", "accounts/"+id, nil), 200, "")
	if anna.visitor().Via != "" {
		t.Fatal("a removed account is still signed in")
	}
	want(t, a.browser().api("POST", "login", map[string]string{"name": "anna", "password": "password of anna"}), 401, "wrongPassword")
	if got := strings.Join(a.endedWith(), " "); !strings.Contains(got, id+":removed") {
		t.Fatalf("Ended = %s", got)
	}
}

func TestRolesListsTheAppsRoles(t *testing.T) {
	a := newApp(t, manyAccounts)
	r := a.owner().api("GET", "roles", nil)
	if got := r.json(t)["roles"]; len(got.([]any)) != 2 {
		t.Fatalf("roles %v", got)
	}
}
