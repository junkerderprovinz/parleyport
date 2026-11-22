package signin_test

import (
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/signin/signintest"
)

func TestTheAppAsksForThePasswordBeforeAStaleChange(t *testing.T) {
	a := newApp(t)
	owner := a.owner()
	if got := owner.api("GET", "settings", nil).json(t)["askPassword"]; got != true {
		t.Fatalf("askPassword is %v by default", got)
	}
	a.clock.Add(11 * time.Minute)
	r := owner.api("POST", "me/tokens", map[string]any{"name": "script", "scopes": []string{"read"}})
	want(t, r, 403, "signInAgain")
	if r.json(t)["askPassword"] != true {
		t.Fatalf("signInAgain does not offer the password: %s", r.Body)
	}
	if owner.api("GET", "me", nil).json(t)["askPassword"] != true {
		t.Fatal("me does not say the app asks")
	}
	want(t, owner.api("POST", "me/confirm", map[string]string{"password": ownerPassword}), 200, "")
	want(t, owner.api("POST", "me/tokens", map[string]any{"name": "script", "scopes": []string{"read"}}), 200, "")
}

func TestWithoutTheQuestionAStaleChangeWantsANewSignIn(t *testing.T) {
	a := newApp(t)
	owner := a.owner()
	want(t, owner.api("PATCH", "settings", map[string]bool{"askPassword": false}), 200, "")
	a.open()
	if got := owner.api("GET", "settings", nil).json(t)["askPassword"]; got != false {
		t.Fatalf("the setting did not last: %v", got)
	}
	a.clock.Add(11 * time.Minute)
	r := owner.api("POST", "me/tokens", map[string]any{"name": "script", "scopes": []string{"read"}})
	want(t, r, 403, "signInAgain")
	if r.json(t)["askPassword"] != false {
		t.Fatalf("signInAgain still offers the password: %s", r.Body)
	}
	want(t, owner.api("POST", "me/confirm", map[string]string{"password": ownerPassword}), 409, "confirmOff")
	fresh := a.signIn()
	want(t, fresh.api("POST", "me/tokens", map[string]any{"name": "script", "scopes": []string{"read"}}), 200, "")
}

func TestOnlyAnAdminSetsTheQuestion(t *testing.T) {
	a := newApp(t, manyAccounts)
	owner := a.owner()
	addAccount(t, owner, "anna", "viewer")
	want(t, a.signInAs("anna").api("PATCH", "settings", map[string]bool{"askPassword": false}), 403, "forbidden")
}

func TestAnAccountWithoutAPasswordIsNotAskedForOne(t *testing.T) {
	a := newApp(t)
	owner := a.owner()
	p, id := addService(t, a, owner, "pocket-id")
	p.Next(signintest.Person{Subject: "sub-anna", Name: "anna", Groups: []string{"family"}})
	anna := a.browser()
	anna.serviceSignIn(p, id)
	a.clock.Add(6 * time.Minute)
	r := anna.api("POST", "me/tokens", map[string]any{"name": "script", "scopes": []string{"read"}})
	want(t, r, 403, "signInAgain")
	if r.json(t)["askPassword"] != false {
		t.Fatalf("an account without a password is asked for one: %s", r.Body)
	}
}
