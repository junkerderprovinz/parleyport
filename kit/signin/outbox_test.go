package signin_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/signin"
	"github.com/junkerderprovinz/parleyport/kit/signin/internal/totp"
)

// importedPair imports the owner and anna, both with an old password, into
// an app with many accounts. Anna also has an old token.
func importedPair(old *oldApp) option {
	return func(c *signin.Config) {
		manyAccounts(c)
		old.option(oldOwner())(c)
		c.Import = func(context.Context) ([]signin.Imported, error) {
			old.imports.Add(1)
			anna := signin.Imported{
				ID: "8", Name: "anna", Role: "viewer", Password: "old:password of anna",
				Tokens: []signin.ImportedToken{{Name: "sync", Scopes: []string{"read"}, Digest: "digest:old_anna"}},
			}
			return []signin.Imported{oldOwner(), anna}, nil
		}
	}
}

func (a *app) signInOwner() *browser {
	a.t.Helper()
	b := a.browser()
	want(a.t, b.api("POST", "login", map[string]string{"name": "owner", "password": ownerPassword}), 200, "")
	return b
}

func TestTurningOnTwoFactorEndsTheAppsWaysIn(t *testing.T) {
	old := &oldApp{}
	a := newApp(t, old.option(oldOwner()))
	twoFactor(t, a, a.signIn())
	if got := a.endedWith(); !slices.Contains(got, "7:twoFactor") {
		t.Fatalf("Ended = %v", got)
	}
	if got := old.droppedWith(); !slices.Equal(got, []string{"7:twoFactor"}) {
		t.Fatalf("Drop = %v", got)
	}
}

func TestTurningOffTwoFactorEndsTheAppsWaysIn(t *testing.T) {
	a := newApp(t)
	b := a.owner()
	secret, _ := twoFactor(t, a, b)
	want(t, b.api("DELETE", "me/totp", map[string]string{"code": totp.Code(secret, a.clock.Now())}), 200, "")
	n := 0
	for _, e := range a.endedWith() {
		if strings.HasSuffix(e, ":twoFactor") {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("Ended = %v", a.endedWith())
	}
}

func TestDropRunsWhenAnImportedAccountIsBlocked(t *testing.T) {
	old := &oldApp{}
	a := newApp(t, importedPair(old))
	want(t, a.signInOwner().api("PATCH", "accounts/8", map[string]any{"blocked": true}), 200, "")
	if got := old.droppedWith(); !slices.Equal(got, []string{"8:blocked"}) {
		t.Fatalf("Drop = %v", got)
	}
}

func TestDropRunsWhenAnImportedTokenIsDeleted(t *testing.T) {
	old := &oldApp{}
	a := newApp(t, importedPair(old))
	anna := a.signInAs("anna")
	var list struct{ Tokens []struct{ ID string } }
	if err := jsonOf(anna.api("GET", "me/tokens", nil), &list); err != nil || len(list.Tokens) != 1 {
		t.Fatalf("tokens %+v %v", list, err)
	}
	want(t, anna.api("DELETE", "me/tokens/"+list.Tokens[0].ID, nil), 200, "")
	if got := old.droppedWith(); !slices.Equal(got, []string{"8:way"}) {
		t.Fatalf("Drop = %v", got)
	}
	if got := a.endedWith(); slices.Contains(got, "8:way") {
		t.Fatalf("Ended heard a single way in going: %v", got)
	}
}

func TestDropRunsWhenAnImportedPasskeyIsRemoved(t *testing.T) {
	old := &oldApp{}
	a := newApp(t, old.option(oldOwner()))
	owner := a.signIn()
	addPasskey(t, owner, a.authenticator())
	var list struct{ Passkeys []struct{ ID string } }
	if err := jsonOf(owner.api("GET", "me/passkeys", nil), &list); err != nil || len(list.Passkeys) != 1 {
		t.Fatalf("passkeys %+v %v", list, err)
	}
	want(t, owner.api("DELETE", "me/passkeys/"+list.Passkeys[0].ID, nil), 200, "")
	if got := old.droppedWith(); !slices.Equal(got, []string{"7:way"}) {
		t.Fatalf("Drop = %v", got)
	}
}

func TestUnlinkingAnImportedIdentityDropsTheOldFields(t *testing.T) {
	old := &oldApp{}
	owner := oldOwner()
	owner.Identities = []signin.ImportedIdentity{{Issuer: "https://id.example", Subject: "sub-owner", Name: "owner"}}
	a := newApp(t, old.option(owner))
	b := a.signIn()
	var list struct{ Identities []struct{ ID string } }
	if err := jsonOf(b.api("GET", "me/identities", nil), &list); err != nil || len(list.Identities) != 1 {
		t.Fatalf("identities %+v %v", list, err)
	}
	want(t, b.api("DELETE", "me/identities/"+list.Identities[0].ID, nil), 200, "")
	if got := old.droppedWith(); !slices.Equal(got, []string{"7:way"}) {
		t.Fatalf("Drop = %v", got)
	}
}

func TestAResetDropsOnlyTokensAndSessionsOfTheOtherAccounts(t *testing.T) {
	old := &oldApp{}
	log := &logBuffer{}
	a := newApp(t, importedPair(old), withLog(log))
	code := resetCode(t, a, log)
	want(t, a.browser().api("POST", "reset", map[string]string{"code": code, "password": "a brand new password"}), 200, "")
	dropped, ended := old.droppedWith(), a.endedWith()
	for _, w := range []string{"7:reset", "8:resetOther"} {
		if !slices.Contains(dropped, w) || !slices.Contains(ended, w) {
			t.Fatalf("Drop = %v, Ended = %v, want %s in both", dropped, ended, w)
		}
	}
	anna := a.signInAs("anna")
	want(t, anna.api("PUT", "me/password", map[string]string{"current": "password of anna", "next": "anna's new password"}), 200, "")
	if got := old.droppedWith(); !slices.Contains(got, "8:password") {
		t.Fatalf("after a partial drop the next epoch dropped nothing: %v", got)
	}
}

func TestDropRunsAgainAfterARestartUntilItTakes(t *testing.T) {
	old := &oldApp{}
	var broken atomic.Bool
	broken.Store(true)
	a := newApp(t, old.option(oldOwner()), func(c *signin.Config) {
		drop := c.Legacy.Drop
		c.Legacy.Drop = func(ctx context.Context, account string, what signin.Ending) error {
			if broken.Load() {
				return errors.New("disk full")
			}
			return drop(ctx, account, what)
		}
	})
	want(t, a.signIn().api("PUT", "me/password", map[string]string{"current": ownerPassword, "next": "another good password"}), 200, "")
	broken.Store(false)
	a.open()
	if got := old.droppedWith(); !slices.Equal(got, []string{"7:password"}) {
		t.Fatalf("Drop = %v", got)
	}
}

// stuckFor makes the app's Ended fail for one account and hear the others.
func stuckFor(a *app, account *string) {
	a.cfg.Hooks.Ended = func(_ context.Context, id string, what signin.Ending) error {
		if id == *account {
			return errors.New("the app's table is locked")
		}
		a.mu.Lock()
		a.ended = append(a.ended, id+":"+string(what))
		a.mu.Unlock()
		return nil
	}
	a.open()
}

func TestAStuckEndingHoldsBackNoOtherAccount(t *testing.T) {
	var stuck string
	a := newApp(t, manyAccounts)
	stuckFor(a, &stuck)
	owner := a.owner()
	stuck = addAccount(t, owner, "anna", "viewer")
	ben := addAccount(t, owner, "ben", "viewer")
	want(t, owner.api("PATCH", "accounts/"+stuck, map[string]any{"blocked": true}), 200, "")
	want(t, owner.api("PATCH", "accounts/"+ben, map[string]any{"blocked": true}), 200, "")
	if got := a.endedWith(); !slices.Contains(got, ben+":blocked") {
		t.Fatalf("Ended = %v", got)
	}
}

func TestAStuckEndingIsLoggedOnceAnHour(t *testing.T) {
	var stuck string
	log := &logBuffer{}
	a := newApp(t, manyAccounts, withLog(log))
	stuckFor(a, &stuck)
	owner := a.owner()
	stuck = addAccount(t, owner, "anna", "viewer")
	ben := addAccount(t, owner, "ben", "viewer")
	want(t, owner.api("PATCH", "accounts/"+stuck, map[string]any{"blocked": true}), 200, "")
	lines := func() int { return strings.Count(log.String(), "account="+stuck) }
	for _, blocked := range []bool{true, false, true} {
		want(t, owner.api("PATCH", "accounts/"+ben, map[string]any{"blocked": blocked}), 200, "")
	}
	if n := lines(); n != 1 {
		t.Fatalf("the stuck ending was logged %d times within minutes:\n%s", n, log)
	}
	a.clock.Add(61 * time.Minute)
	want(t, owner.api("PATCH", "accounts/"+ben, map[string]any{"blocked": false}), 200, "")
	if n := lines(); n != 2 {
		t.Fatalf("the stuck ending was logged %d times after an hour:\n%s", n, log)
	}
}

func jsonOf(r reply, v any) error {
	if r.Status != http.StatusOK {
		return errors.New(string(r.Body))
	}
	return json.Unmarshal(r.Body, v)
}
