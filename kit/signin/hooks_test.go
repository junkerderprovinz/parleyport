package signin_test

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/signin"
)

// phoneDoor lets in a request with the header a paired phone sends, as the
// account the app paired it with.
func phoneDoor(account *string) option {
	return func(c *signin.Config) {
		c.Hooks.Doors = []signin.Door{func(r *http.Request) (signin.Visitor, bool) {
			if r.Header.Get("X-Phone") != "paired" {
				return signin.Visitor{}, false
			}
			return signin.Visitor{Account: *account, Role: "admin", Scopes: []string{"read"}}, true
		}}
	}
}

func TestADoorLetsInWithTheRoleThePackageKeeps(t *testing.T) {
	var account string
	a := newApp(t, manyAccounts, phoneDoor(&account))
	owner := a.owner()
	account = addAccount(t, owner, "anna", "viewer")
	phone := a.browser()
	phone.header.Set("X-Phone", "paired")
	v := phone.visitor()
	if v.Via != signin.ViaDoor || v.Name != "anna" || v.Role != "viewer" || len(v.Scopes) != 1 {
		t.Fatalf("the phone is %+v", v)
	}
	want(t, phone.api("POST", "me/tokens", map[string]any{"name": "x", "scopes": []string{"read"}}), 403, "forbidden")

	owner.api("PATCH", "accounts/"+account, map[string]any{"blocked": true})
	if v := phone.visitor(); v.Via != "" {
		t.Fatalf("a door let a blocked account in: %+v", v)
	}
	account = "nobody"
	if v := phone.visitor(); v.Via != "" {
		t.Fatalf("a door let an unknown account in: %+v", v)
	}
}

func TestHooksHearSignInsAndTheLog(t *testing.T) {
	var mu sync.Mutex
	var signedIn []signin.Visitor
	var results []string
	a := newApp(t, func(c *signin.Config) {
		c.Hooks.SignedIn = func(_ context.Context, v signin.Visitor, _ []string) {
			mu.Lock()
			signedIn = append(signedIn, v)
			mu.Unlock()
		}
		c.Hooks.Logged = func(_ context.Context, e signin.Entry) {
			mu.Lock()
			results = append(results, e.Result)
			mu.Unlock()
		}
	})
	a.owner()
	a.browser().api("POST", "login", map[string]string{"password": "wrong password"})
	a.signIn()
	mu.Lock()
	defer mu.Unlock()
	if len(signedIn) != 1 || signedIn[0].Via != signin.ViaPassword {
		t.Fatalf("SignedIn heard %+v", signedIn)
	}
	if len(results) != 3 || results[0] != "firstPassword" || results[1] != "wrongPassword" || results[2] != "ok" {
		t.Fatalf("Logged heard %v", results)
	}
}

func TestEndingsWaitUntilTheAppTakesThem(t *testing.T) {
	a := newApp(t)
	failing := true
	var got []string
	a.cfg.Hooks.Ended = func(_ context.Context, account string, what signin.Ending) error {
		if failing {
			return context.DeadlineExceeded
		}
		got = append(got, string(what))
		return nil
	}
	a.open()
	a.owner()
	if len(got) != 0 {
		t.Fatal("a failing hook took the ending")
	}
	failing = false
	a.open()
	if len(got) != 1 || got[0] != "firstPassword" {
		t.Fatalf("after a restart the hook got %v", got)
	}
}
