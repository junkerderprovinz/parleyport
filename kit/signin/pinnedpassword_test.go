package signin_test

import (
	"strings"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/signin"
	"github.com/junkerderprovinz/parleyport/kit/signin/memstore"
	"github.com/junkerderprovinz/parleyport/kit/signin/signintest"
)

const pinnedSecret = "set from outside"

func pinnedHash(t *testing.T, pw string) string {
	t.Helper()
	h, err := signin.HashPinned(pw)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func pinnedTo(hash string) option {
	return func(c *signin.Config) { c.PinnedPassword = signin.PinnedPassword{Hash: hash} }
}

func TestAPinnedPasswordClosesAnOpenAppAndSignsTheOwnerIn(t *testing.T) {
	a := newApp(t, pinnedTo(pinnedHash(t, pinnedSecret)))
	if a.auth.Anyone() {
		t.Fatal("an app with a pinned password is open")
	}
	opts := a.browser().api("GET", "options", nil).json(t)
	if opts["open"] != false || opts["pinned"] != true {
		t.Fatalf("options %v", opts)
	}
	want(t, a.browser().api("POST", "login", map[string]string{"password": pinnedSecret + " wrong"}), 401, "wrongPassword")
	b := a.browser()
	want(t, b.api("POST", "login", map[string]string{"password": pinnedSecret}), 200, "")
	if v := b.visitor(); v.Role != "admin" || v.Via != signin.ViaPassword {
		t.Fatalf("the owner is %+v", v)
	}
	if me := b.api("GET", "me", nil).json(t); me["pinned"] != true || me["password"] != true || me["owner"] != true {
		t.Fatalf("me %v", me)
	}
}

func TestAPinnedPasswordTakesThePlaceOfTheOneSetInTheApp(t *testing.T) {
	a := newApp(t)
	a.owner()
	a.cfg.PinnedPassword = signin.PinnedPassword{Hash: pinnedHash(t, pinnedSecret)}
	a.open()
	want(t, a.browser().api("POST", "login", map[string]string{"password": ownerPassword}), 401, "wrongPassword")
	want(t, a.browser().api("POST", "login", map[string]string{"password": pinnedSecret}), 200, "")

	a.cfg.PinnedPassword = signin.PinnedPassword{}
	a.open()
	if got := a.browser().api("GET", "options", nil).json(t)["pinned"]; got != false {
		t.Fatalf("options pinned = %v without a pinned password", got)
	}
	a.signIn()
}

func TestAPinnedPasswordIsNeverChangedRemovedOrReset(t *testing.T) {
	a := newApp(t, pinnedTo(pinnedHash(t, pinnedSecret)))
	b := a.browser()
	want(t, b.api("POST", "login", map[string]string{"password": pinnedSecret}), 200, "")
	want(t, b.api("PUT", "me/password", map[string]string{"current": pinnedSecret, "next": "another password"}), 409, "pinned")
	want(t, b.api("DELETE", "me/password", map[string]string{"current": pinnedSecret}), 409, "pinned")
	want(t, a.browser().api("POST", "reset-code", map[string]string{}), 409, "pinned")
	want(t, a.browser().api("POST", "reset", map[string]string{"code": "AAAA-AAAA-AAAA", "password": "another password"}), 409, "pinned")
	want(t, a.browser().api("POST", "login", map[string]string{"password": pinnedSecret}), 200, "")
	if a.auth.Anyone() {
		t.Fatal("the app opened")
	}
}

func TestTheSignInChecksAPinnedHashOfTheAppsOwnForm(t *testing.T) {
	var asked []string
	a := newApp(t, func(c *signin.Config) {
		c.PinnedPassword = signin.PinnedPassword{
			Hash: "own:" + pinnedSecret,
			Check: func(hash, pw string) bool {
				asked = append(asked, hash)
				return hash == "own:"+pw
			},
		}
	})
	want(t, a.browser().api("POST", "login", map[string]string{"password": "guess"}), 401, "wrongPassword")
	want(t, a.browser().api("POST", "login", map[string]string{"password": pinnedSecret}), 200, "")
	if len(asked) != 2 || asked[0] != "own:"+pinnedSecret {
		t.Fatalf("Check was asked %v", asked)
	}
}

func TestANewPinnedPasswordEndsTheOwnersSessions(t *testing.T) {
	a := newApp(t, pinnedTo(pinnedHash(t, pinnedSecret)))
	b := a.browser()
	want(t, b.api("POST", "login", map[string]string{"password": pinnedSecret}), 200, "")

	a.open()
	if v := b.visitor(); v.Via != signin.ViaPassword {
		t.Fatalf("a restart with the same pinned password ended the session: %+v", v)
	}

	a.cfg.PinnedPassword = signin.PinnedPassword{Hash: pinnedHash(t, "the next one")}
	a.open()
	if v := b.visitor(); v.Via != "" {
		t.Fatalf("the session outlived the pinned password it signed in with: %+v", v)
	}
	if ended := strings.Join(a.endedWith(), " "); !strings.Contains(ended, ":password") {
		t.Fatalf("the app heard %q", ended)
	}
	want(t, a.browser().api("POST", "login", map[string]string{"password": "the next one"}), 200, "")
}

func TestAPinnedPasswordNeedsAnOwnerApp(t *testing.T) {
	a := newApp(t, manyAccounts)
	cfg := a.cfg
	cfg.Store = memstore.New()
	cfg.PinnedPassword = signin.PinnedPassword{Hash: pinnedHash(t, pinnedSecret)}
	if _, err := signin.Open(cfg); err == nil {
		t.Fatal("Open took a pinned password for an app with many accounts")
	}
}

func TestAnAppWithAPinnedPasswordKeepsTheContract(t *testing.T) {
	a := newApp(t, pinnedTo(pinnedHash(t, pinnedSecret)))
	signintest.Run(t, a.srv.Config.Handler, signintest.Options{Password: pinnedSecret, Pinned: true})
}
