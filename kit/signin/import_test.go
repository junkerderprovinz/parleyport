package signin_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/signin"
	"github.com/junkerderprovinz/parleyport/kit/signin/internal/totp"
)

// oldApp is what an app kept before the package: a password in its own
// format, a session cookie and a token of its own.
type oldApp struct {
	imports, checks, drops atomic.Int32
	issued                 time.Time

	mu      sync.Mutex
	dropped []string
}

// droppedWith lists the calls of Legacy.Drop as account:what.
func (o *oldApp) droppedWith() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.dropped...)
}

func (o *oldApp) option(owner signin.Imported) option {
	return func(c *signin.Config) {
		c.Import = func(context.Context) ([]signin.Imported, error) {
			o.imports.Add(1)
			return []signin.Imported{owner}, nil
		}
		c.Legacy = signin.Legacy{
			Password: func(_ context.Context, hash, pw string) (bool, error) {
				o.checks.Add(1)
				return hash == "old:"+pw, nil
			},
			Session: func(r *http.Request) (string, time.Time, bool) {
				c, err := r.Cookie("old_session")
				if err != nil || c.Value != "valid" {
					return "", time.Time{}, false
				}
				return "7", o.issued, true
			},
			SessionLife: 30 * 24 * time.Hour,
			Recovery:    func(hash, code string) bool { return hash == "old:"+code },
			Token: func(tok string) (string, bool) {
				if !strings.HasPrefix(tok, "old_") {
					return "", false
				}
				return "digest:" + tok, true
			},
			Drop: func(_ context.Context, account string, what signin.Ending) error {
				o.drops.Add(1)
				o.mu.Lock()
				o.dropped = append(o.dropped, account+":"+string(what))
				o.mu.Unlock()
				return nil
			},
		}
	}
}

func oldOwner() signin.Imported {
	return signin.Imported{
		ID: "7", Name: "owner", Role: "admin", Owner: true, Password: "old:" + ownerPassword,
		Tokens: []signin.ImportedToken{{Name: "script", Scopes: []string{"read"}, Digest: "digest:old_abc"}},
	}
}

func TestImportRunsOnceAndOldPasswordsSignIn(t *testing.T) {
	old := &oldApp{}
	a := newApp(t, old.option(oldOwner()))
	if a.auth.Anyone() {
		t.Fatal("the app is open with an imported password")
	}
	want(t, a.browser().api("POST", "login", map[string]string{"password": ownerPassword}), 200, "")
	want(t, a.browser().api("POST", "login", map[string]string{"password": ownerPassword}), 200, "")
	if n := old.checks.Load(); n != 1 {
		t.Fatalf("the old check ran %d times, the hash was not written anew", n)
	}
	a.open()
	if n := old.imports.Load(); n != 1 {
		t.Fatalf("import ran %d times", n)
	}
	if v := a.signIn().visitor(); v.Account != "7" || v.Name != "owner" {
		t.Fatalf("visitor %+v", v)
	}
}

func TestAFailedImportWritesNothing(t *testing.T) {
	a := newApp(t)
	store := freshStore(a)
	a.cfg.Import = func(context.Context) ([]signin.Imported, error) { return nil, errors.New("old data unreadable") }
	if _, err := signin.Open(a.cfg); err == nil {
		t.Fatal("Open went on after a failed import")
	}
	if docs, _ := store.List(context.Background(), "meta"); len(docs) != 0 {
		t.Fatal("a failed import left its mark, so it would not run again")
	}
	old := &oldApp{}
	a.cfg = withOption(a.cfg, old.option(oldOwner()))
	a.open()
	if old.imports.Load() != 1 || a.auth.Anyone() {
		t.Fatal("the import did not run on the next start")
	}
}

func TestImportRefusesTwoAccountsWithOneName(t *testing.T) {
	a := newApp(t)
	freshStore(a)
	a.cfg.Import = func(context.Context) ([]signin.Imported, error) {
		return []signin.Imported{{ID: "1", Name: "Anna", Owner: true}, {ID: "2", Name: "anna"}}, nil
	}
	if _, err := signin.Open(a.cfg); err == nil {
		t.Fatal("two accounts named anna imported")
	}
}

func TestAnOldSessionIsSwappedForANewOne(t *testing.T) {
	old := &oldApp{}
	a := newApp(t, func(c *signin.Config) {})
	old.issued = a.clock.Now().Add(-time.Hour)
	a.cfg = withOption(a.cfg, old.option(oldOwner()))
	a.store = freshStore(a)
	a.open()

	b := a.browser()
	b.c.Jar.SetCookies(mustURL(a), []*http.Cookie{{Name: "old_session", Value: "valid", Path: "/"}})
	if v := b.visitor(); v.Account != "7" {
		t.Fatalf("the old session does not count: %+v", v)
	}
	if b.cookie("__Host-alpha-session") == nil {
		t.Fatal("no new session was set")
	}
	b.c.Jar.SetCookies(mustURL(a), []*http.Cookie{{Name: "old_session", Value: "", Path: "/", MaxAge: -1}})
	if v := b.visitor(); v.Account != "7" {
		t.Fatal("the new session does not count on its own")
	}
}

func TestAnOldSessionEndsWithItsOldLifeAndTheFirstEpoch(t *testing.T) {
	old := &oldApp{}
	a := newApp(t)
	old.issued = a.clock.Now().Add(-29 * 24 * time.Hour)
	a.cfg = withOption(a.cfg, old.option(oldOwner()))
	a.store = freshStore(a)
	a.open()
	b := a.browser()
	b.c.Jar.SetCookies(mustURL(a), []*http.Cookie{{Name: "old_session", Value: "valid", Path: "/"}})
	a.clock.Add(2 * 24 * time.Hour)
	if v := b.visitor(); v.Via != "" {
		t.Fatalf("an old session past its old life counts: %+v", v)
	}

	c := a.browser()
	old.issued = a.clock.Now().Add(-time.Hour)
	owner := a.signIn()
	want(t, owner.api("PUT", "me/password", map[string]string{"current": ownerPassword, "next": "another good password"}), 200, "")
	c.c.Jar.SetCookies(mustURL(a), []*http.Cookie{{Name: "old_session", Value: "valid", Path: "/"}})
	if v := c.visitor(); v.Via != "" {
		t.Fatalf("an old session counts after the password changed: %+v", v)
	}
	if old.drops.Load() != 1 {
		t.Fatalf("Drop ran %d times", old.drops.Load())
	}
}

func TestAnOldSessionIssuedAfterTheImportDoesNotCount(t *testing.T) {
	old := &oldApp{}
	a := newApp(t)
	old.issued = a.clock.Now().Add(time.Minute)
	a.cfg = withOption(a.cfg, old.option(oldOwner()))
	a.store = freshStore(a)
	a.open()
	a.clock.Add(2 * time.Minute)
	b := a.browser()
	b.c.Jar.SetCookies(mustURL(a), []*http.Cookie{{Name: "old_session", Value: "valid", Path: "/"}})
	if v := b.visitor(); v.Via != "" {
		t.Fatalf("an old session made after the import counts: %+v", v)
	}
}

func TestAnOldTokenStillWorks(t *testing.T) {
	old := &oldApp{}
	a := newApp(t, old.option(oldOwner()))
	b := a.browser()
	b.header.Set("Authorization", "Bearer old_abc")
	if v := b.visitor(); v.Via != signin.ViaToken || v.Account != "7" {
		t.Fatalf("visitor %+v", v)
	}
	b.header.Set("Authorization", "Bearer old_xyz")
	if v := b.visitor(); v.Via != "" {
		t.Fatalf("an unknown old token counts: %+v", v)
	}
}

func TestAnImportedSecondFactorAndOldRecoveryCodes(t *testing.T) {
	old := &oldApp{}
	owner := oldOwner()
	owner.TOTP = []byte("12345678901234567890")
	owner.Recovery = []string{"old:aaaaa-bbbbb"}
	a := newApp(t, old.option(owner))
	b := a.browser()
	if r := b.api("POST", "login", map[string]string{"password": ownerPassword}); r.json(t)["step"] != "code" {
		t.Fatalf("an imported second factor is not asked for: %s", r.Body)
	}
	want(t, b.api("POST", "login/totp", map[string]string{"code": totp.Code(owner.TOTP, a.clock.Now())}), 200, "")
	c := a.browser()
	c.api("POST", "login", map[string]string{"password": ownerPassword})
	want(t, c.api("POST", "login/totp", map[string]string{"code": "aaaaa-bbbbb"}), 200, "")
	d := a.browser()
	d.api("POST", "login", map[string]string{"password": ownerPassword})
	want(t, d.api("POST", "login/totp", map[string]string{"code": "aaaaa-bbbbb"}), 401, "wrongCode")
}
