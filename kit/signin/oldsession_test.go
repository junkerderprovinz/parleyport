package signin_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/signin"
)

// withOldSessions starts an app on the old data of oldOwner with the given
// old sessions, by cookie value.
func withOldSessions(t *testing.T, sessions map[string]signin.OldSession) *app {
	t.Helper()
	old := &oldApp{sessions: sessions}
	a := newApp(t)
	a.cfg = withOption(a.cfg, old.option(oldOwner()))
	a.store = freshStore(a)
	a.open()
	return a
}

func (b *browser) oldCookie(value string) *browser {
	b.c.Jar.SetCookies(mustURL(b.a), []*http.Cookie{{Name: "old_session", Value: value, Path: "/"}})
	return b
}

func oldSession(key string, issued time.Time) signin.OldSession {
	return signin.OldSession{Account: "7", Key: key, Via: signin.ViaPassword, Issued: issued, SignedAt: issued, Expires: issued.Add(30 * 24 * time.Hour)}
}

func TestAnOldCookieWorksForTwoMinutesAfterItsSwap(t *testing.T) {
	start := newClock().Now()
	a := withOldSessions(t, map[string]signin.OldSession{"one": oldSession("one", start.Add(-time.Hour))})
	if v := a.browser().oldCookie("one").visitor(); v.Account != "7" {
		t.Fatalf("the old session does not count: %+v", v)
	}
	again := a.browser().oldCookie("one")
	r := again.do("GET", "/app", nil)
	if r.Status != http.StatusOK || len(r.Header.Values("Set-Cookie")) != 0 {
		t.Fatalf("a request that raced the swap got %d with cookies %v", r.Status, r.Header.Values("Set-Cookie"))
	}
	a.clock.Add(3 * time.Minute)
	if v := again.visitor(); v.Via != "" {
		t.Fatalf("the old cookie counts minutes after its swap: %+v", v)
	}
}

func TestAnOldCookieDoesNotOutliveTheSwappedSession(t *testing.T) {
	start := newClock().Now()
	a := withOldSessions(t, map[string]signin.OldSession{"one": oldSession("one", start.Add(-time.Hour))})
	b := a.browser().oldCookie("one")
	b.visitor()
	want(t, b.api("POST", "logout", map[string]any{}), 200, "")
	if v := a.browser().oldCookie("one").visitor(); v.Via != "" {
		t.Fatalf("the old cookie outlived the session it was swapped for: %+v", v)
	}
}

func TestASwappedOldSessionIsFreshOnlyFromItsSignIn(t *testing.T) {
	start := newClock().Now()
	s := oldSession("one", start.Add(-time.Minute))
	s.SignedAt = start.Add(-time.Hour)
	a := withOldSessions(t, map[string]signin.OldSession{"one": s})
	b := a.browser().oldCookie("one")
	if me := b.api("GET", "me", nil).json(t); me["account"] != "7" || me["fresh"] != false {
		t.Fatalf("a session renewed a minute ago but signed in an hour ago: %v", me)
	}
}

func TestAnOldSessionEndsAtItsOwnExpiry(t *testing.T) {
	start := newClock().Now()
	s := oldSession("one", start.Add(-time.Hour))
	s.Expires = start.Add(time.Hour)
	a := withOldSessions(t, map[string]signin.OldSession{"one": s})
	b := a.browser().oldCookie("one")
	if b.visitor().Account != "7" {
		t.Fatal("the old session does not count")
	}
	a.clock.Add(2 * time.Hour)
	if v := b.visitor(); v.Via != "" {
		t.Fatalf("the swapped session outlived the old one: %+v", v)
	}
}

func TestTwoOldSessionsWithTheSameIssueTimeBothSwap(t *testing.T) {
	issued := newClock().Now().Add(-time.Hour)
	a := withOldSessions(t, map[string]signin.OldSession{"one": oldSession("one", issued), "two": oldSession("two", issued)})
	if v := a.browser().oldCookie("one").visitor(); v.Account != "7" {
		t.Fatalf("the first old session does not count: %+v", v)
	}
	a.clock.Add(3 * time.Minute)
	if v := a.browser().oldCookie("two").visitor(); v.Account != "7" {
		t.Fatalf("a second old session from the same second does not count: %+v", v)
	}
}

func TestAnOldServiceSessionNeedsItsServiceAfterADay(t *testing.T) {
	start := newClock().Now()
	recent, stale := oldSession("recent", start.Add(-time.Hour)), oldSession("stale", start.Add(-time.Hour))
	recent.Via, recent.Service = signin.ViaService, "config"
	stale.Via, stale.Service, stale.SignedAt = signin.ViaService, "config", start.Add(-48*time.Hour)
	a := withOldSessions(t, map[string]signin.OldSession{"recent": recent, "stale": stale})
	if v := a.browser().oldCookie("recent").visitor(); v.Via != signin.ViaService || v.Service != "config" {
		t.Fatalf("a recent old session of a sign-in service is %+v", v)
	}
	b := a.browser().oldCookie("stale")
	if v := b.visitor(); v.Via != "" {
		t.Fatalf("an old session the service last confirmed two days ago counts: %+v", v)
	}
	if got := b.api("GET", "options", nil).json(t)["renew"]; got != "config" {
		t.Fatalf("options renew = %v", got)
	}
}
