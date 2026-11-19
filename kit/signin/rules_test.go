package signin_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/signin"
	"github.com/junkerderprovinz/parleyport/kit/signin/memstore"
)

func TestOneAddressWaitsAfterTenWrongPasswordsForAnyNames(t *testing.T) {
	a := newApp(t, manyAccounts)
	a.owner()
	b := a.browser()
	for i := range 10 {
		want(t, b.api("POST", "login", map[string]string{"name": fmt.Sprintf("guess %d", i), "password": "wrong password"}), 401, "wrongPassword")
	}
	want(t, b.api("POST", "login", map[string]string{"name": "admin", "password": ownerPassword}), 429, "throttled")
	want(t, a.browser().from("10.0.0.9", "POST", "/api/signin/v1/login", map[string]string{"name": "admin", "password": ownerPassword}), 200, "")
}

func TestACopiedPasskeyChallengeCountsOnce(t *testing.T) {
	a := newApp(t)
	key := a.authenticator()
	addPasskey(t, a.owner(), key)
	b := a.browser()
	r := b.api("POST", "login/passkey/options", map[string]any{})
	challenge := *(&http.Response{Header: r.Header}).Cookies()[0]
	assertion, _ := key.Get(r.Body)
	want(t, b.api("POST", "login/passkey", json.RawMessage(assertion)), 200, "")

	thief := a.browser()
	u := mustURL(a)
	u.Path = "/api/signin/v1/login/passkey"
	challenge.Path = u.Path
	thief.c.Jar.SetCookies(u, []*http.Cookie{&challenge})
	again, _ := key.Get(r.Body)
	want(t, thief.api("POST", "login/passkey", json.RawMessage(again)), 401, "passkeyRefused")
}

func TestACallbackWithAnotherStateIsRefused(t *testing.T) {
	a := newApp(t)
	p, id := addService(t, a, a.owner(), "pocket-id")
	b := a.browser()
	p.Next(ownerAtService)
	back, _ := url.Parse(b.startTrip(p, "/signin/oidc/"+id+"?return=/home"))
	q := back.Query()
	q.Set("state", "someone else's")
	back.RawQuery = q.Encode()
	if got := b.do("GET", back.RequestURI(), nil).Header.Get("Location"); got != "/?signin=flowExpired" || b.visitor().Via != "" {
		t.Fatalf("a callback with another state ended at %s", got)
	}
}

func TestAnOldSessionEndsWithTheFirstEpoch(t *testing.T) {
	old := &oldApp{}
	a := newApp(t)
	old.issued = a.clock.Now().Add(-time.Hour)
	a.cfg = withOption(a.cfg, old.option(oldOwner()))
	a.cfg.Legacy.Drop = nil
	a.store = freshStore(a)
	a.open()
	owner := a.signIn()
	want(t, owner.api("PUT", "me/password", map[string]string{"current": ownerPassword, "next": "another good password"}), 200, "")
	b := a.browser()
	b.c.Jar.SetCookies(mustURL(a), []*http.Cookie{{Name: "old_session", Value: "valid", Path: "/"}})
	if v := b.visitor(); v.Via != "" {
		t.Fatalf("an old session counts after the account's first epoch: %+v", v)
	}
}

// metaFails is a store whose documents read fine in a list but not one by
// one, as a store can break half way.
type metaFails struct{ *memstore.Store }

func (s metaFails) Get(ctx context.Context, kind, id string) ([]byte, error) {
	if kind == "meta" {
		return nil, errors.New("disk read error")
	}
	return s.Store.Get(ctx, kind, id)
}

func TestOpenFailsWhenTheStoreCannotSayItWasSetUp(t *testing.T) {
	seal, _ := signin.NewSealer(testKey())
	if _, err := signin.Open(signin.Config{Domain: "alpha", Store: metaFails{memstore.New()}, Seal: seal, Owner: true}); err == nil {
		t.Fatal("Open went on without knowing whether the store was set up")
	}
}

func TestAPasswordChangeLeavesTokensAlone(t *testing.T) {
	a := newApp(t)
	owner := a.owner()
	r := owner.api("POST", "me/tokens", map[string]any{"name": "script", "scopes": []string{"read"}})
	want(t, r, 200, "")
	script := a.browser()
	script.header.Set("Authorization", "Bearer "+r.json(t)["value"].(string))
	want(t, owner.api("PUT", "me/password", map[string]string{"current": ownerPassword, "next": "another good password"}), 200, "")
	if v := script.visitor(); v.Via != signin.ViaToken || !strings.Contains(strings.Join(v.Scopes, ","), "read") {
		t.Fatalf("a token stopped with the password change: %+v", v)
	}
}

func TestSigningOutEverywhereEndsOldSessionsWithoutDrop(t *testing.T) {
	old := &oldApp{}
	a := newApp(t)
	old.issued = a.clock.Now().Add(-time.Hour)
	a.cfg = withOption(a.cfg, old.option(oldOwner()))
	a.cfg.Legacy.Drop = nil
	a.store = freshStore(a)
	a.open()
	b := a.browser()
	b.c.Jar.SetCookies(mustURL(a), []*http.Cookie{{Name: "old_session", Value: "valid", Path: "/"}})
	want(t, a.signIn().api("DELETE", "me/sessions", nil), 200, "")
	if v := b.visitor(); v.Via != "" {
		t.Fatalf("an old session outlived signing out everywhere: %+v", v)
	}
}
