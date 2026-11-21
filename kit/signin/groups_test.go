package signin_test

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/signin"
	"github.com/junkerderprovinz/parleyport/kit/signin/signintest"
)

// heardGroups records the groups Admit and SignedIn hear, in order.
type heardGroups struct {
	mu            sync.Mutex
	admit, signed [][]string
}

func (h *heardGroups) option(c *signin.Config) {
	c.Hooks.Admit = func(_ context.Context, in signin.Arrival) (string, error) {
		h.mu.Lock()
		h.admit = append(h.admit, in.Groups)
		h.mu.Unlock()
		return "", nil
	}
	c.Hooks.SignedIn = func(_ context.Context, _ signin.Visitor, groups []string) {
		h.mu.Lock()
		h.signed = append(h.signed, groups)
		h.mu.Unlock()
	}
}

// last reports whether the latest groups both hooks heard are absent (nil)
// or present.
func (h *heardGroups) last(t *testing.T) (admitNil, signedNil bool) {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.admit) == 0 || len(h.signed) == 0 {
		t.Fatal("the hooks heard nothing")
	}
	return h.admit[len(h.admit)-1] == nil, h.signed[len(h.signed)-1] == nil
}

func TestAnEmptyGroupsClaimIsNotAMissingOne(t *testing.T) {
	h := &heardGroups{}
	p := signintest.NewProvider(t)
	a := newApp(t, manyAccounts, closed, fromConfig(p, false), h.option)
	b := a.browser()
	p.Next(signintest.Person{Subject: "sub-anna", Name: "anna", Groups: []string{}})
	b.serviceSignIn(p, "config")
	if admitNil, signedNil := h.last(t); admitNil || signedNil {
		t.Fatal("an empty groups claim reached the app as a missing one")
	}

	a.clock.Add(25 * time.Hour)
	p.Next(signintest.Person{Subject: "sub-anna", Name: "anna"})
	if got := b.via(p, "/signin/oidc/config?renew=1&return=/home"); got != "/home" {
		t.Fatalf("the renewal ended at %s", got)
	}
	if admitNil, signedNil := h.last(t); !admitNil || !signedNil {
		t.Fatal("a missing groups claim reached the app as an empty one on renewal")
	}

	a.clock.Add(25 * time.Hour)
	p.Next(signintest.Person{Subject: "sub-anna", Name: "anna", Groups: []string{}})
	b.via(p, "/signin/oidc/config?renew=1&return=/home")
	if admitNil, signedNil := h.last(t); admitNil || signedNil {
		t.Fatal("an empty groups claim reached the app as a missing one on renewal")
	}
}

func TestAnAppsOwnMintAnswersSignInAgainAsTheKitDoes(t *testing.T) {
	a := newApp(t)
	owner := a.owner()
	a.clock.Add(11 * time.Minute)
	kit := owner.api("POST", "me/tokens", map[string]any{"name": "script", "scopes": []string{"read"}})
	rec := &recorder{header: http.Header{}}
	r := owner.requestTo("/app")
	if err := a.auth.Mint(r, func() error { return nil }); !errors.Is(err, signin.ErrNotFresh) {
		t.Fatalf("Mint = %v", err)
	}
	a.auth.SignInAgain(rec, r)
	if rec.status != kit.Status || rec.body != string(kit.Body) || rec.header.Get("Content-Type") != "application/json" || rec.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("SignInAgain wrote %d %s, the kit %d %s", rec.status, rec.body, kit.Status, kit.Body)
	}
}

type recorder struct {
	header http.Header
	status int
	body   string
}

func (r *recorder) Header() http.Header         { return r.header }
func (r *recorder) WriteHeader(status int)      { r.status = status }
func (r *recorder) Write(b []byte) (int, error) { r.body += string(b); return len(b), nil }

func TestAnAdminsTokenReadsButDoesNotChangeOtherAccounts(t *testing.T) {
	a := newApp(t, manyAccounts)
	owner := a.owner()
	id := addAccount(t, owner, "anna", "viewer")
	a.signInAs("anna")
	tok := owner.api("POST", "me/tokens", map[string]any{"name": "script", "scopes": []string{"read"}}).json(t)["value"].(string)
	script := a.browser()
	script.header.Set("Authorization", "Bearer "+tok)
	r := script.requestTo("/app")
	if s, err := a.auth.Sessions(r, id); err != nil || len(s) != 1 {
		t.Fatalf("Sessions with an admin's token = %v, %v", s, err)
	}
	if _, err := a.auth.Tokens(r, id); err != nil {
		t.Fatalf("Tokens with an admin's token: %v", err)
	}
	if _, err := a.auth.Passkeys(r, id); err != nil {
		t.Fatalf("Passkeys with an admin's token: %v", err)
	}
	refusal(t, a.auth.Revoke(r, id), "notWithToken")

	viewer := a.browser()
	viewer.header.Set("Authorization", "Bearer "+a.signInAs("anna").api("POST", "me/tokens", map[string]any{"name": "x", "scopes": []string{"read"}}).json(t)["value"].(string))
	_, err := a.auth.Sessions(viewer.requestTo("/app"), id)
	refusal(t, err, "forbidden")
}

func TestCheckPasswordSaysHowLongToWait(t *testing.T) {
	a := newApp(t, manyAccounts)
	addAccount(t, a.owner(), "anna", "viewer")
	r := a.browser().requestTo("/dav")
	for range 6 {
		_, _ = a.auth.CheckPassword(r, "dav", "anna", "wrong password")
	}
	_, err := a.auth.CheckPassword(r, "dav", "anna", "password of anna")
	var no *signin.Refusal
	if !errors.As(err, &no) || no.Code != "throttled" || no.Retry <= 0 {
		t.Fatalf("err = %#v, want throttled with a wait", err)
	}
}
