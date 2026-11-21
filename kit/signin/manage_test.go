package signin_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/signin"
	"github.com/junkerderprovinz/parleyport/kit/signin/signintest"
)

// numbered gives new accounts the ids 1001, 1002 and on, as an app with
// numeric ids of its own does.
func numbered(next *atomic.Int64) option {
	next.Store(1000)
	return func(c *signin.Config) {
		c.NewID = func() (string, error) { return fmt.Sprint(next.Add(1)), nil }
	}
}

// changes records what Hooks.Changing hears, and refuses a name of
// "refused".
type changes struct {
	mu  sync.Mutex
	got []signin.Change
}

func (c *changes) option(cfg *signin.Config) {
	cfg.Hooks.Changing = func(_ context.Context, ch signin.Change) error {
		if ch.Name == "refused" {
			return errors.New("the app's table says no")
		}
		c.mu.Lock()
		c.got = append(c.got, ch)
		c.mu.Unlock()
		return nil
	}
}

func (c *changes) kinds() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, ch := range c.got {
		out = append(out, string(ch.Kind)+":"+ch.Name)
	}
	return out
}

func (c *changes) last() signin.Change {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.got[len(c.got)-1]
}

func refusal(t *testing.T, err error, code string) {
	t.Helper()
	var no *signin.Refusal
	if !errors.As(err, &no) || no.Code != code {
		t.Fatalf("err = %v, want the code %s", err, code)
	}
}

func TestTheAppMakesTheIDsOfNewAccounts(t *testing.T) {
	var next atomic.Int64
	a := newApp(t, manyAccounts, numbered(&next))
	owner := a.owner()
	if id := owner.visitor().Account; id != "1001" {
		t.Fatalf("the owner's id is %s", id)
	}
	if id := addAccount(t, owner, "anna", "viewer"); id != "1002" {
		t.Fatalf("anna's id is %s", id)
	}
	p, svc := addService(t, a, owner, "pocket-id")
	p.Next(signintest.Person{Subject: "sub-ben", Name: "ben"})
	b := a.browser()
	b.serviceSignIn(p, svc)
	if id := b.visitor().Account; id != "1003" {
		t.Fatalf("ben's id is %s", id)
	}
}

func TestANewIDThatIsTakenIsNeverUsed(t *testing.T) {
	ids := []string{"1", "1", "2"}
	a := newApp(t, manyAccounts, func(c *signin.Config) {
		c.NewID = func() (string, error) {
			id := ids[0]
			ids = ids[1:]
			return id, nil
		}
	})
	owner := a.owner()
	if id := addAccount(t, owner, "anna", "viewer"); id != "2" {
		t.Fatalf("anna got the id %s of another account", id)
	}
}

func TestTheAppHearsEveryChangeBeforeItIsWritten(t *testing.T) {
	ch := &changes{}
	a := newApp(t, manyAccounts, ch.option)
	owner := a.owner()
	id := addAccount(t, owner, "anna", "viewer")
	want(t, owner.api("PATCH", "accounts/"+id, map[string]any{"name": "anna b", "role": "admin", "blocked": true}), 200, "")
	want(t, owner.api("DELETE", "accounts/"+id, nil), 200, "")
	got := strings.Join(ch.kinds(), " ")
	if got != "create:admin create:anna rename:anna b role:anna b block:anna b remove:anna b" {
		t.Fatalf("Changing heard %s", got)
	}
	want(t, owner.api("POST", "accounts", map[string]string{"name": "refused", "password": "a password long enough", "role": "viewer"}), 500, "internal")
	want(t, a.browser().api("POST", "login", map[string]string{"name": "refused", "password": "a password long enough"}), 401, "wrongPassword")
}

func TestAnAccountFromAServiceComesWithItsIdentity(t *testing.T) {
	ch := &changes{}
	a := newApp(t, manyAccounts, ch.option)
	p, id := addService(t, a, a.owner(), "pocket-id")
	p.Next(signintest.Person{Subject: "sub-ben", Name: "ben"})
	a.browser().serviceSignIn(p, id)
	c := ch.last()
	if c.Kind != signin.ChangeCreate || c.Via != signin.ViaService || c.Service != id || c.Issuer != p.URL || c.Subject != "sub-ben" || c.Role != "admin" {
		t.Fatalf("Changing heard %+v", c)
	}
}

func TestTheFirstPasswordNeverMakesASecondAccountWithTheSameName(t *testing.T) {
	a := newApp(t, manyAccounts)
	freshStore(a)
	a.cfg.Import = func(context.Context) ([]signin.Imported, error) {
		return []signin.Imported{{ID: "5", Name: "admin", Identities: []signin.ImportedIdentity{{Issuer: "https://id.example", Subject: "s", Name: "admin"}}}}, nil
	}
	a.open()
	want(t, a.browser().api("PUT", "me/password", map[string]string{"name": "Admin", "next": ownerPassword}), 409, "nameTaken")
}

func TestRemovalWaitsForTheAppBeforeTheNameIsFree(t *testing.T) {
	var stuck string
	a := newApp(t, manyAccounts)
	stuckFor(a, &stuck)
	owner := a.owner()
	stuck = addAccount(t, owner, "anna", "viewer")
	want(t, owner.api("DELETE", "accounts/"+stuck, nil), 200, "")
	want(t, owner.api("POST", "accounts", map[string]string{"name": "Anna", "password": "password of anna", "role": "viewer"}), 409, "nameTaken")
	stuck = ""
	a.open()
	addAccount(t, a.signInWith("admin", ownerPassword), "anna", "viewer")
}

func TestARemovedIDIsNotGivenOutWhileTheAppCleansUp(t *testing.T) {
	var stuck string
	var reuse atomic.Bool
	a := newApp(t, manyAccounts, func(c *signin.Config) {
		c.NewID = func() (string, error) {
			if reuse.Load() {
				reuse.Store(false)
				return stuck, nil
			}
			return fmt.Sprint(time.Now().UnixNano()), nil
		}
	})
	stuckFor(a, &stuck)
	owner := a.owner()
	stuck = addAccount(t, owner, "anna", "viewer")
	want(t, owner.api("DELETE", "accounts/"+stuck, nil), 200, "")
	reuse.Store(true)
	if id := addAccount(t, owner, "ben", "viewer"); id == stuck {
		t.Fatal("ben got the id of an account the app has not cleaned up")
	}
}

func (a *app) signInWith(name, password string) *browser {
	a.t.Helper()
	b := a.browser()
	want(a.t, b.api("POST", "login", map[string]string{"name": name, "password": password}), 200, "")
	return b
}

func TestTheAppCreatesAndRenamesAccounts(t *testing.T) {
	ch := &changes{}
	a := newApp(t, manyAccounts, ch.option)
	owner := a.owner()
	r := owner.requestTo("/app")
	acc, err := a.auth.CreateAccount(r, "anna", "password of anna", "viewer")
	if err != nil || acc.Name != "anna" || acc.Role != "viewer" || !acc.Password {
		t.Fatalf("CreateAccount = %+v, %v", acc, err)
	}
	_, err = a.auth.CreateAccount(r, "ANNA", "password of anna", "viewer")
	refusal(t, err, "nameTaken")
	if err := a.auth.RenameAccount(r, acc.ID, "anna b"); err != nil {
		t.Fatal(err)
	}
	a.signInWith("anna b", "password of anna")
	refusal(t, a.auth.RenameAccount(r, acc.ID, "admin"), "nameTaken")
}

func TestTheAppSetsAnotherAccountsPassword(t *testing.T) {
	a := newApp(t, manyAccounts)
	owner := a.owner()
	id := addAccount(t, owner, "anna", "viewer")
	anna := a.signInAs("anna")
	tok := anna.api("POST", "me/tokens", map[string]any{"name": "script", "scopes": []string{"read"}}).json(t)["value"].(string)
	if err := a.auth.SetPassword(owner.requestTo("/app"), id, "anna's next password"); err != nil {
		t.Fatal(err)
	}
	if anna.visitor().Via != "" {
		t.Fatal("anna's session outlived the new password")
	}
	script := a.browser()
	script.header.Set("Authorization", "Bearer "+tok)
	if script.visitor().Via != signin.ViaToken {
		t.Fatal("a new password took anna's token, as no password change does")
	}
	a.signInWith("anna", "anna's next password")
	if !slices.Contains(a.endedWith(), id+":password") {
		t.Fatalf("Ended = %v", a.endedWith())
	}
	a.clock.Add(11 * time.Minute)
	if err := a.auth.SetPassword(owner.requestTo("/app"), id, "anna's third password"); !errors.Is(err, signin.ErrNotFresh) {
		t.Fatalf("a stale admin set a password: %v", err)
	}
}

func TestTheAppRevokesEveryWayInOfAnAccount(t *testing.T) {
	a := newApp(t, manyAccounts)
	owner := a.owner()
	id := addAccount(t, owner, "anna", "viewer")
	anna := a.signInAs("anna")
	addPasskey(t, anna, a.authenticator())
	tok := anna.api("POST", "me/tokens", map[string]any{"name": "script", "scopes": []string{"read"}}).json(t)["value"].(string)
	if err := a.auth.Revoke(owner.requestTo("/app"), id); err != nil {
		t.Fatal(err)
	}
	script := a.browser()
	script.header.Set("Authorization", "Bearer "+tok)
	if anna.visitor().Via != "" || script.visitor().Via != "" {
		t.Fatal("a session or token outlived the revoke")
	}
	if keys, _ := a.auth.Passkeys(owner.requestTo("/app"), id); len(keys) != 0 {
		t.Fatalf("passkeys %v", keys)
	}
	if !slices.Contains(a.endedWith(), id+":revoked") {
		t.Fatalf("Ended = %v", a.endedWith())
	}
	a.signInAs("anna")
}

func TestTheAppListsAndEndsOneSessionTokenOrPasskey(t *testing.T) {
	a := newApp(t, manyAccounts)
	owner := a.owner()
	id := addAccount(t, owner, "anna", "viewer")
	anna, other := a.signInAs("anna"), a.signInAs("anna")
	addPasskey(t, anna, a.authenticator())
	anna.api("POST", "me/tokens", map[string]any{"name": "script", "scopes": []string{"read"}})
	r := owner.requestTo("/app")

	sessions, err := a.auth.Sessions(r, id)
	if err != nil || len(sessions) != 2 {
		t.Fatalf("Sessions = %v, %v", sessions, err)
	}
	if err := a.auth.EndSession(r, id, other.visitorSession(t)); err != nil {
		t.Fatal(err)
	}
	if other.visitor().Via != "" || anna.visitor().Via == "" {
		t.Fatal("EndSession ended the wrong session")
	}
	refusal(t, a.auth.EndSession(r, owner.visitorSession(t), anna.visitorSession(t)), "notFound")

	tokens, err := a.auth.Tokens(r, id)
	if err != nil || len(tokens) != 1 {
		t.Fatalf("Tokens = %v, %v", tokens, err)
	}
	if err := a.auth.RevokeToken(r, id, tokens[0].ID); err != nil {
		t.Fatal(err)
	}
	if tokens, _ := a.auth.Tokens(r, id); len(tokens) != 0 {
		t.Fatalf("Tokens after the revoke = %v", tokens)
	}

	keys, err := a.auth.Passkeys(r, id)
	if err != nil || len(keys) != 1 {
		t.Fatalf("Passkeys = %v, %v", keys, err)
	}
	if err := a.auth.RemovePasskey(r, id, keys[0].ID); err != nil {
		t.Fatal(err)
	}
	if keys, _ := a.auth.Passkeys(r, id); len(keys) != 0 {
		t.Fatalf("Passkeys after the removal = %v", keys)
	}
}

func (b *browser) visitorSession(t *testing.T) string {
	t.Helper()
	v, _ := signin.From(b.requestTo("/app").Context())
	if v.Session() == "" {
		t.Fatal("the browser has no session")
	}
	return v.Session()
}

func TestOnlyAnAdminChangesAccountsFromTheApp(t *testing.T) {
	a := newApp(t, manyAccounts)
	owner := a.owner()
	id := addAccount(t, owner, "anna", "viewer")
	tok := owner.api("POST", "me/tokens", map[string]any{"name": "script", "scopes": []string{"all"}}).json(t)["value"].(string)
	script := a.browser()
	script.header.Set("Authorization", "Bearer "+tok)
	refusal(t, a.auth.SetBlocked(a.signInAs("anna").requestTo("/app"), id, true), "forbidden")
	refusal(t, a.auth.SetBlocked(script.requestTo("/app"), id, true), "notWithToken")
	refusal(t, a.auth.SetBlocked(a.browser().requestTo("/app"), id, true), "signInFirst")
	_, err := a.auth.Sessions(a.signInAs("anna").requestTo("/app"), id)
	refusal(t, err, "forbidden")
}

func TestTheAppCannotChangeTheOwner(t *testing.T) {
	a := newApp(t, manyAccounts)
	owner := a.owner()
	me := owner.visitor().Account
	addAccount(t, owner, "anna", "admin")
	r := a.signInAs("anna").requestTo("/app")
	refusal(t, a.auth.SetRole(r, me, "viewer"), "accountOwner")
	refusal(t, a.auth.SetBlocked(r, me, true), "accountOwner")
	refusal(t, a.auth.SetPassword(r, me, "a password of my choosing"), "accountOwner")
	refusal(t, a.auth.Revoke(r, me), "accountOwner")
	refusal(t, a.auth.RemoveAccount(r, me), "accountOwner")
	refusal(t, a.auth.RenameAccount(r, me, "former owner"), "accountOwner")
	if owner.visitor().Via == "" {
		t.Fatal("the owner was signed out")
	}
}

func TestEndingsDoNotStopWithTheRequest(t *testing.T) {
	var live atomic.Bool
	a := newApp(t, manyAccounts)
	a.cfg.Hooks.Ended = func(ctx context.Context, _ string, what signin.Ending) error {
		if what == signin.EndBlocked {
			live.Store(ctx.Err() == nil)
		}
		return ctx.Err()
	}
	a.open()
	owner := a.owner()
	id := addAccount(t, owner, "anna", "viewer")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := a.auth.SetBlocked(owner.requestTo("/app").WithContext(ctx), id, true); err != nil {
		t.Fatal(err)
	}
	if !live.Load() {
		t.Fatal("the ending ran with the cancelled context of its request")
	}
}

func TestAliveFollowsEverySessionRule(t *testing.T) {
	a := newApp(t, manyAccounts)
	owner := a.owner()
	ctx := context.Background()
	id := addAccount(t, owner, "anna", "viewer")
	anna := a.signInAs("anna")
	s := anna.visitorSession(t)
	if !a.auth.Alive(ctx, s) {
		t.Fatal("a fresh session is not alive")
	}
	want(t, owner.api("PATCH", "accounts/"+id, map[string]any{"blocked": true}), 200, "")
	if a.auth.Alive(ctx, s) {
		t.Fatal("the session of a blocked account is alive")
	}
	idle := owner.visitorSession(t)
	a.clock.Add(8 * 24 * time.Hour)
	if a.auth.Alive(ctx, idle) {
		t.Fatal("a session a week without use is alive")
	}

	b := newApp(t)
	p, svc := addService(t, b, b.owner(), "pocket-id")
	p.Next(ownerAtService)
	viaService := b.browser()
	viaService.serviceSignIn(p, svc)
	vs := viaService.visitorSession(t)
	b.clock.Add(25 * time.Hour)
	if b.auth.Alive(ctx, vs) {
		t.Fatal("a session the service last confirmed a day ago is alive")
	}
}

func TestATokenHasNoSession(t *testing.T) {
	a := newApp(t)
	owner := a.owner()
	tok := owner.api("POST", "me/tokens", map[string]any{"name": "script", "scopes": []string{"read"}}).json(t)["value"].(string)
	if v, ok := a.auth.TokenVisitor(context.Background(), tok); !ok || v.Via != signin.ViaToken || v.Session() != "" || v.Scopes[0] != "read" {
		t.Fatalf("TokenVisitor = %+v, %v", v, ok)
	}
	if _, ok := a.auth.TokenVisitor(context.Background(), tok+"x"); ok {
		t.Fatal("a spoilt token found a visitor")
	}
}

func TestAccountShowsWhatTheAppNeeds(t *testing.T) {
	a := newApp(t)
	b := a.owner()
	id := b.visitor().Account
	ctx := context.Background()
	before, err := a.auth.Account(ctx, id)
	if err != nil || !before.Owner || !before.Password || before.TwoFactor || before.Blocked || before.Role != "admin" {
		t.Fatalf("Account = %+v, %v", before, err)
	}
	twoFactor(t, a, b)
	after, _ := a.auth.Account(ctx, id)
	if !after.TwoFactor || after.Epoch <= before.Epoch {
		t.Fatalf("after two-factor Account = %+v, before %+v", after, before)
	}
	if _, err := a.auth.Account(ctx, "nobody"); !errors.Is(err, signin.ErrNotFound) {
		t.Fatalf("an unknown account: %v", err)
	}
}

func TestCheckPasswordLetsInOnlyWhatThePasswordAloneWould(t *testing.T) {
	a := newApp(t, manyAccounts)
	owner := a.owner()
	id := addAccount(t, owner, "anna", "viewer")
	addAccount(t, owner, "ben", "viewer")
	r := a.browser().requestTo("/dav")
	v, err := a.auth.CheckPassword(r, "dav", "anna", "password of anna")
	if err != nil || v.Account != id || v.Via != signin.ViaPassword || v.Session() != "" {
		t.Fatalf("CheckPassword = %+v, %v", v, err)
	}
	_, err = a.auth.CheckPassword(r, "dav", "anna", "wrong password")
	refusal(t, err, "wrongPassword")
	twoFactor(t, a, a.signInAs("ben"))
	_, err = a.auth.CheckPassword(r, "dav", "ben", "password of ben")
	refusal(t, err, "wrongPassword")
	want(t, owner.api("PATCH", "accounts/"+id, map[string]any{"blocked": true}), 200, "")
	_, err = a.auth.CheckPassword(r, "dav", "anna", "password of anna")
	refusal(t, err, "wrongPassword")
}

func TestCheckPasswordWaitsInBucketsOfItsOwn(t *testing.T) {
	a := newApp(t, manyAccounts)
	owner := a.owner()
	addAccount(t, owner, "anna", "viewer")
	r := a.browser().requestTo("/dav")
	for range 6 {
		_, _ = a.auth.CheckPassword(r, "dav", "anna", "wrong password")
	}
	_, err := a.auth.CheckPassword(r, "dav", "anna", "password of anna")
	refusal(t, err, "throttled")
	a.signInAs("anna")
	if _, err := a.auth.CheckPassword(r, "other", "anna", "password of anna"); err != nil {
		t.Fatalf("another bucket waits too: %v", err)
	}
}

func TestCheckPasswordWritesAnOldPasswordAnew(t *testing.T) {
	old := &oldApp{}
	a := newApp(t, old.option(oldOwner()))
	if _, err := a.auth.CheckPassword(a.browser().requestTo("/dav"), "dav", "", ownerPassword); err != nil {
		t.Fatal(err)
	}
	a.signIn()
	if n := old.checks.Load(); n != 1 {
		t.Fatalf("the old check ran %d times", n)
	}
}

func TestThePasswordStaysWhileOtherAccountsSignIn(t *testing.T) {
	a := newApp(t, manyAccounts)
	owner := a.owner()
	addAccount(t, owner, "anna", "viewer")
	want(t, owner.api("DELETE", "me/password", map[string]string{"current": ownerPassword}), 409, "othersSignIn")
	a.signInAs("anna")
	if a.auth.Anyone() {
		t.Fatal("the app opened")
	}

	b := newApp(t, manyAccounts)
	admin := b.owner()
	p, id := addService(t, b, admin, "pocket-id")
	p.Next(signintest.Person{Subject: "sub-ben", Name: "ben"})
	b.browser().serviceSignIn(p, id)
	want(t, admin.api("DELETE", "me/password", map[string]string{"current": ownerPassword}), 409, "othersSignIn")
}
