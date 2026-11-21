package signin_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/signin"
	"github.com/junkerderprovinz/parleyport/kit/signin/signintest"
)

// withClaim imports the owner with a password and anna, who signed in only
// through the sign-in service at issuer and was never bound to a subject.
func withClaim(t *testing.T, issuer string, change ...func(*signin.Imported)) *app {
	t.Helper()
	old := &oldApp{}
	anna := signin.Imported{ID: "8", Name: "anna", Role: "viewer", Identities: []signin.ImportedIdentity{{Issuer: issuer, Name: "anna", ClaimByName: true}}}
	for _, c := range change {
		c(&anna)
	}
	return newApp(t, manyAccounts, func(c *signin.Config) {
		old.option(oldOwner())(c)
		c.Import = func(context.Context) ([]signin.Imported, error) { return []signin.Imported{oldOwner(), anna}, nil }
	})
}

func TestAnUnboundImportedAccountIsClaimedOnceByName(t *testing.T) {
	p := signintest.NewProvider(t)
	a := withClaim(t, p.URL)
	id := addProvider(t, a.signInOwner(), p, "/settings")
	p.Next(signintest.Person{Subject: "sub-anna", Name: "anna"})
	b := a.browser()
	b.serviceSignIn(p, id)
	if v := b.visitor(); v.Account != "8" || v.Via != signin.ViaService {
		t.Fatalf("anna's first sign-in is %+v", v)
	}
	p.Next(signintest.Person{Subject: "sub-other", Name: "anna"})
	if got := a.browser().serviceSignIn(p, id); got != "/home?signin=nameTaken" {
		t.Fatalf("a second person named anna ended at %s", got)
	}
	p.Next(signintest.Person{Subject: "sub-anna", Name: "anna at home"})
	c := a.browser()
	c.serviceSignIn(p, id)
	if v := c.visitor(); v.Account != "8" {
		t.Fatalf("the claimed binding did not last: %+v", v)
	}
}

func TestAClaimByNameNeedsTheExactName(t *testing.T) {
	p := signintest.NewProvider(t)
	a := withClaim(t, p.URL)
	id := addProvider(t, a.signInOwner(), p, "/settings")
	p.Next(signintest.Person{Subject: "sub-anna", Name: "Anna"})
	if got := a.browser().serviceSignIn(p, id); got != "/home?signin=nameTaken" {
		t.Fatalf("Anna ended at %s", got)
	}
}

func TestAClaimByNameNeedsTheSameIssuer(t *testing.T) {
	p, other := signintest.NewProvider(t), signintest.NewProvider(t)
	a := withClaim(t, p.URL)
	id := addProvider(t, a.signInOwner(), other, "/settings")
	other.Next(signintest.Person{Subject: "sub-anna", Name: "anna"})
	if got := a.browser().serviceSignIn(other, id); got != "/home?signin=nameTaken" {
		t.Fatalf("anna at another issuer ended at %s", got)
	}
}

func TestAClaimByNameNeverTakesAnAccountWithAPassword(t *testing.T) {
	a := newApp(t)
	freshStore(a)
	a.cfg = withOption(a.cfg, manyAccounts)
	a.cfg.Import = func(context.Context) ([]signin.Imported, error) {
		return []signin.Imported{oldOwner(), {ID: "8", Name: "anna", Password: "old:x", Identities: []signin.ImportedIdentity{{Issuer: "https://id.example", Name: "anna", ClaimByName: true}}}}, nil
	}
	if _, err := signin.Open(a.cfg); err == nil {
		t.Fatal("an account with a password was imported to be claimed by name")
	}

	log := &logBuffer{}
	p := signintest.NewProvider(t)
	b := withClaim(t, p.URL)
	b.cfg = withOption(b.cfg, withLog(log))
	b.open()
	id := addProvider(t, b.signInOwner(), p, "/settings")
	code := resetCode(t, b, log)
	want(t, b.browser().api("POST", "reset", map[string]string{"code": code, "name": "anna", "password": "anna's own password"}), 200, "")
	p.Next(ownerAtService)
	if got := b.signInOwner().testService(p, id); got != "/settings?signin=testOk" {
		t.Fatalf("the test sign-in after the reset ended at %s", got)
	}
	p.Next(signintest.Person{Subject: "sub-anna", Name: "anna"})
	if got := b.browser().serviceSignIn(p, id); got != "/home?signin=nameTaken" {
		t.Fatalf("a claim by name of an account with a password ended at %s", got)
	}
}

func TestAClaimByNameNeverTakesTheOwner(t *testing.T) {
	a := newApp(t)
	freshStore(a)
	owner := oldOwner()
	owner.Password = ""
	owner.Identities = []signin.ImportedIdentity{{Issuer: "https://id.example", Name: "owner", ClaimByName: true}}
	a.cfg.Import = func(context.Context) ([]signin.Imported, error) { return []signin.Imported{owner}, nil }
	if _, err := signin.Open(a.cfg); err == nil {
		t.Fatal("the owner was imported to be claimed by name")
	}
}

func TestImportedOutsideAccountsKeepTheirTokensForADay(t *testing.T) {
	ben := signin.Imported{
		ID: "9", Name: "ben", Role: "admin",
		Identities: []signin.ImportedIdentity{{Issuer: "https://id.example", Subject: "sub-ben", Name: "ben"}},
		Tokens:     []signin.ImportedToken{{Name: "backup", Scopes: []string{"read"}, Digest: "digest:old_ben"}},
	}
	old := &oldApp{}
	a := newApp(t, manyAccounts, func(c *signin.Config) {
		old.option(oldOwner())(c)
		c.Import = func(context.Context) ([]signin.Imported, error) { return []signin.Imported{oldOwner(), ben}, nil }
	})
	script := a.browser()
	script.header.Set("Authorization", "Bearer old_ben")
	if v := script.visitor(); v.Account != "9" {
		t.Fatalf("the token of an account from outside rests right after the import: %+v", v)
	}
	a.clock.Add(26 * time.Hour)
	if v := script.visitor(); v.Via != "" {
		t.Fatalf("the token works a day without the service: %+v", v)
	}
}

func TestImportKeepsWhenAccountsAndPasskeysWereLastUsed(t *testing.T) {
	seen, used := newClock().Now().Add(-48*time.Hour), newClock().Now().Add(-72*time.Hour)
	key := signintest.NewAuthenticator("")
	pk, err := key.Passkey("localhost", []byte("old handle"))
	if err != nil {
		t.Fatal(err)
	}
	pk.Used = used
	owner := oldOwner()
	owner.Seen, owner.Handle, owner.Passkeys = seen, []byte("old handle"), []signin.ImportedPasskey{pk}
	a := newApp(t, (&oldApp{}).option(owner))
	var acc struct{ Seen time.Time }
	if raw, err := a.store.Get(context.Background(), "account", "7"); err != nil || json.Unmarshal(raw, &acc) != nil || !acc.Seen.Equal(seen) {
		t.Fatalf("account %s %v", raw, err)
	}
	docs, _ := a.store.List(context.Background(), "passkey")
	var p struct{ Used time.Time }
	if len(docs) != 1 || json.Unmarshal(docs[0].Data, &p) != nil || !p.Used.Equal(used) {
		t.Fatalf("passkeys %v", docs)
	}
}
