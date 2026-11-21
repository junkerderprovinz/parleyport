package signin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
)

// Legacy checks what an app kept in its own form before it used the
// package. Every field is optional. A value that passes is written anew in
// the package's form, so the old form fades out on its own.
type Legacy struct {
	// Password checks pw against an imported hash.
	Password func(ctx context.Context, hash, pw string) (bool, error)
	// Session reads the app's old session cookie from r. The guard swaps it
	// once for a new session in the same response, and for two minutes
	// after takes it as that session, for the requests a page sent at the
	// same time.
	Session func(r *http.Request) (OldSession, bool)
	// Recovery checks code against one imported recovery code hash.
	Recovery func(hash, code string) bool
	// Token returns the digest the app stored for an incoming token in its
	// old form, so the imported token is found.
	Token func(token string) (digest string, ok bool)
	// Drop removes the app's old fields for account once the package ended
	// one of its ways in, so going back to the version before cannot bring
	// an ended password or token back. For EndResetOther only the old
	// sessions and tokens go, since the account's password still stands;
	// for anything else every old field goes, and Drop is not called again
	// for that account. For EndRemoved it runs before Hooks.Ended. It runs
	// again, also after a restart, until it returns nil.
	Drop func(ctx context.Context, account string, what Ending) error
}

// OldSession is a session the app issued before it used the package. It
// counts only when it was issued before the import, until it expires and
// until the account's first epoch in the package.
type OldSession struct {
	Account string
	// Key tells the session apart from every other one, such as a digest
	// of its cookie.
	Key string
	// Issued is when the app issued or last renewed the cookie, SignedAt
	// when the person signed in, which decides how fresh the session is.
	Issued, SignedAt, Expires time.Time
	// Via is ViaPassword, or ViaService with the id of a service from
	// Config.Services for a session that service started, which then needs
	// the service again a day after SignedAt.
	Via     Via
	Service string
}

// Imported is one account an app had before it used the package, as its
// Import hands it over. Hashes, digests and handles stay in the app's form
// and are checked through Legacy. TOTP is the plain secret, which the
// package seals anew.
type Imported struct {
	// ID stays the account's id, so whatever the app keeps per account
	// still points at it.
	ID       string
	Name     string
	Role     string
	Owner    bool
	Password string
	TOTP     []byte
	TOTPLast int64
	Recovery []string
	// Handle is the user handle the passkeys were registered with. The
	// browser finds a passkey only with it.
	Handle     []byte
	Passkeys   []ImportedPasskey
	Tokens     []ImportedToken
	Identities []ImportedIdentity
	Created    time.Time
	// Seen is when the account last signed in.
	Seen time.Time
}

// ImportedPasskey is a passkey as WebAuthn registered it.
type ImportedPasskey struct {
	Name            string
	ID              []byte
	PublicKey       []byte // COSE
	SignCount       uint32
	AAGUID          []byte
	Transports      []string
	BackupEligible  bool
	BackupState     bool
	AttestationType string
	RPID            string
	Created         time.Time
	Used            time.Time
}

// ImportedToken is an API token by the digest the app stored, which
// Legacy.Token works out again for an incoming token.
type ImportedToken struct {
	Name    string
	Scopes  []string
	Digest  string
	Created time.Time
	Expires time.Time
}

// ImportedIdentity binds the account to a person at a sign-in service.
//
// ClaimByName is for an account the app bound to a service by name alone,
// without a subject. The first sign-in from Issuer under exactly Name binds
// its subject, once, and only while the account has no password and is not
// the owner.
type ImportedIdentity struct {
	Issuer      string
	Subject     string
	Name        string
	ClaimByName bool
}

// nameClaim waits for the first sign-in that binds an imported account by
// name.
type nameClaim struct {
	Issuer  string `json:"issuer"`
	Name    string `json:"name"`
	Account string `json:"account"`
}

func claimID(issuer, name string) string { return shortID("claim", issuer, name) }

// importAll runs Config.Import on a store without the package's documents
// and writes what it returns in one batch with the mark that the import
// ran, so it never runs twice. The caller holds mu.
func (a *Auth) importAll(ctx context.Context, m *meta) ([]Doc, error) {
	if a.cfg.Import == nil {
		return nil, nil
	}
	old, err := a.cfg.Import(ctx)
	if err != nil {
		return nil, fmt.Errorf("signin: import: %w", err)
	}
	now := a.now()
	m.Imported = now
	names := map[string]bool{}
	owners := 0
	var docs []Doc
	var first *account
	for _, in := range old {
		key := strings.ToLower(strings.TrimSpace(in.Name))
		if in.ID == "" || key == "" || names[key] {
			return nil, fmt.Errorf("signin: import: account %q has no id or a name given twice", in.Name)
		}
		names[key] = true
		if in.Owner {
			owners++
		}
		// Checked starts at the import, so tokens of an account from
		// outside keep working for a day without its service.
		acc := &account{
			ID: in.ID, Name: strings.TrimSpace(in.Name), Role: in.Role, Owner: in.Owner, Via: ViaPassword,
			Created: in.Created, Seen: in.Seen, Checked: now, LegacyPassword: in.Password, TOTPLast: in.TOTPLast,
			LegacyRecovery: in.Recovery, Handle: in.Handle, Imported: true,
		}
		if acc.Created.IsZero() {
			acc.Created = now
		}
		if !slices.Contains(a.roles, acc.Role) {
			acc.Role = a.roles[len(a.roles)-1]
		}
		if acc.Password == "" && acc.LegacyPassword == "" && len(in.Identities) > 0 {
			acc.Via = ViaService
		}
		if len(in.TOTP) > 0 {
			if acc.TOTP, err = a.sealFor("totp", acc.ID, in.TOTP); err != nil {
				return nil, err
			}
		}
		if first == nil {
			first = acc
		}
		docs = append(docs, a.doc(kindAccount, acc.ID, acc))
		for _, p := range in.Passkeys {
			docs = append(docs, a.doc(kindPasskey, passkeyID(p.ID), importedPasskey(acc.ID, p, now)))
		}
		for _, t := range in.Tokens {
			created := t.Created
			if created.IsZero() {
				created = now
			}
			docs = append(docs, a.doc(kindToken, legacyTokenID(t.Digest), apiToken{
				Account: acc.ID, Name: t.Name, Scopes: t.Scopes, Created: created, Expires: t.Expires, Digest: t.Digest, Legacy: true,
			}))
		}
		for _, id := range in.Identities {
			if id.ClaimByName {
				if in.Owner || in.Password != "" || id.Subject != "" || id.Issuer == "" || id.Name == "" {
					return nil, fmt.Errorf("signin: import: account %q cannot be claimed by name", in.Name)
				}
				docs = append(docs, a.doc(kindClaim, claimID(id.Issuer, id.Name), nameClaim{Issuer: id.Issuer, Name: id.Name, Account: acc.ID}))
				continue
			}
			docs = append(docs, a.doc(kindIdentity, identityID(identityService, id.Issuer, id.Subject), identity{
				Kind: identityService, Issuer: id.Issuer, Subject: id.Subject, Name: id.Name, Account: acc.ID, Linked: now,
			}))
		}
	}
	if owners > 1 {
		return nil, errors.New("signin: import: more than one owner")
	}
	if a.cfg.Owner && owners == 0 && len(old) > 1 {
		return nil, errors.New("signin: import: an app with one owner needs one account marked Owner")
	}
	if owners == 0 && len(old) == 1 && a.cfg.Owner {
		first.Owner = true
		docs[0] = a.doc(kindAccount, first.ID, first)
	}
	return docs, nil
}

const swapGrace = 2 * time.Minute

// claimed is the imported account that waits for its first sign-in from
// who's issuer under exactly who's name, while it has no password. The
// caller holds mu.
func (a *Auth) claimed(ctx context.Context, who *person) (*account, error) {
	c := new(nameClaim)
	err := a.load(ctx, kindClaim, claimID(who.issuer, who.name), c)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	acc, err := a.account(ctx, c.Account)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil || acc.hasPassword() {
		return nil, err
	}
	return acc, nil
}

// swap marks an old session that was swapped for the session of the
// package with the id Session.
type swap struct {
	At      time.Time `json:"at"`
	Session string    `json:"session,omitempty"`
}

// byOldSession accepts the app's old session cookie for an imported account
// and swaps it for a session of the package. It swaps once, so signing out
// of the new session cannot bring the old one back.
func (a *Auth) byOldSession(w http.ResponseWriter, r *http.Request) (Visitor, bool) {
	if a.cfg.Legacy.Session == nil || a.imported.IsZero() {
		return Visitor{}, false
	}
	old, good := a.cfg.Legacy.Session(r)
	now := a.now()
	if !good || old.Key == "" || old.Issued.IsZero() || !old.Issued.Before(a.imported) || !now.Before(old.Expires) {
		return Visitor{}, false
	}
	if old.Via != ViaService {
		old.Via, old.Service = ViaPassword, ""
	}
	if old.SignedAt.IsZero() {
		old.SignedAt = old.Issued
	}
	ctx := r.Context()
	a.mu.Lock()
	defer a.mu.Unlock()
	swapped := shortID("old-session", old.Key)
	if sw := new(swap); a.load(ctx, kindSwapped, swapped, sw) == nil {
		if sw.Session == "" || now.Sub(sw.At) >= swapGrace {
			return Visitor{}, false
		}
		v, _, _, err := a.session(ctx, sw.Session)
		return v, err == nil
	}
	acc, err := a.account(ctx, old.Account)
	if err != nil || acc.Blocked || acc.Epoch != 0 || !acc.Imported {
		return Visitor{}, false
	}
	s := sessionOf(acc, old.Via, old.Service)
	s.Expires, s.SignedAt = old.Expires, old.SignedAt
	if old.Via == ViaService {
		s.Checked = old.SignedAt
	}
	// A session of a sign-in service that needs the service again is still
	// swapped, so the next request can renew it.
	current := old.Via != ViaService || now.Sub(s.Checked) <= serviceLife
	if w == nil {
		v := a.visitorOf(acc, old.Via, old.Service)
		v.signedAt = old.SignedAt
		return v, current
	}
	docs := a.newSession(w, r, nil, s)
	docs = append(docs, a.doc(kindSwapped, swapped, swap{At: now, Session: docs[0].ID}))
	if err := a.cfg.Store.Apply(ctx, docs...); err != nil {
		a.log.Warn("signin: swapping an old session", "err", err)
		return Visitor{}, false
	}
	if !current {
		return Visitor{}, false
	}
	v := a.visitorOf(acc, old.Via, old.Service)
	v.session, v.signedAt = docs[0].ID, old.SignedAt
	return v, true
}
