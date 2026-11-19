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
	// Session reads the app's old session cookie from r and returns the
	// account and when it was issued. The guard accepts it once and swaps
	// it for a new session in the same response.
	Session func(r *http.Request) (account string, issued time.Time, ok bool)
	// SessionLife is how long the app's old sessions lasted. An old session
	// counts only up to its issue plus this, and never after the account's
	// first epoch in the package.
	SessionLife time.Duration
	// Recovery checks code against one imported recovery code hash.
	Recovery func(hash, code string) bool
	// Token returns the digest the app stored for an incoming token in its
	// old form, so the imported token is found.
	Token func(token string) (digest string, ok bool)
	// Drop removes the app's old fields for account once the package
	// ended its sessions for the first time, so going back to the version
	// before cannot bring an ended password or token back.
	Drop func(ctx context.Context, account string) error
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
type ImportedIdentity struct {
	Issuer  string
	Subject string
	Name    string
}

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
		acc := &account{
			ID: in.ID, Name: strings.TrimSpace(in.Name), Role: in.Role, Owner: in.Owner, Via: ViaPassword,
			Created: in.Created, LegacyPassword: in.Password, TOTPLast: in.TOTPLast,
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

// swap marks an old session that was swapped for a new one.
type swap struct {
	At time.Time `json:"at"`
}

// byOldSession accepts the app's old session cookie for an imported account
// and swaps it for a session of the package. It counts once, so signing out
// of the new session cannot bring the old one back, and only for a session
// issued before the import, within its old life, and until the account's
// first epoch.
func (a *Auth) byOldSession(w http.ResponseWriter, r *http.Request) (Visitor, bool) {
	if a.cfg.Legacy.Session == nil || a.imported.IsZero() {
		return Visitor{}, false
	}
	id, issued, good := a.cfg.Legacy.Session(r)
	if !good || !issued.Before(a.imported) {
		return Visitor{}, false
	}
	ends := issued.Add(a.cfg.Legacy.SessionLife)
	if !a.now().Before(ends) {
		return Visitor{}, false
	}
	ctx := r.Context()
	a.mu.Lock()
	defer a.mu.Unlock()
	acc, err := a.account(ctx, id)
	if err != nil || acc.Blocked || acc.Epoch != 0 || !acc.Imported {
		return Visitor{}, false
	}
	swapped := shortID("old-session", id, issued.UTC().Format(time.RFC3339Nano))
	if a.load(ctx, kindSwapped, swapped, new(swap)) == nil {
		return Visitor{}, false
	}
	v := a.visitorOf(acc, ViaPassword, "")
	if w == nil {
		return v, true
	}
	s := sessionOf(acc, ViaPassword, "")
	s.Expires, s.SignedAt = ends, issued
	docs := append(a.newSession(w, r, nil, s), a.doc(kindSwapped, swapped, swap{At: a.now()}))
	if err := a.cfg.Store.Apply(ctx, docs...); err != nil {
		a.log.Warn("signin: swapping an old session", "err", err)
		return Visitor{}, false
	}
	v.session, v.signedAt = docs[0].ID, issued
	return v, true
}
