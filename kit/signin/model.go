package signin

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// The kinds of documents in the store.
const (
	kindMeta     = "meta"
	kindAccount  = "account"
	kindSession  = "session"
	kindToken    = "token"
	kindPasskey  = "passkey"
	kindIdentity = "identity"
	kindService  = "service"
	kindLog      = "log"
	kindEnding   = "ending"
	kindSwapped  = "swapped"

	metaID = "signin"
)

type meta struct {
	Version  int       `json:"version"`
	Created  time.Time `json:"created"`
	Imported time.Time `json:"imported,omitzero"`
}

type account struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Role    string    `json:"role"`
	Owner   bool      `json:"owner,omitempty"`
	Via     Via       `json:"via"`
	Service string    `json:"service,omitempty"`
	Created time.Time `json:"created"`
	Seen    time.Time `json:"seen,omitzero"`
	Blocked bool      `json:"blocked,omitempty"`
	// Epoch counts the events that end every session of the account.
	Epoch int `json:"epoch"`

	Password       string `json:"password,omitempty"`
	LegacyPassword string `json:"legacyPassword,omitempty"`

	TOTP          []byte    `json:"totp,omitempty"`
	TOTPLast      int64     `json:"totpLast,omitempty"`
	TOTPPending   []byte    `json:"totpPending,omitempty"`
	TOTPPendingAt time.Time `json:"totpPendingAt,omitzero"`
	Recovery      []string  `json:"recovery,omitempty"`
	// LegacyRecovery are recovery codes in the app's old form, checked by
	// Legacy.Recovery until new codes are made.
	LegacyRecovery []string `json:"legacyRecovery,omitempty"`

	Handle []byte `json:"handle,omitempty"`

	Groups []string `json:"groups,omitempty"`
	// Checked is when a sign-in service last let the account in. Tokens of
	// an account from outside rest when it is too long ago.
	Checked time.Time `json:"checked,omitzero"`
	// Imported marks an account whose old fields the app still keeps, for
	// Legacy.Drop after its first epoch.
	Imported bool `json:"imported,omitempty"`
}

func (acc *account) hasPassword() bool { return acc.Password != "" || acc.LegacyPassword != "" }

func (acc *account) twoFactor() bool { return len(acc.TOTP) > 0 }

type session struct {
	Account  string    `json:"account"`
	Via      Via       `json:"via"`
	Service  string    `json:"service,omitempty"`
	Created  time.Time `json:"created"`
	Seen     time.Time `json:"seen"`
	Expires  time.Time `json:"expires"`
	SignedAt time.Time `json:"signedAt"`
	// Checked is when the sign-in service last confirmed a session of
	// ViaService. After a day the session needs the service again.
	Checked time.Time `json:"checked,omitzero"`
	Epoch   int       `json:"epoch"`
	From    string    `json:"from,omitempty"`
	Agent   string    `json:"agent,omitempty"`
}

type apiToken struct {
	Account string    `json:"account"`
	Name    string    `json:"name"`
	Scopes  []string  `json:"scopes"`
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires,omitzero"`
	Used    time.Time `json:"used,omitzero"`
	Digest  string    `json:"digest"`
	Legacy  bool      `json:"legacy,omitempty"`
}

func (a *Auth) doc(kind, id string, v any) Doc {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("signin: %s does not marshal: %v", kind, err))
	}
	return Doc{Kind: kind, ID: id, Data: b}
}

func gone(kind, id string) Doc { return Doc{Kind: kind, ID: id} }

func (a *Auth) load(ctx context.Context, kind, id string, v any) error {
	b, err := a.cfg.Store.Get(ctx, kind, id)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("signin: %s %q: %w", kind, id, err)
	}
	return nil
}

func listOf[T any](ctx context.Context, a *Auth, kind string) (map[string]*T, []string, error) {
	docs, err := a.cfg.Store.List(ctx, kind)
	if err != nil {
		return nil, nil, err
	}
	out := make(map[string]*T, len(docs))
	ids := make([]string, 0, len(docs))
	for _, d := range docs {
		v := new(T)
		if err := json.Unmarshal(d.Data, v); err != nil {
			return nil, nil, fmt.Errorf("signin: %s %q: %w", kind, d.ID, err)
		}
		out[d.ID] = v
		ids = append(ids, d.ID)
	}
	return out, ids, nil
}

func (a *Auth) accounts(ctx context.Context) ([]*account, error) {
	m, ids, err := listOf[account](ctx, a, kindAccount)
	if err != nil {
		return nil, err
	}
	out := make([]*account, 0, len(ids))
	for _, id := range ids {
		out = append(out, m[id])
	}
	return out, nil
}

func (a *Auth) account(ctx context.Context, id string) (*account, error) {
	acc := new(account)
	if err := a.load(ctx, kindAccount, id, acc); err != nil {
		return nil, err
	}
	return acc, nil
}

// byName finds the account with name, ignoring case.
func (a *Auth) byName(ctx context.Context, name string) (*account, error) {
	all, err := a.accounts(ctx)
	if err != nil {
		return nil, err
	}
	for _, acc := range all {
		if strings.EqualFold(acc.Name, name) {
			return acc, nil
		}
	}
	return nil, fmt.Errorf("account %q: %w", name, ErrNotFound)
}

func (a *Auth) owner(ctx context.Context) (*account, error) {
	all, err := a.accounts(ctx)
	if err != nil {
		return nil, err
	}
	for _, acc := range all {
		if acc.Owner {
			return acc, nil
		}
	}
	return nil, fmt.Errorf("owner: %w", ErrNotFound)
}

// label is the domain the package seals and MACs one kind of value under.
func (a *Auth) label(kind string) string { return a.d + "/signin/" + kind + "/v1" }

func (a *Auth) mac(kind string, data []byte) []byte { return a.cfg.Seal.MAC(a.label(kind), data) }

func (a *Auth) macHex(kind, data string) string { return hex.EncodeToString(a.mac(kind, []byte(data))) }

func (a *Auth) passwordInput(pw string) []byte { return a.mac("password", []byte(pw)) }

// sealFor seals a value of kind that belongs to owner, so it never opens
// under another account or kind.
func (a *Auth) sealFor(kind, owner string, plain []byte) ([]byte, error) {
	return a.cfg.Seal.Seal(a.label(kind)+"|"+owner, plain)
}

func (a *Auth) openFor(kind, owner string, sealed []byte) ([]byte, error) {
	return a.cfg.Seal.Open(a.label(kind)+"|"+owner, sealed)
}

// shortID is a stable id for a key that must not show in the store as is.
func shortID(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:16])
}

const (
	identityService = "service"
)

// identity binds a person at a sign-in service, by issuer and subject, to
// one account. It never goes by a name the account happens to share.
type identity struct {
	Kind    string    `json:"kind"`
	Service string    `json:"service,omitempty"`
	Issuer  string    `json:"issuer,omitempty"`
	Subject string    `json:"subject"`
	Name    string    `json:"name,omitempty"`
	Account string    `json:"account"`
	Linked  time.Time `json:"linked"`
	Seen    time.Time `json:"seen,omitzero"`
}

func identityID(kind, issuer, subject string) string { return shortID(kind, issuer, subject) }

type passkeyDoc struct {
	Account    string              `json:"account"`
	Name       string              `json:"name"`
	Created    time.Time           `json:"created"`
	Used       time.Time           `json:"used,omitzero"`
	RPID       string              `json:"rpID"`
	Credential webauthn.Credential `json:"credential"`
}

func passkeyID(credential []byte) string { return base64.RawURLEncoding.EncodeToString(credential) }

func importedPasskey(account string, p ImportedPasskey, now time.Time) passkeyDoc {
	created := p.Created
	if created.IsZero() {
		created = now
	}
	c := webauthn.Credential{
		ID: p.ID, PublicKey: p.PublicKey, AttestationType: p.AttestationType,
		Flags:         webauthn.CredentialFlags{UserPresent: true, UserVerified: true, BackupEligible: p.BackupEligible, BackupState: p.BackupState},
		Authenticator: webauthn.Authenticator{AAGUID: p.AAGUID, SignCount: p.SignCount},
	}
	for _, t := range p.Transports {
		c.Transport = append(c.Transport, protocol.AuthenticatorTransport(t))
	}
	return passkeyDoc{Account: account, Name: p.Name, Created: created, RPID: p.RPID, Credential: c}
}
