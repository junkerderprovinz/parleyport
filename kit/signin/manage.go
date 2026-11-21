package signin

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/junkerderprovinz/parleyport/kit/signin/internal/password"
)

// The account methods are the contract's account routes for an app with
// screens of its own. r is the admin's request through Guard, the rules are
// those of the routes, and what they refuse comes back as a *Refusal.

// admin returns what Guard found for r when it is an admin signed in as an
// account.
func (a *Auth) admin(r *http.Request) (*found, error) {
	f := a.foundIn(r)
	switch {
	case !f.ok:
		return nil, refuse(http.StatusUnauthorized, "signInFirst")
	case f.v.Via == ViaToken:
		return nil, refuse(http.StatusForbidden, "notWithToken")
	case f.v.Via == ViaAnyone:
		return nil, refuse(http.StatusConflict, "setPasswordFirst")
	case f.v.Via == ViaDoor || !f.v.AtLeast(a.roles[0]):
		return nil, refuse(http.StatusForbidden, "forbidden")
	}
	return f, nil
}

// Session is the id of the session the visitor came in through, empty for
// a token or a door. Alive tells whether it still counts.
func (v Visitor) Session() string { return v.session }

// Alive reports whether the session id still counts, under every rule a
// session keeps, for work that outlasts a request such as a terminal.
func (a *Auth) Alive(ctx context.Context, id string) bool {
	_, _, _, err := a.session(ctx, id)
	return id != "" && err == nil
}

// Account returns the account id, or an error wrapping ErrNotFound.
func (a *Auth) Account(ctx context.Context, id string) (Account, error) {
	acc, err := a.account(ctx, id)
	if err != nil {
		return Account{}, err
	}
	return a.viewOf(acc), nil
}

// TokenVisitor returns who the API token raw stands for, for a way in of
// the app's own that carries a token elsewhere than in the Authorization
// header, such as a password field.
func (a *Auth) TokenVisitor(ctx context.Context, raw string) (Visitor, bool) {
	return a.byToken(ctx, raw)
}

// CheckPassword checks a password the app takes outside the sign-in page,
// such as HTTP Basic credentials. It waits under the same rules as a
// sign-in, in buckets of its own that bucket names, and refuses with
// wrongPassword whatever the password alone would not sign in: a wrong
// password, a blocked account and one with two-factor.
func (a *Auth) CheckPassword(r *http.Request, bucket, name, pw string) (Visitor, error) {
	if a.Anyone() {
		return Visitor{}, refuse(http.StatusConflict, "setPasswordFirst")
	}
	ctx := r.Context()
	now := a.now()
	addr := addressKey(a.client(r))
	if addr != "" {
		addr = bucket + "|" + addr
	}
	nameKey := bucket + "|name:" + strings.ToLower(strings.TrimSpace(name))
	if a.cfg.Owner {
		nameKey = bucket + "|name:owner"
	}
	if max(a.limits.wait(perAddress, addr, now), a.limits.wait(perName, nameKey, now)) > 0 {
		return Visitor{}, refuse(http.StatusTooManyRequests, "throttled")
	}
	acc, err := a.signInAccount(ctx, name)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return Visitor{}, err
	}
	good := false
	if acc != nil {
		good, err = a.checkPassword(ctx, acc, pw)
	} else {
		err = a.burn(ctx)
	}
	if errors.Is(err, errBusy) {
		return Visitor{}, refuse(http.StatusTooManyRequests, "throttled")
	}
	if err != nil {
		return Visitor{}, err
	}
	if !good {
		a.limits.fail(perAddress, addr, now)
		a.limits.fail(perName, nameKey, now)
		e := Entry{Name: a.typedName(ctx, name), Via: ViaPassword, Result: "wrongPassword"}
		if acc != nil {
			e.Account, e.Name = acc.ID, acc.Name
		}
		a.note(ctx, r, e)
		return Visitor{}, refuse(http.StatusUnauthorized, "wrongPassword")
	}
	a.limits.clear(nameKey)
	if acc.Password == "" || !password.Current(acc.Password) {
		a.rehash(ctx, acc, pw)
	}
	if acc.Blocked || acc.twoFactor() {
		return Visitor{}, refuse(http.StatusUnauthorized, "wrongPassword")
	}
	return a.visitorOf(acc, ViaPassword, ""), nil
}

// CreateAccount adds a local account with a password. It wants a fresh
// sign-in of the admin, as a new lasting way in does.
func (a *Auth) CreateAccount(r *http.Request, name, password, role string) (Account, error) {
	if _, err := a.admin(r); err != nil {
		return Account{}, err
	}
	acc, err := a.createAccount(r, name, password, role)
	if err != nil {
		return Account{}, err
	}
	return a.viewOf(acc), nil
}

// RenameAccount gives the account id another name, which no other account
// holds in any case.
func (a *Auth) RenameAccount(r *http.Request, id, name string) error {
	return a.change(r, id, accountChange{Name: &name})
}

// SetRole gives the account id another role. A lower one ends its sessions
// and tokens.
func (a *Auth) SetRole(r *http.Request, id, role string) error {
	return a.change(r, id, accountChange{Role: &role})
}

// SetBlocked blocks or unblocks the account id. Blocking ends its sessions
// and tokens.
func (a *Auth) SetBlocked(r *http.Request, id string, blocked bool) error {
	return a.change(r, id, accountChange{Blocked: &blocked})
}

func (a *Auth) change(r *http.Request, id string, in accountChange) error {
	f, err := a.admin(r)
	if err != nil {
		return err
	}
	_, err = a.changeAccount(r, f, id, in)
	return err
}

// RemoveAccount removes the account id and every way in it had.
func (a *Auth) RemoveAccount(r *http.Request, id string) error {
	f, err := a.admin(r)
	if err != nil {
		return err
	}
	return a.removeAccount(r, f, id)
}

// SetPassword gives the local account id a new password, which ends its
// sessions as a password change does and leaves its tokens. It wants a
// fresh sign-in of the admin.
func (a *Auth) SetPassword(r *http.Request, id, password string) error {
	f, err := a.admin(r)
	if err != nil {
		return err
	}
	if err := a.newPassword(password); err != nil {
		return err
	}
	hash, err := a.hashPassword(password)
	if err != nil {
		return err
	}
	ctx := r.Context()
	err = a.Mint(r, func() error {
		acc, err := a.otherAccount(ctx, f, id)
		if err != nil {
			return err
		}
		if !acc.hasPassword() {
			return refuse(http.StatusForbidden, "notLocal")
		}
		acc.Password, acc.LegacyPassword = hash, ""
		acc.Epoch++
		return a.cfg.Store.Apply(ctx, append(a.endingsOf(acc, EndPassword), a.doc(kindAccount, acc.ID, acc))...)
	})
	if err == nil {
		a.runEndings(ctx)
	}
	return err
}

// Revoke ends every session, token and passkey of the account id, which
// keeps its password.
func (a *Auth) Revoke(r *http.Request, id string) error {
	f, err := a.admin(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	err = a.locked(ctx, f, func() error {
		acc, err := a.otherAccount(ctx, f, id)
		if err != nil {
			return err
		}
		docs, err := a.endAll(r, acc.ID)
		if err != nil {
			return err
		}
		passkeys, err := a.wipe(ctx, kindPasskey, owned(acc.ID))
		if err != nil {
			return err
		}
		acc.Epoch++
		docs = append(append(docs, passkeys...), a.endingsOf(acc, EndRevoked)...)
		return a.cfg.Store.Apply(ctx, append(docs, a.doc(kindAccount, acc.ID, acc))...)
	})
	if err == nil {
		a.runEndings(ctx)
	}
	return err
}

// otherAccount loads the account id for a change by the admin f, which may
// not touch the owner. The caller holds mu.
func (a *Auth) otherAccount(ctx context.Context, f *found, id string) (*account, error) {
	acc, err := a.account(ctx, id)
	if err != nil {
		return nil, err
	}
	if acc.Owner {
		return nil, refuse(http.StatusForbidden, "accountOwner")
	}
	return acc, nil
}

// locked runs fn under mu while the admin f still counts.
func (a *Auth) locked(ctx context.Context, f *found, fn func() error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.stillValid(ctx, f); err != nil {
		return refuse(http.StatusUnauthorized, "signInFirst")
	}
	return fn()
}

// Sessions lists the sessions of the account id that still count.
func (a *Auth) Sessions(r *http.Request, id string) ([]Session, error) {
	f, err := a.admin(r)
	if err != nil {
		return nil, err
	}
	acc, err := a.account(r.Context(), id)
	if err != nil {
		return nil, err
	}
	return a.sessionsOf(r, acc.ID, acc.Epoch, f.v.session)
}

// EndSession ends the session sid of the account id.
func (a *Auth) EndSession(r *http.Request, id, sid string) error {
	f, err := a.admin(r)
	if err != nil {
		return err
	}
	return a.locked(r.Context(), f, func() error { return a.endOwnSession(r.Context(), id, sid) })
}

// Tokens lists the API tokens of the account id.
func (a *Auth) Tokens(r *http.Request, id string) ([]Token, error) {
	if _, err := a.admin(r); err != nil {
		return nil, err
	}
	return a.tokensOf(r.Context(), id)
}

// RevokeToken deletes the API token tid of the account id.
func (a *Auth) RevokeToken(r *http.Request, id, tid string) error {
	f, err := a.admin(r)
	if err != nil {
		return err
	}
	err = a.locked(r.Context(), f, func() error { return a.removeToken(r.Context(), id, tid) })
	if err == nil {
		a.runEndings(r.Context())
	}
	return err
}

// Passkeys lists the passkeys of the account id.
func (a *Auth) Passkeys(r *http.Request, id string) ([]Passkey, error) {
	if _, err := a.admin(r); err != nil {
		return nil, err
	}
	return a.passkeyList(r, id)
}

// RemovePasskey removes the passkey pid of the account id.
func (a *Auth) RemovePasskey(r *http.Request, id, pid string) error {
	f, err := a.admin(r)
	if err != nil {
		return err
	}
	err = a.locked(r.Context(), f, func() error { return a.removePasskey(r.Context(), id, pid) })
	if err == nil {
		a.runEndings(r.Context())
	}
	return err
}
