package signin

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/junkerderprovinz/parleyport/kit/signin/internal/token"
)

func (a *Auth) getMe(w http.ResponseWriter, r *http.Request, f *found) {
	out := struct {
		Visitor
		Owner        bool `json:"owner"`
		Password     bool `json:"password"`
		TwoFactor    bool `json:"twoFactor"`
		RecoveryLeft int  `json:"recoveryLeft"`
		Fresh        bool `json:"fresh"`
	}{Visitor: f.v, Fresh: a.fresh(f)}
	if f.v.Account != "" {
		acc, err := a.account(r.Context(), f.v.Account)
		if err != nil {
			a.internal(w, err)
			return
		}
		out.Owner, out.Password, out.TwoFactor = acc.Owner, acc.hasPassword(), acc.twoFactor()
		out.RecoveryLeft = len(acc.Recovery) + len(acc.LegacyRecovery)
	}
	ok(w, out)
}

// checkNew answers when pw cannot be a password and reports whether it can.
func (a *Auth) checkNew(w http.ResponseWriter, pw string) bool {
	if len(pw) > maxPassword {
		fail(w, http.StatusBadRequest, "passwordLong")
		return false
	}
	if utf8.RuneCountInString(pw) < a.minPass {
		fail(w, http.StatusBadRequest, "passwordShort", "min", a.minPass)
		return false
	}
	return true
}

func (a *Auth) putPassword(w http.ResponseWriter, r *http.Request, f *found) {
	var in struct {
		Name    string `json:"name"`
		Current string `json:"current"`
		Next    string `json:"next"`
	}
	if !readJSON(w, r, smallBody, &in) || !a.checkNew(w, in.Next) {
		return
	}
	if f.v.Via == ViaAnyone {
		a.firstPassword(w, r, f, strings.TrimSpace(in.Name), in.Next)
		return
	}
	if f.v.Account == "" || f.v.session == "" {
		fail(w, http.StatusForbidden, "forbidden")
		return
	}
	ctx := r.Context()
	acc, err := a.account(ctx, f.v.Account)
	if err != nil {
		a.internal(w, err)
		return
	}
	if !acc.hasPassword() {
		fail(w, http.StatusForbidden, "notLocal")
		return
	}
	if !a.passwordAgain(w, r, acc, in.Current) {
		return
	}
	hash, err := a.hashPassword(in.Next)
	if err != nil {
		a.internal(w, err)
		return
	}
	a.mu.Lock()
	acc, err = a.stillValid(ctx, f)
	if err != nil {
		a.mu.Unlock()
		fail(w, http.StatusUnauthorized, "signInFirst")
		return
	}
	acc.Password, acc.LegacyPassword = hash, ""
	acc.Epoch++
	docs := []Doc{a.doc(kindAccount, acc.ID, acc), a.ending(acc.ID, EndPassword)}
	docs = append(docs, a.newSession(w, r, f, a.reissue(r, f, acc))...)
	err = a.cfg.Store.Apply(ctx, docs...)
	a.mu.Unlock()
	if err != nil {
		a.internal(w, err)
		return
	}
	a.afterEpoch(ctx, acc)
	a.note(ctx, r, Entry{Account: acc.ID, Name: acc.Name, Result: "passwordChanged"})
	ok(w, nil)
}

// passwordAgain checks the password of the signed-in account a change asks
// for again, under the same throttle as a sign-in.
func (a *Auth) passwordAgain(w http.ResponseWriter, r *http.Request, acc *account, pw string) bool {
	ctx := r.Context()
	now := a.now()
	key := "name:" + strings.ToLower(acc.Name)
	if a.cfg.Owner && acc.Owner {
		key = "name:owner"
	}
	if wait := a.limits.wait(perName, key, now); wait > 0 {
		throttled(w, wait)
		return false
	}
	good, err := a.checkPassword(ctx, acc, pw)
	if errors.Is(err, errBusy) {
		throttled(w, hashWait)
		return false
	}
	if err != nil {
		a.internal(w, err)
		return false
	}
	if !good {
		a.limits.fail(perName, key, now)
		a.note(ctx, r, Entry{Account: acc.ID, Name: acc.Name, Via: ViaPassword, Result: "wrongPassword"})
		fail(w, http.StatusUnauthorized, "wrongPassword")
		return false
	}
	a.limits.clear(key)
	return true
}

// firstPassword sets the password that closes an open app. Whoever sets it
// becomes the owner and is signed in.
func (a *Auth) firstPassword(w http.ResponseWriter, r *http.Request, f *found, name, pw string) {
	ctx := r.Context()
	if name == "" {
		name = a.roles[0]
	}
	hash, err := a.hashPassword(pw)
	if err != nil {
		a.internal(w, err)
		return
	}
	a.mu.Lock()
	if !a.open.Load() {
		a.mu.Unlock()
		fail(w, http.StatusConflict, "passwordSet")
		return
	}
	acc, err := a.owner(ctx)
	if errors.Is(err, ErrNotFound) {
		acc = &account{ID: newID(), Name: name, Role: a.roles[0], Owner: true, Via: ViaPassword, Created: a.now()}
	} else if err != nil {
		a.mu.Unlock()
		a.internal(w, err)
		return
	}
	acc.Password, acc.LegacyPassword = hash, ""
	acc.Epoch++
	docs := []Doc{a.doc(kindAccount, acc.ID, acc), a.ending(acc.ID, EndFirstPassword)}
	docs = append(docs, a.newSession(w, r, f, sessionOf(acc, ViaPassword, ""))...)
	err = a.cfg.Store.Apply(ctx, docs...)
	if err == nil {
		err = a.refreshOpen(ctx)
	}
	a.mu.Unlock()
	if err != nil {
		a.internal(w, err)
		return
	}
	a.runEndings(ctx)
	a.note(ctx, r, Entry{Account: acc.ID, Name: acc.Name, Via: ViaPassword, Result: "firstPassword"})
	ok(w, map[string]any{"visitor": a.visitorOf(acc, ViaPassword, "")})
}

// deletePassword takes the owner's password away. With no password left
// the app is open again, so every other way in goes with it.
func (a *Auth) deletePassword(w http.ResponseWriter, r *http.Request, f *found) {
	var in struct {
		Current string `json:"current"`
	}
	if !readJSON(w, r, smallBody, &in) {
		return
	}
	ctx := r.Context()
	acc, err := a.account(ctx, f.v.Account)
	if err != nil {
		a.internal(w, err)
		return
	}
	if !acc.Owner || !acc.hasPassword() {
		fail(w, http.StatusForbidden, "notOwner")
		return
	}
	if !a.passwordAgain(w, r, acc, in.Current) {
		return
	}
	a.mu.Lock()
	docs, err := a.openUp(ctx)
	if err == nil {
		err = a.cfg.Store.Apply(ctx, docs...)
	}
	if err == nil {
		err = a.refreshOpen(ctx)
	}
	a.mu.Unlock()
	if err != nil {
		a.internal(w, err)
		return
	}
	a.clearCookie(w, r, "session", "/")
	a.runEndings(ctx)
	a.note(ctx, r, Entry{Account: acc.ID, Name: acc.Name, Result: "passwordRemoved"})
	ok(w, nil)
}

// openUp is every change that takes the app back to open: no password, no
// second factor, no passkeys, tokens or sessions, every sign-in service and
// the proxy off. The caller holds mu.
func (a *Auth) openUp(ctx context.Context) ([]Doc, error) {
	all, err := a.accounts(ctx)
	if err != nil {
		return nil, err
	}
	var docs []Doc
	for _, acc := range all {
		acc.Password, acc.LegacyPassword = "", ""
		acc.TOTP, acc.TOTPPending, acc.Recovery, acc.LegacyRecovery = nil, nil, nil, nil
		acc.Epoch++
		docs = append(docs, a.doc(kindAccount, acc.ID, acc), a.ending(acc.ID, EndOpened))
	}
	for _, kind := range []string{kindSession, kindToken, kindPasskey} {
		more, err := a.wipe(ctx, kind, func([]byte) bool { return true })
		if err != nil {
			return nil, err
		}
		docs = append(docs, more...)
	}
	more, _, _, err := a.pauseOutside(ctx)
	if err != nil {
		return nil, err
	}
	return append(docs, more...), nil
}

// wipe returns deletes for every document of kind that match accepts.
func (a *Auth) wipe(ctx context.Context, kind string, match func([]byte) bool) ([]Doc, error) {
	list, err := a.cfg.Store.List(ctx, kind)
	if err != nil {
		return nil, err
	}
	var docs []Doc
	for _, d := range list {
		if match(d.Data) {
			docs = append(docs, gone(kind, d.ID))
		}
	}
	return docs, nil
}

func (a *Auth) postConfirm(w http.ResponseWriter, r *http.Request, f *found) {
	var in struct {
		Password string `json:"password"`
	}
	if !readJSON(w, r, smallBody, &in) {
		return
	}
	ctx := r.Context()
	if f.v.session == "" {
		fail(w, http.StatusForbidden, "forbidden")
		return
	}
	acc, err := a.account(ctx, f.v.Account)
	if err != nil {
		a.internal(w, err)
		return
	}
	if !acc.hasPassword() {
		fail(w, http.StatusForbidden, "notLocal")
		return
	}
	if !a.passwordAgain(w, r, acc, in.Password) {
		return
	}
	a.mu.Lock()
	s := new(session)
	err = a.load(ctx, kindSession, f.v.session, s)
	if err == nil {
		s.SignedAt = a.now()
		err = a.cfg.Store.Apply(ctx, a.doc(kindSession, f.v.session, s))
	}
	a.mu.Unlock()
	if err != nil {
		a.internal(w, err)
		return
	}
	ok(w, nil)
}

func newID() string { return token.Random(12) }

func equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
