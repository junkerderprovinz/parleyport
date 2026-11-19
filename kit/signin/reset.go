package signin

import (
	"crypto/rand"
	"errors"
	"net/http"
	"strings"
	"time"
)

// A reset code is twelve characters of Crockford's base32 alphabet, 60
// bits, shown in the container log as three groups of four. Whoever reads
// the log runs the app anyway.
const (
	resetAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	resetLen      = 12
	resetLife     = 10 * time.Minute
	resetQuiet    = time.Minute
)

type resetState struct {
	digest  string
	expires time.Time
	printed time.Time
}

func (a *Auth) postResetCode(w http.ResponseWriter, _ *http.Request, _ *found) {
	if a.open.Load() {
		fail(w, http.StatusConflict, "setPasswordFirst")
		return
	}
	now := a.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	if now.Before(a.reset.expires) && now.Sub(a.reset.printed) < resetQuiet {
		ok(w, nil)
		return
	}
	b := make([]byte, resetLen)
	rand.Read(b)
	for i := range b {
		b[i] = resetAlphabet[b[i]%32]
	}
	code := string(b)
	a.reset = resetState{digest: a.macHex("reset", code), expires: now.Add(resetLife), printed: now}
	a.log.Warn("signin: someone asked to reset the password, the code is valid for 10 minutes",
		"code", code[:4]+"-"+code[4:8]+"-"+code[8:])
	ok(w, nil)
}

func (a *Auth) postReset(w http.ResponseWriter, r *http.Request, f *found) {
	var in struct {
		Code     string `json:"code"`
		Password string `json:"password"`
		Name     string `json:"name"`
	}
	if !readJSON(w, r, smallBody, &in) || !a.checkNew(w, in.Password) {
		return
	}
	ctx := r.Context()
	now := a.now()
	if wait := a.limits.wait(perReset, "reset", now); wait > 0 {
		throttled(w, wait)
		return
	}
	code := strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(in.Code))
	a.mu.Lock()
	good := len(code) == resetLen && now.Before(a.reset.expires) && equal(a.macHex("reset", code), a.reset.digest)
	a.mu.Unlock()
	if !good {
		a.limits.fail(perReset, "reset", now)
		a.note(ctx, r, Entry{Result: "resetRefused"})
		fail(w, http.StatusUnauthorized, "resetRefused")
		return
	}
	hash, err := a.hashPassword(in.Password)
	if err != nil {
		a.internal(w, err)
		return
	}

	a.mu.Lock()
	if !equal(a.macHex("reset", code), a.reset.digest) {
		a.mu.Unlock()
		fail(w, http.StatusUnauthorized, "resetRefused")
		return
	}
	a.reset = resetState{}
	acc, err := a.owner(ctx)
	if !a.cfg.Owner && strings.TrimSpace(in.Name) != "" {
		acc, err = a.byName(ctx, strings.TrimSpace(in.Name))
	}
	if errors.Is(err, ErrNotFound) {
		a.mu.Unlock()
		fail(w, http.StatusNotFound, "noAccount")
		return
	}
	if err != nil {
		a.mu.Unlock()
		a.internal(w, err)
		return
	}
	docs, removed, err := a.resetDocs(r, acc, hash)
	if err == nil {
		docs = append(docs, a.newSession(w, r, f, sessionOf(acc, ViaPassword, ""))...)
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
	a.afterEpoch(ctx, acc)
	a.note(ctx, r, Entry{Account: acc.ID, Name: acc.Name, Via: ViaPassword, Result: "reset"})
	ok(w, map[string]any{"removed": removed, "visitor": a.visitorOf(acc, ViaPassword, "")})
}

// resetDocs is everything a reset changes. Whoever knew the old password may
// have left a way in behind, so the reset ends every session and token,
// takes acc's passkeys and second factor, and pauses every sign-in service
// and the proxy until the owner turns them on again. The caller holds mu.
func (a *Auth) resetDocs(r *http.Request, acc *account, hash string) ([]Doc, map[string]any, error) {
	ctx := r.Context()
	removed := map[string]any{"twoFactor": acc.twoFactor()}
	acc.Password, acc.LegacyPassword = hash, ""
	acc.TOTP, acc.TOTPPending, acc.TOTPLast, acc.Recovery, acc.LegacyRecovery = nil, nil, 0, nil, nil
	acc.Blocked = false
	all, err := a.accounts(ctx)
	if err != nil {
		return nil, nil, err
	}
	var docs []Doc
	for _, other := range all {
		if other.ID == acc.ID {
			other = acc
		}
		other.Epoch++
		docs = append(docs, a.doc(kindAccount, other.ID, other), a.ending(other.ID, EndReset))
	}
	sessions, err := a.wipe(ctx, kindSession, func([]byte) bool { return true })
	if err != nil {
		return nil, nil, err
	}
	tokens, err := a.wipe(ctx, kindToken, func([]byte) bool { return true })
	if err != nil {
		return nil, nil, err
	}
	passkeys, err := a.wipe(ctx, kindPasskey, owned(acc.ID))
	if err != nil {
		return nil, nil, err
	}
	outside, err := a.pauseOutside(ctx)
	if err != nil {
		return nil, nil, err
	}
	services := 0
	for _, d := range outside {
		if d.Kind == kindService {
			services++
		}
	}
	removed["tokens"], removed["passkeys"] = len(tokens), len(passkeys)
	removed["services"], removed["proxy"] = services, len(outside) > services
	docs = append(docs, sessions...)
	docs = append(docs, tokens...)
	docs = append(docs, passkeys...)
	docs = append(docs, outside...)
	return docs, removed, nil
}
