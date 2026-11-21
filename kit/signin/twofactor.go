package signin

import (
	"crypto/rand"
	"net/http"
	"strings"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/signin/internal/totp"
)

// Recovery codes are ten characters of Crockford's base32 alphabet, 50
// bits, shown as two groups of five.
const (
	codeAlphabet = "0123456789abcdefghjkmnpqrstvwxyz"
	codeLen      = 10
	codeCount    = 10
	pendingLife  = 10 * time.Minute
)

// localAccount loads the account of f for a change to its password sign-in,
// and answers when there is none.
func (a *Auth) localAccount(w http.ResponseWriter, r *http.Request, f *found) (*account, bool) {
	if f.v.session == "" {
		fail(w, http.StatusForbidden, "forbidden")
		return nil, false
	}
	acc, err := a.account(r.Context(), f.v.Account)
	if err != nil {
		a.internal(w, err)
		return nil, false
	}
	if !acc.hasPassword() {
		fail(w, http.StatusForbidden, "notLocal")
		return nil, false
	}
	return acc, true
}

func (a *Auth) postTOTP(w http.ResponseWriter, r *http.Request, f *found) {
	if !a.fresh(f) {
		a.notFresh(w, r, f)
		return
	}
	acc, good := a.localAccount(w, r, f)
	if !good {
		return
	}
	secret, err := totp.NewSecret()
	if err != nil {
		a.internal(w, err)
		return
	}
	sealed, err := a.sealFor("totp-pending", acc.ID, secret)
	if err != nil {
		a.internal(w, err)
		return
	}
	a.mu.Lock()
	acc, err = a.stillValid(r.Context(), f)
	if err == nil {
		acc.TOTPPending, acc.TOTPPendingAt = sealed, a.now()
		err = a.cfg.Store.Apply(r.Context(), a.doc(kindAccount, acc.ID, acc))
	}
	a.mu.Unlock()
	if err != nil {
		a.internal(w, err)
		return
	}
	ok(w, map[string]string{"secret": totp.Encode(secret), "uri": totp.URI(a.cfg.Name, acc.Name, secret)})
}

func (a *Auth) postTOTPConfirm(w http.ResponseWriter, r *http.Request, f *found) {
	var in struct {
		Code string `json:"code"`
	}
	if !readJSON(w, r, smallBody, &in) {
		return
	}
	if _, good := a.localAccount(w, r, f); !good {
		return
	}
	ctx := r.Context()
	a.mu.Lock()
	codes, err := a.confirmTOTP(w, r, f, in.Code)
	a.mu.Unlock()
	if err != nil {
		a.answer(w, r, f, err)
		return
	}
	a.runEndings(ctx)
	ok(w, map[string]any{"codes": codes})
}

// confirmTOTP turns two-factor on with the pending secret once code fits
// it. The caller holds mu.
func (a *Auth) confirmTOTP(w http.ResponseWriter, r *http.Request, f *found, code string) ([]string, error) {
	now := a.now()
	acc, err := a.stillValid(r.Context(), f)
	if err != nil {
		return nil, refuse(http.StatusUnauthorized, "signInFirst")
	}
	if len(acc.TOTPPending) == 0 || now.Sub(acc.TOTPPendingAt) > pendingLife {
		return nil, refuse(http.StatusConflict, "setupExpired")
	}
	secret, err := a.openFor("totp-pending", acc.ID, acc.TOTPPending)
	if err != nil {
		return nil, err
	}
	step, good := totp.Check(secret, strings.TrimSpace(code), now, 0)
	if !good {
		return nil, refuse(http.StatusUnauthorized, "wrongCode")
	}
	if acc.TOTP, err = a.sealFor("totp", acc.ID, secret); err != nil {
		return nil, err
	}
	acc.TOTPLast, acc.TOTPPending, acc.TOTPPendingAt = step, nil, time.Time{}
	codes := a.newCodes(acc)
	acc.Epoch++
	docs := append(a.endingsOf(acc, EndTwoFactor), a.doc(kindAccount, acc.ID, acc))
	docs = append(docs, a.newSession(w, r, f, a.reissue(r, f, acc))...)
	return codes, a.cfg.Store.Apply(r.Context(), docs...)
}

func (a *Auth) deleteTOTP(w http.ResponseWriter, r *http.Request, f *found) {
	var in struct {
		Code string `json:"code"`
	}
	if !readJSON(w, r, smallBody, &in) {
		return
	}
	if _, good := a.localAccount(w, r, f); !good {
		return
	}
	ctx := r.Context()
	now := a.now()
	key := "code:" + f.v.Account
	if wait := a.limits.wait(perCode, key, now); wait > 0 {
		throttled(w, wait)
		return
	}
	a.mu.Lock()
	err := a.endTOTP(w, r, f, in.Code, key, now)
	a.mu.Unlock()
	if err != nil {
		a.answer(w, r, f, err)
		return
	}
	a.runEndings(ctx)
	ok(w, nil)
}

// endTOTP turns two-factor off once code is one of its codes. The caller
// holds mu.
func (a *Auth) endTOTP(w http.ResponseWriter, r *http.Request, f *found, code, key string, now time.Time) error {
	ctx := r.Context()
	acc, err := a.stillValid(ctx, f)
	if err != nil {
		return refuse(http.StatusUnauthorized, "signInFirst")
	}
	if !acc.twoFactor() {
		return nil
	}
	used, err := a.useSecondFactor(ctx, acc, code, now)
	if err != nil {
		return err
	}
	if used == "" {
		a.limits.fail(perCode, key, now)
		return refuse(http.StatusUnauthorized, "wrongCode")
	}
	acc.TOTP, acc.TOTPLast, acc.Recovery, acc.LegacyRecovery = nil, 0, nil, nil
	acc.Epoch++
	docs := append(a.endingsOf(acc, EndTwoFactor), a.doc(kindAccount, acc.ID, acc))
	docs = append(docs, a.newSession(w, r, f, a.reissue(r, f, acc))...)
	return a.cfg.Store.Apply(ctx, docs...)
}

func (a *Auth) postTOTPCodes(w http.ResponseWriter, r *http.Request, f *found) {
	if !a.fresh(f) {
		a.notFresh(w, r, f)
		return
	}
	if _, good := a.localAccount(w, r, f); !good {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	acc, err := a.stillValid(r.Context(), f)
	if err != nil {
		fail(w, http.StatusUnauthorized, "signInFirst")
		return
	}
	if !acc.twoFactor() {
		fail(w, http.StatusConflict, "twoFactorOff")
		return
	}
	codes := a.newCodes(acc)
	if err := a.cfg.Store.Apply(r.Context(), a.doc(kindAccount, acc.ID, acc)); err != nil {
		a.internal(w, err)
		return
	}
	ok(w, map[string]any{"codes": codes})
}

// newCodes gives acc fresh recovery codes in place of every older one and
// returns them, the only time they are shown.
func (a *Auth) newCodes(acc *account) []string {
	codes := make([]string, codeCount)
	acc.Recovery, acc.LegacyRecovery = make([]string, codeCount), nil
	for i := range codes {
		codes[i] = newRecoveryCode()
		acc.Recovery[i] = a.macHex("recovery|"+acc.ID, normalCode(codes[i]))
	}
	return codes
}

// normalCode returns code in lower case without spaces and dashes when it
// has the shape of a recovery code, else "".
func normalCode(code string) string {
	code = strings.ToLower(strings.NewReplacer(" ", "", "-", "").Replace(code))
	if len(code) != codeLen {
		return ""
	}
	for i := 0; i < len(code); i++ {
		if strings.IndexByte(codeAlphabet, code[i]) < 0 {
			return ""
		}
	}
	return code
}

func newRecoveryCode() string {
	b := make([]byte, codeLen)
	rand.Read(b)
	for i := range b {
		b[i] = codeAlphabet[b[i]%32]
	}
	return string(b[:5]) + "-" + string(b[5:])
}
