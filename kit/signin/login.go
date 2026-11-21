package signin

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/signin/internal/password"
	"github.com/junkerderprovinz/parleyport/kit/signin/internal/token"
	"github.com/junkerderprovinz/parleyport/kit/signin/internal/totp"
)

const (
	maxPassword = 1024
	stepLife    = 5 * time.Minute
	stepPath    = APIPrefix + "login"
	hashWait    = 5 * time.Second
)

var errBusy = errors.New("signin: too many sign-ins at once")

func (a *Auth) getOptions(w http.ResponseWriter, r *http.Request, f *found) {
	out := map[string]any{
		"open":        a.Anyone(),
		"owner":       a.cfg.Owner,
		"minPassword": a.minPass,
		"signedIn":    f.ok && f.v.Via != ViaAnyone,
		"passkeys":    false,
	}
	services, err := a.offeredServices(r.Context())
	if err != nil {
		a.internal(w, err)
		return
	}
	out["services"] = services
	if f.renew != "" {
		out["renew"] = f.renew
	}
	if !a.Anyone() && a.atPublic(r) && a.relyingParty() != nil {
		keys, err := a.cfg.Store.List(r.Context(), kindPasskey)
		if err != nil {
			a.internal(w, err)
			return
		}
		out["passkeys"] = len(keys) > 0
	}
	ok(w, out)
}

func (a *Auth) postLogin(w http.ResponseWriter, r *http.Request, f *found) {
	var in struct {
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, smallBody, &in) {
		return
	}
	ctx := r.Context()
	if a.Anyone() {
		fail(w, http.StatusConflict, "setPasswordFirst")
		return
	}
	now := a.now()
	addr := addressKey(a.client(r))
	nameKey := "name:" + strings.ToLower(strings.TrimSpace(in.Name))
	if a.cfg.Owner {
		nameKey = "name:owner"
	}
	if wait := max(a.limits.wait(perAddress, addr, now), a.limits.wait(perName, nameKey, now)); wait > 0 {
		a.note(ctx, r, Entry{Name: a.typedName(ctx, in.Name), Via: ViaPassword, Result: "throttled"})
		throttled(w, wait)
		return
	}
	acc, err := a.signInAccount(ctx, in.Name)
	if err != nil && !errors.Is(err, ErrNotFound) {
		a.internal(w, err)
		return
	}
	good := false
	if acc != nil && len(in.Password) <= maxPassword {
		good, err = a.checkPassword(ctx, acc, in.Password)
	} else {
		err = a.burn(ctx)
	}
	if errors.Is(err, errBusy) {
		throttled(w, hashWait)
		return
	}
	if err != nil {
		a.internal(w, err)
		return
	}
	if !good {
		a.limits.fail(perAddress, addr, now)
		a.limits.fail(perName, nameKey, now)
		e := Entry{Name: a.typedName(ctx, in.Name), Via: ViaPassword, Result: "wrongPassword"}
		if acc != nil {
			e.Account, e.Name = acc.ID, acc.Name
		}
		a.note(ctx, r, e)
		fail(w, http.StatusUnauthorized, "wrongPassword")
		return
	}
	a.limits.clear(nameKey)
	if acc.Blocked {
		a.note(ctx, r, Entry{Account: acc.ID, Name: acc.Name, Via: ViaPassword, Result: "blocked"})
		fail(w, http.StatusForbidden, "blocked")
		return
	}
	if acc.Password == "" || !password.Current(acc.Password) {
		a.rehash(ctx, acc, in.Password)
	}
	if acc.twoFactor() {
		raw := token.Random(32)
		a.steps.put(a.macHex("step", raw), step{account: acc.ID, epoch: acc.Epoch, expires: now.Add(stepLife)}, now)
		a.setCookie(w, r, "step", raw, stepPath, stepLife)
		ok(w, map[string]string{"step": "code"})
		return
	}
	a.signedIn(w, r, f, acc.ID, acc.Epoch, ViaPassword, "", nil)
}

func (a *Auth) postLoginTOTP(w http.ResponseWriter, r *http.Request, f *found) {
	var in struct {
		Code string `json:"code"`
	}
	if !readJSON(w, r, smallBody, &in) {
		return
	}
	ctx := r.Context()
	now := a.now()
	raw := a.readCookie(r, "step", stepPath)
	key := a.macHex("step", raw)
	st, found := a.steps.get(key, now)
	if raw == "" || !found {
		fail(w, http.StatusUnauthorized, "stepExpired")
		return
	}
	codeKey := "code:" + st.account
	if wait := a.limits.wait(perCode, codeKey, now); wait > 0 {
		throttled(w, wait)
		return
	}
	a.mu.Lock()
	acc, err := a.account(ctx, st.account)
	if err != nil || acc.Epoch != st.epoch || !acc.twoFactor() {
		a.mu.Unlock()
		a.steps.drop(key)
		fail(w, http.StatusUnauthorized, "stepExpired")
		return
	}
	used, err := a.useSecondFactor(ctx, acc, in.Code, now)
	if err == nil && used != "" {
		err = a.cfg.Store.Apply(ctx, a.doc(kindAccount, acc.ID, acc))
	}
	a.mu.Unlock()
	if err != nil {
		a.internal(w, err)
		return
	}
	if used == "" {
		a.limits.fail(perCode, codeKey, now)
		a.note(ctx, r, Entry{Account: acc.ID, Name: acc.Name, Via: ViaPassword, Result: "wrongCode"})
		fail(w, http.StatusUnauthorized, "wrongCode")
		return
	}
	a.limits.clear(codeKey)
	a.steps.drop(key)
	a.clearCookie(w, r, "step", stepPath)
	if used == "recovery" {
		a.note(ctx, r, Entry{Account: acc.ID, Name: acc.Name, Via: ViaPassword, Result: "recoveryUsed"})
	}
	a.signedIn(w, r, f, acc.ID, st.epoch, ViaPassword, "", nil)
}

// useSecondFactor checks code against acc's authenticator app and recovery
// codes and marks it used in acc. It returns "totp" or "recovery", or "" for
// a code that does not count. The caller holds mu and writes acc.
func (a *Auth) useSecondFactor(ctx context.Context, acc *account, code string, now time.Time) (string, error) {
	code = strings.TrimSpace(code)
	if len(code) == 6 {
		secret, err := a.openFor("totp", acc.ID, acc.TOTP)
		if err != nil {
			return "", err
		}
		step, good := totp.Check(secret, code, now, acc.TOTPLast)
		if !good {
			return "", nil
		}
		acc.TOTPLast = step
		return "totp", nil
	}
	if norm := normalCode(code); norm != "" {
		digest := a.macHex("recovery|"+acc.ID, norm)
		for i, c := range acc.Recovery {
			if equal(c, digest) {
				acc.Recovery = append(acc.Recovery[:i:i], acc.Recovery[i+1:]...)
				return "recovery", nil
			}
		}
	}
	if a.cfg.Legacy.Recovery != nil && code != "" {
		for i, h := range acc.LegacyRecovery {
			if a.cfg.Legacy.Recovery(h, code) {
				acc.LegacyRecovery = append(acc.LegacyRecovery[:i:i], acc.LegacyRecovery[i+1:]...)
				return "recovery", nil
			}
		}
	}
	return "", nil
}

func (a *Auth) postLogout(w http.ResponseWriter, r *http.Request, f *found) {
	ctx := r.Context()
	if f.cookie != "" {
		a.mu.Lock()
		err := a.cfg.Store.Apply(ctx, gone(kindSession, a.sessionID(f.cookie)))
		a.mu.Unlock()
		if err != nil {
			a.internal(w, err)
			return
		}
		a.clearCookie(w, r, "session", "/")
	}
	ok(w, nil)
}

// signedIn makes the session for an account whose sign-in just succeeded,
// as long as nothing ended its sessions since the check, and answers with
// the visitor.
func (a *Auth) signedIn(w http.ResponseWriter, r *http.Request, f *found, id string, epoch int, via Via, service string, groups []string) {
	ctx := r.Context()
	a.mu.Lock()
	acc, err := a.account(ctx, id)
	if err != nil || acc.Epoch != epoch || acc.Blocked {
		a.mu.Unlock()
		fail(w, http.StatusUnauthorized, "signInFirst")
		return
	}
	acc.Seen = a.now()
	docs := append(a.newSession(w, r, f, sessionOf(acc, via, service)), a.doc(kindAccount, acc.ID, acc))
	err = a.cfg.Store.Apply(ctx, docs...)
	a.mu.Unlock()
	if err != nil {
		a.internal(w, err)
		return
	}
	v := a.visitorOf(acc, via, service)
	a.note(ctx, r, Entry{Account: acc.ID, Name: acc.Name, Via: via, Service: service, Result: "ok"})
	if a.cfg.Hooks.SignedIn != nil {
		a.cfg.Hooks.SignedIn(ctx, v, groups)
	}
	ok(w, map[string]any{"visitor": v})
}

// signInAccount is the account a password sign-in with name is for.
func (a *Auth) signInAccount(ctx context.Context, name string) (*account, error) {
	if a.cfg.Owner {
		return a.owner(ctx)
	}
	return a.byName(ctx, strings.TrimSpace(name))
}

// typedName is how the log names an account someone typed: by its name when
// it exists, else by a tag, because people often type their password into
// the name field.
func (a *Auth) typedName(ctx context.Context, name string) string {
	name = strings.TrimSpace(name)
	if name == "" || a.cfg.Owner {
		return ""
	}
	if acc, err := a.byName(ctx, name); err == nil {
		return acc.Name
	}
	return "#" + a.macHex("logname", strings.ToLower(name))[:12]
}

// checkPassword checks pw against acc's hash, or its old one through
// Legacy.Password.
func (a *Auth) checkPassword(ctx context.Context, acc *account, pw string) (bool, error) {
	if len(pw) > maxPassword {
		return false, nil
	}
	release, err := a.hashing(ctx)
	if err != nil {
		return false, err
	}
	defer release()
	switch {
	case acc.Password != "":
		return password.Check(acc.Password, a.passwordInput(pw))
	case acc.LegacyPassword != "" && a.cfg.Legacy.Password != nil:
		return a.cfg.Legacy.Password(ctx, acc.LegacyPassword, pw)
	}
	_, _ = password.Check(a.dummy, []byte("x"))
	return false, nil
}

// burn spends the time of one check on an account that does not exist, so
// the answer does not tell which names do.
func (a *Auth) burn(ctx context.Context) error {
	release, err := a.hashing(ctx)
	if err != nil {
		return err
	}
	defer release()
	_, _ = password.Check(a.dummy, []byte("x"))
	return nil
}

// hashing waits for one of the few Argon2 slots, so a burst of sign-ins
// cannot take all the memory.
func (a *Auth) hashing(ctx context.Context) (func(), error) {
	t := time.NewTimer(hashWait)
	defer t.Stop()
	select {
	case a.argon <- struct{}{}:
		return func() { <-a.argon }, nil
	case <-t.C:
		return nil, errBusy
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// rehash writes pw in the kit's current form after a sign-in with an older
// one, as long as the hash it was checked against is still the one stored.
// Otherwise a sign-in that crossed a reset could bring the old password back.
func (a *Auth) rehash(ctx context.Context, was *account, pw string) {
	h, err := a.hashPassword(pw)
	if err != nil {
		a.log.Warn("signin: hashing a password anew", "err", err)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	acc, err := a.account(ctx, was.ID)
	if err != nil || acc.Password != was.Password || acc.LegacyPassword != was.LegacyPassword || acc.Epoch != was.Epoch {
		return
	}
	id := acc.ID
	acc.Password, acc.LegacyPassword = h, ""
	if err := a.cfg.Store.Apply(ctx, a.doc(kindAccount, id, acc)); err != nil {
		a.log.Warn("signin: hashing a password anew", "err", err)
	}
}

func (a *Auth) hashPassword(pw string) (string, error) {
	release, err := a.hashing(context.Background())
	if err != nil {
		return "", err
	}
	defer release()
	return password.Hash(a.passwordInput(pw))
}

// step is a sign-in that passed the password and waits for the code.
type step struct {
	account string
	epoch   int
	expires time.Time
}

const maxSteps = 10_000

type steps struct {
	mu sync.Mutex
	m  map[string]step
}

func newSteps() *steps { return &steps{m: map[string]step{}} }

func (s *steps) put(key string, st step, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.m) >= maxSteps {
		for k, v := range s.m {
			if now.After(v.expires) {
				delete(s.m, k)
			}
		}
	}
	if len(s.m) < maxSteps {
		s.m[key] = st
	}
}

func (s *steps) get(key string, now time.Time) (step, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.m[key]
	if ok && now.After(st.expires) {
		delete(s.m, key)
		return step{}, false
	}
	return st, ok
}

func (s *steps) drop(key string) {
	s.mu.Lock()
	delete(s.m, key)
	s.mu.Unlock()
}
