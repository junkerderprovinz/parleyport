package signin

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/signin/internal/token"
)

const (
	sessionLife   = 30 * 24 * time.Hour
	sessionIdle   = 7 * 24 * time.Hour
	serviceLife   = 24 * time.Hour
	freshPassword = 10 * time.Minute
	freshService  = 5 * time.Minute
	seenEvery     = time.Hour
	// Tokens of an account from outside rest once its sign-in service has
	// not let it in for this long, a day and an hour of slack.
	outsideRest = 25 * time.Hour
)

type ctxKey struct{}

// found is what the guard learnt about a request.
type found struct {
	ok bool
	v  Visitor
	// cookie is the session cookie the request carried, valid or not.
	cookie string
	// renew names the sign-in service whose session ran out and can be
	// renewed without asking.
	renew string
}

// Guard finds the visitor of every request and puts it where From finds it.
// It decides nothing about routes: a request nobody signed in for reaches
// next without a visitor, and the app answers it.
func (a *Auth) Guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f := a.find(w, r)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, f)))
	})
}

func (a *Auth) foundIn(r *http.Request) *found {
	if f, ok := r.Context().Value(ctxKey{}).(*found); ok {
		return f
	}
	return a.find(nil, r)
}

func (a *Auth) find(w http.ResponseWriter, r *http.Request) *found {
	ctx := r.Context()
	f := &found{}
	if a.open.Load() {
		f.ok, f.v = true, Visitor{Role: a.roles[0], Via: ViaAnyone, roles: a.roles}
		return f
	}
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		// A token that does not count never falls back to a cookie.
		f.v, f.ok = a.byToken(ctx, strings.TrimPrefix(auth, "Bearer "))
		return f
	}
	if raw := a.readCookie(r, "session", "/"); raw != "" {
		f.cookie = raw
		v, renew, err := a.bySession(ctx, raw)
		if err == nil {
			f.ok, f.v = true, v
			return f
		}
		f.renew = renew
	}
	if v, good := a.byOldSession(w, r); good {
		f.ok, f.v = true, v
		return f
	}
	f.v, f.ok = a.byDoor(r)
	return f
}

// byDoor asks the app's own ways in. What a door returns counts only for an
// account the package knows and has not blocked, with the role the package
// keeps for it.
func (a *Auth) byDoor(r *http.Request) (Visitor, bool) {
	for _, door := range a.cfg.Hooks.Doors {
		v, good := door(r)
		if !good {
			continue
		}
		acc, err := a.account(r.Context(), v.Account)
		if err != nil || acc.Blocked {
			return Visitor{}, false
		}
		out := a.visitorOf(acc, ViaDoor, v.Service)
		out.Scopes = v.Scopes
		return out, true
	}
	return Visitor{}, false
}

func (a *Auth) sessionID(raw string) string { return a.macHex("session", raw)[:32] }

func (a *Auth) bySession(ctx context.Context, raw string) (Visitor, string, error) {
	id := a.sessionID(raw)
	s := new(session)
	if err := a.load(ctx, kindSession, id, s); err != nil {
		return Visitor{}, "", err
	}
	now := a.now()
	if !now.Before(s.Expires) || now.Sub(s.Seen) > sessionIdle {
		return Visitor{}, "", errors.New("session over")
	}
	acc, err := a.account(ctx, s.Account)
	if err != nil {
		return Visitor{}, "", err
	}
	if acc.Blocked || acc.Epoch != s.Epoch {
		return Visitor{}, "", errors.New("session ended")
	}
	if s.Via == ViaService && now.Sub(s.Checked) > serviceLife {
		return Visitor{}, s.Service, errors.New("session needs its sign-in service")
	}
	if now.Sub(s.Seen) > seenEvery {
		a.touchSession(ctx, id)
	}
	v := a.visitorOf(acc, s.Via, s.Service)
	v.session, v.signedAt, v.epoch = id, s.SignedAt, s.Epoch
	return v, "", nil
}

// touchSession writes when a session was last used, under the lock so it
// cannot bring back a session that a sign-out deleted meanwhile.
func (a *Auth) touchSession(ctx context.Context, id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := new(session)
	if err := a.load(ctx, kindSession, id, s); err != nil {
		return
	}
	s.Seen = a.now()
	if err := a.cfg.Store.Apply(ctx, a.doc(kindSession, id, s)); err != nil {
		a.log.Warn("signin: noting a session's use", "err", err)
	}
}

func (a *Auth) visitorOf(acc *account, via Via, service string) Visitor {
	role := acc.Role
	if acc.Owner {
		role = a.roles[0]
	} else if !slices.Contains(a.roles, role) {
		role = a.roles[len(a.roles)-1]
	}
	return Visitor{Account: acc.ID, Name: acc.Name, Role: role, Via: via, Service: service, roles: a.roles, epoch: acc.Epoch}
}

// stillValid reads f's session and account again, under mu, to see that
// nothing ended them since the guard looked.
func (a *Auth) stillValid(ctx context.Context, f *found) (*account, error) {
	acc, err := a.account(ctx, f.v.Account)
	if err != nil {
		return nil, err
	}
	if acc.Blocked {
		return nil, errors.New("account blocked")
	}
	if f.v.session != "" {
		s := new(session)
		if err := a.load(ctx, kindSession, f.v.session, s); err != nil {
			return nil, err
		}
		if s.Epoch != acc.Epoch {
			return nil, errors.New("session ended")
		}
	}
	return acc, nil
}

// fresh reports whether f's visitor signed in moments ago, as new lasting
// ways in want.
func (a *Auth) fresh(f *found) bool {
	if !f.ok {
		return false
	}
	age := a.now().Sub(f.v.signedAt)
	switch f.v.Via {
	case ViaAnyone:
		return true
	case ViaPassword, ViaPasskey:
		return age < freshPassword
	case ViaService:
		return age < freshService
	}
	return false
}

// newSession signs the browser of r in with s, fills in what s leaves out,
// and ends the session the browser had. The caller holds mu and applies the
// returned docs.
func (a *Auth) newSession(w http.ResponseWriter, r *http.Request, f *found, s session) []Doc {
	now := a.now()
	raw := token.Random(32)
	if s.Expires.IsZero() || s.Expires.After(now.Add(sessionLife)) {
		s.Expires = now.Add(sessionLife)
	}
	if s.SignedAt.IsZero() {
		s.SignedAt = now
	}
	s.Created, s.Seen = now, now
	s.From, s.Agent = a.client(r).String(), cut(r.UserAgent(), 200)
	docs := []Doc{a.doc(kindSession, a.sessionID(raw), s)}
	if f != nil && f.cookie != "" {
		docs = append(docs, gone(kindSession, a.sessionID(f.cookie)))
	}
	a.setCookie(w, r, "session", raw, "/", s.Expires.Sub(now))
	return docs
}

func sessionOf(acc *account, via Via, service string) session {
	return session{Account: acc.ID, Via: via, Service: service, Epoch: acc.Epoch}
}

// reissue is the session that takes over from f's after an epoch of acc
// the visitor caused. It ends when the old one would have and keeps when
// the sign-in service last confirmed it, so a password change cannot stretch
// either. The caller holds mu.
func (a *Auth) reissue(r *http.Request, f *found, acc *account) session {
	s := sessionOf(acc, f.v.Via, f.v.Service)
	old := new(session)
	if a.load(r.Context(), kindSession, f.v.session, old) == nil {
		s.Expires, s.Checked = old.Expires, old.Checked
	}
	return s
}

// cookieName gives a cookie the __Host- prefix when it is for the whole
// site, __Secure- when it is for one path, and over plain http the domain
// alone, which browsers keep apart from the https names.
func (a *Auth) cookieName(r *http.Request, base, path string) string {
	if !a.https(r) {
		return a.d + "_" + base
	}
	if path == "/" {
		return "__Host-" + a.d + "-" + base
	}
	return "__Secure-" + a.d + "-" + base
}

func (a *Auth) setCookie(w http.ResponseWriter, r *http.Request, base, value, path string, life time.Duration) {
	if w == nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: a.cookieName(r, base, path), Value: value, Path: a.cookiePath(path), MaxAge: int(life.Seconds()),
		HttpOnly: true, Secure: a.https(r), SameSite: http.SameSiteLaxMode,
	})
}

func (a *Auth) clearCookie(w http.ResponseWriter, r *http.Request, base, path string) {
	http.SetCookie(w, &http.Cookie{
		Name: a.cookieName(r, base, path), Value: "", Path: a.cookiePath(path), MaxAge: -1,
		HttpOnly: true, Secure: a.https(r), SameSite: http.SameSiteLaxMode,
	})
}

// readCookie reads a cookie under the one name setCookie gives it for the
// request's scheme, so a cookie planted over plain http or by a neighbour
// subdomain never counts on https.
func (a *Auth) readCookie(r *http.Request, base, path string) string {
	if c, err := r.Cookie(a.cookieName(r, base, path)); err == nil {
		return c.Value
	}
	return ""
}

func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}
