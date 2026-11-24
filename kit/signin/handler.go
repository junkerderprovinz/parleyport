package signin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// APIPrefix is where Handler serves the contract.
const APIPrefix = "/api/signin/v1/"

// BrowserPrefix is where Handler serves the pages a browser is sent to, such
// as the way to and back from a sign-in service.
const BrowserPrefix = "/signin/"

// Handler serves the contract under APIPrefix and the browser routes under
// BrowserPrefix, both below Config.Base. Mount it on both:
//
//	mux.Handle(signin.APIPrefix, auth.Handler())
//	mux.Handle(signin.BrowserPrefix, auth.Handler())
//
// With a base such as /files/ the paths are /files/api/signin/v1/ and
// /files/signin/, and a handler in front that strips the base works too.
//
// It finds the visitor itself when Guard did not run first.
func (a *Auth) Handler() http.Handler { return a.handler }

// access is who may call a route.
type access int

const (
	public       access = iota // anybody
	visitor                    // any visitor, also everyone while the app is open
	member                     // an account signed in through a session
	admin                      // a visitor with the admin role
	adminAccount               // an admin signed in as an account, so not while the app is open
	adminOpen                  // an admin signed in as an account, or everyone while the app is open
	memberOpen                 // an account signed in through a session, or everyone while the app is open
)

type route func(w http.ResponseWriter, r *http.Request, f *found)

func (a *Auth) routes() http.Handler {
	mux := http.NewServeMux()
	for _, rt := range a.api() {
		method, path, _ := strings.Cut(rt.pattern, " ")
		mux.HandleFunc(method+" "+APIPrefix+path, func(w http.ResponseWriter, r *http.Request) {
			a.serveAPI(w, r, rt.pattern, rt.need, rt.fn)
		})
	}

	mux.HandleFunc(APIPrefix, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		fail(w, http.StatusNotFound, "notFound")
	})
	mux.HandleFunc("GET "+oidcPath+"callback", a.getOIDCCallback)
	mux.HandleFunc("GET "+oidcPath+"{id}", a.getOIDCStart)
	for _, s := range a.cfg.Services {
		if s.StartPath != "" {
			mux.HandleFunc("GET "+s.StartPath, func(w http.ResponseWriter, r *http.Request) {
				// The app's older start took the way back as redirect.
				q := r.URL.Query()
				ret := q.Get("return")
				if ret == "" {
					ret = q.Get("redirect")
				}
				a.startService(w, r, s.ID, ret)
			})
		}
		if s.CallbackPath != "" {
			mux.HandleFunc("GET "+s.CallbackPath, func(w http.ResponseWriter, r *http.Request) { a.callback(w, r, s.CallbackPath) })
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Context().Value(ctxKey{}).(*found); !ok {
			r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, a.find(w, r)))
		}
		if rest, under := strings.CutPrefix(r.URL.Path, strings.TrimSuffix(a.base(), "/")); under && strings.HasPrefix(rest, "/") {
			r2 := new(http.Request)
			*r2 = *r
			u := *r.URL
			u.Path, u.RawPath = rest, ""
			r2.URL = &u
			r = r2
		}
		mux.ServeHTTP(w, r)
	})
}

// under is path on the app, below Base.
func (a *Auth) under(path string) string { return a.base() + strings.TrimPrefix(path, "/") }

// base is the path browsers find the package under: Config.Base, or else
// the path of Config.Public, which can change while the app runs.
func (a *Auth) base() string {
	if a.fixedBase != "" {
		return a.fixedBase
	}
	if u := a.public(); u != nil {
		if b, ok := basePath(u.Path); ok {
			return b
		}
	}
	return "/"
}

// basePath is p with one slash on each end, and false when p is no path.
func basePath(p string) (string, bool) {
	b := "/" + strings.Trim(p, "/") + "/"
	if b == "//" {
		return "/", true
	}
	return b, !strings.ContainsAny(b, "?#") && !strings.Contains(b, "//")
}

// cookiePath is where a cookie for path goes. A session is for the whole
// site, which the __Host- name needs.
func (a *Auth) cookiePath(path string) string {
	if path == "/" {
		return path
	}
	return a.under(path)
}

func (a *Auth) serveAPI(w http.ResponseWriter, r *http.Request, pattern string, need access, fn route) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if !a.sameOrigin(r) {
			fail(w, http.StatusForbidden, "crossSite")
			return
		}
		if hasBody(r) && !isJSON(r) {
			fail(w, http.StatusUnsupportedMediaType, "notJSON")
			return
		}
	}
	f := r.Context().Value(ctxKey{}).(*found)
	if need != public {
		if !f.ok {
			fail(w, http.StatusUnauthorized, "signInFirst")
			return
		}
		if f.v.Via == ViaToken && pattern != "GET me" {
			fail(w, http.StatusForbidden, "notWithToken")
			return
		}
		if need == member || need == adminAccount {
			switch f.v.Via {
			case ViaAnyone:
				fail(w, http.StatusConflict, "setPasswordFirst")
				return
			case ViaDoor:
				fail(w, http.StatusForbidden, "forbidden")
				return
			}
		}
		if (need == adminOpen || need == memberOpen) && f.v.Via == ViaDoor {
			fail(w, http.StatusForbidden, "forbidden")
			return
		}
		if (need == admin || need == adminAccount || need == adminOpen) && !f.v.AtLeast(a.roles[0]) {
			fail(w, http.StatusForbidden, "forbidden")
			return
		}
	}
	fn(w, r, f)
}

// sameOrigin reports whether a change comes from the app's own pages. A
// browser says so in Sec-Fetch-Site, or one that sends it only to https
// pages in Origin, which must then be the app's public address or the host
// it asked for, such as its address on the LAN. A page of another site
// carries no cookie of that host. With neither header, only an API token
// counts, never a cookie.
func (a *Auth) sameOrigin(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return true
	case "":
	default:
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	if u := a.public(); u != nil && origin == u.Scheme+"://"+u.Host {
		return true
	}
	scheme := "http"
	if a.https(r) {
		scheme = "https"
	}
	return origin == scheme+"://"+r.Host
}

func hasBody(r *http.Request) bool { return r.ContentLength > 0 || len(r.TransferEncoding) > 0 }

func isJSON(r *http.Request) bool {
	t, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && t == "application/json"
}

// readJSON reads a body of at most limit bytes into v and answers 400 when
// that fails. An empty body leaves v as it is.
func readJSON(w http.ResponseWriter, r *http.Request, limit int64, v any) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			fail(w, http.StatusRequestEntityTooLarge, "tooLarge")
		} else {
			fail(w, http.StatusBadRequest, "badRequest")
		}
		return false
	}
	if len(body) == 0 {
		return true
	}
	if err := json.Unmarshal(body, v); err != nil {
		fail(w, http.StatusBadRequest, "badRequest")
		return false
	}
	return true
}

const smallBody = 8 << 10

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// fail answers with an error code and, as pairs of key and value, more
// fields for it.
func fail(w http.ResponseWriter, status int, code string, extra ...any) {
	body := map[string]any{"error": code}
	for i := 0; i+1 < len(extra); i += 2 {
		body[extra[i].(string)] = extra[i+1]
	}
	writeJSON(w, status, body)
}

func ok(w http.ResponseWriter, v any) {
	if v == nil {
		v = struct{}{}
	}
	writeJSON(w, http.StatusOK, v)
}

func throttled(w http.ResponseWriter, wait time.Duration) {
	secs := int(math.Ceil(wait.Seconds()))
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	fail(w, http.StatusTooManyRequests, "throttled", "retryAfter", secs)
}

// Refusal is a request the package turned down. Status and Code are what
// the contract answers it with, such as 409 and nameTaken. Retry is how
// long to wait with throttled, for a Retry-After.
type Refusal struct {
	Status int
	Code   string
	Retry  time.Duration
}

func (e *Refusal) Error() string { return "signin: " + e.Code }

func refuse(status int, code string) error { return &Refusal{Status: status, Code: code} }

// answer fails the request as err says.
func (a *Auth) answer(w http.ResponseWriter, r *http.Request, f *found, err error) {
	var no *Refusal
	switch {
	case errors.As(err, &no) && no.Retry > 0:
		throttled(w, no.Retry)
	case errors.As(err, &no):
		fail(w, no.Status, no.Code)
	case errors.Is(err, ErrNotFresh):
		a.notFresh(w, r, f)
	case errors.Is(err, ErrNotFound):
		fail(w, http.StatusNotFound, "notFound")
	default:
		a.internal(w, err)
	}
}

func (a *Auth) internal(w http.ResponseWriter, err error) {
	a.log.Error("signin: request failed", "err", err)
	fail(w, http.StatusInternalServerError, "internal")
}

// readRaw reads a body of at most limit bytes as it is.
func readRaw(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		fail(w, http.StatusRequestEntityTooLarge, "tooLarge")
		return nil, false
	}
	return body, true
}

// api is the contract, one route a line, as openapi.yaml lists it.
func (a *Auth) api() []apiRoute {
	return []apiRoute{
		{"GET options", public, a.getOptions},
		{"POST login", public, a.postLogin},
		{"POST login/totp", public, a.postLoginTOTP},
		{"POST login/passkey/options", public, a.postPasskeyLoginOptions},
		{"POST login/passkey", public, a.postPasskeyLogin},
		{"POST logout", public, a.postLogout},
		{"POST reset-code", public, a.postResetCode},
		{"POST reset", public, a.postReset},
		{"GET me", visitor, a.getMe},
		{"PUT me/password", visitor, a.putPassword},
		{"DELETE me/password", member, a.deletePassword},
		{"POST me/confirm", member, a.postConfirm},
		{"GET me/sessions", member, a.getSessions},
		{"DELETE me/sessions", member, a.deleteSessions},
		{"DELETE me/sessions/{id}", member, a.deleteSession},
		{"POST me/totp", member, a.postTOTP},
		{"POST me/totp/confirm", member, a.postTOTPConfirm},
		{"DELETE me/totp", member, a.deleteTOTP},
		{"POST me/totp/codes", member, a.postTOTPCodes},
		{"GET me/passkeys", member, a.getPasskeys},
		{"POST me/passkeys/options", member, a.postPasskeyOptions},
		{"POST me/passkeys", member, a.postPasskey},
		{"PATCH me/passkeys/{id}", member, a.patchPasskey},
		{"DELETE me/passkeys/{id}", member, a.deletePasskey},
		{"GET me/identities", member, a.getIdentities},
		{"DELETE me/identities/{id}", member, a.deleteIdentity},
		{"POST me/identities/{service}/link", member, a.postIdentityLink},
		{"GET me/tokens", memberOpen, a.getTokens},
		{"POST me/tokens", memberOpen, a.postToken},
		{"DELETE me/tokens/{id}", memberOpen, a.deleteToken},
		{"GET accounts", admin, a.getAccounts},
		{"POST accounts", adminAccount, a.postAccount},
		{"PATCH accounts/{id}", adminOpen, a.patchAccount},
		{"DELETE accounts/{id}", adminOpen, a.deleteAccount},
		{"GET roles", admin, a.getRoles},
		{"GET methods/presets", admin, a.getPresets},
		{"GET methods/oidc", admin, a.getServices},
		{"POST methods/oidc", adminOpen, a.postService},
		{"PATCH methods/oidc/{id}", adminOpen, a.patchService},
		{"DELETE methods/oidc/{id}", adminOpen, a.deleteService},
		{"POST methods/oidc/{id}/check", adminOpen, a.postServiceCheck},
		{"POST methods/oidc/{id}/test", adminOpen, a.postServiceTest},
		{"GET settings", admin, a.getSettings},
		{"PATCH settings", adminOpen, a.patchSettings},
		{"GET log", admin, a.getLog},
	}
}

type apiRoute struct {
	pattern string
	need    access
	fn      route
}
