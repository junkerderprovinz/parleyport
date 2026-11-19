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
// BrowserPrefix. Mount it on both:
//
//	mux.Handle(signin.APIPrefix, auth.Handler())
//	mux.Handle(signin.BrowserPrefix, auth.Handler())
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
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Context().Value(ctxKey{}).(*found); !ok {
			r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, a.find(w, r)))
		}
		mux.ServeHTTP(w, r)
	})
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
		if (need == admin || need == adminAccount) && !f.v.AtLeast(a.roles[0]) {
			fail(w, http.StatusForbidden, "forbidden")
			return
		}
	}
	fn(w, r, f)
}

// sameOrigin reports whether a change comes from the app's own pages. A
// browser says so in Sec-Fetch-Site, or an older one in Origin, which must
// then be the app's public address, or without one the host it asked for.
// With neither header, only an API token counts, never a cookie.
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
	if u := a.public(); u != nil {
		return origin == u.Scheme+"://"+u.Host
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
		{"GET me/tokens", member, a.getTokens},
		{"POST me/tokens", member, a.postToken},
		{"DELETE me/tokens/{id}", member, a.deleteToken},
		{"GET accounts", admin, a.getAccounts},
		{"POST accounts", adminAccount, a.postAccount},
		{"PATCH accounts/{id}", adminAccount, a.patchAccount},
		{"DELETE accounts/{id}", adminAccount, a.deleteAccount},
		{"GET roles", admin, a.getRoles},
		{"GET methods/presets", admin, a.getPresets},
		{"GET methods/oidc", admin, a.getServices},
		{"POST methods/oidc", adminAccount, a.postService},
		{"PATCH methods/oidc/{id}", adminAccount, a.patchService},
		{"DELETE methods/oidc/{id}", adminAccount, a.deleteService},
		{"POST methods/oidc/{id}/check", adminAccount, a.postServiceCheck},
		{"POST methods/oidc/{id}/test", adminAccount, a.postServiceTest},
		{"GET settings", admin, a.getSettings},
		{"PATCH settings", adminAccount, a.patchSettings},
		{"GET log", admin, a.getLog},
	}
}

type apiRoute struct {
	pattern string
	need    access
	fn      route
}
