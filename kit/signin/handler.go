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
	public  access = iota // anybody
	visitor               // any visitor, also everyone while the app is open
	member                // an account signed in through a session or the proxy
	admin                 // a visitor with the admin role
)

type route func(w http.ResponseWriter, r *http.Request, f *found)

func (a *Auth) routes() http.Handler {
	mux := http.NewServeMux()
	api := func(pattern string, need access, fn route) {
		method, path, _ := strings.Cut(pattern, " ")
		mux.HandleFunc(method+" "+APIPrefix+path, func(w http.ResponseWriter, r *http.Request) {
			a.serveAPI(w, r, pattern, need, fn)
		})
	}
	api("GET options", public, a.getOptions)
	api("POST login", public, a.postLogin)
	api("POST login/totp", public, a.postLoginTOTP)
	api("POST login/passkey/options", public, a.postPasskeyLoginOptions)
	api("POST login/passkey", public, a.postPasskeyLogin)
	api("POST logout", public, a.postLogout)
	api("POST reset-code", public, a.postResetCode)
	api("POST reset", public, a.postReset)

	api("GET me", visitor, a.getMe)
	api("PUT me/password", visitor, a.putPassword)
	api("DELETE me/password", member, a.deletePassword)
	api("POST me/confirm", member, a.postConfirm)
	api("GET me/sessions", member, a.getSessions)
	api("DELETE me/sessions", member, a.deleteSessions)
	api("DELETE me/sessions/{id}", member, a.deleteSession)
	api("POST me/totp", member, a.postTOTP)
	api("POST me/totp/confirm", member, a.postTOTPConfirm)
	api("DELETE me/totp", member, a.deleteTOTP)
	api("POST me/totp/codes", member, a.postTOTPCodes)
	api("GET me/passkeys", member, a.getPasskeys)
	api("POST me/passkeys/options", member, a.postPasskeyOptions)
	api("POST me/passkeys", member, a.postPasskey)
	api("PATCH me/passkeys/{id}", member, a.patchPasskey)
	api("DELETE me/passkeys/{id}", member, a.deletePasskey)
	api("GET me/tokens", member, a.getTokens)
	api("POST me/tokens", member, a.postToken)
	api("DELETE me/tokens/{id}", member, a.deleteToken)

	api("GET accounts", admin, a.getAccounts)
	api("POST accounts", admin, a.postAccount)
	api("PATCH accounts/{id}", admin, a.patchAccount)
	api("DELETE accounts/{id}", admin, a.deleteAccount)
	api("GET roles", admin, a.getRoles)
	api("GET log", admin, a.getLog)

	mux.HandleFunc(APIPrefix, func(w http.ResponseWriter, _ *http.Request) { fail(w, http.StatusNotFound, "notFound") })
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Context().Value(ctxKey{}).(*found); !ok {
			r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, a.find(w, r)))
		}
		mux.ServeHTTP(w, r)
	})
}

var crossOrigin = http.NewCrossOriginProtection()

func (a *Auth) serveAPI(w http.ResponseWriter, r *http.Request, pattern string, need access, fn route) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if crossOrigin.Check(r) != nil {
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
		if need == member && (f.v.Via == ViaAnyone || f.v.Via == ViaDoor) {
			if f.v.Via == ViaAnyone {
				fail(w, http.StatusConflict, "setPasswordFirst")
			} else {
				fail(w, http.StatusForbidden, "forbidden")
			}
			return
		}
		if need == admin && !f.v.AtLeast(a.roles[0]) {
			fail(w, http.StatusForbidden, "forbidden")
			return
		}
	}
	fn(w, r, f)
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
