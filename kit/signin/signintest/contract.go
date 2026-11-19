package signintest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"

	"github.com/junkerderprovinz/parleyport/kit/signin"
)

// Options tells Run how to sign in to the app under test.
type Options struct {
	// Password is the password of an account without two-factor, or the
	// first password Run sets when the app is still open.
	Password string
	// Name is the account's name, for an app with many accounts.
	Name string
}

// Run checks h, the app's whole handler with the guard in front, against
// the sign-in contract: the answers match openapi.yaml, the session cookie
// has the flags it needs, changes from another site are refused, and a
// sign-out ends the session. Every deviation is an error on t.
func Run(t testing.TB, h http.Handler, opt Options) {
	t.Helper()
	for _, issue := range check(h, opt) {
		t.Error(issue)
	}
}

type checker struct {
	h      http.Handler
	opt    Options
	cookie *http.Cookie
	issues []string
}

func (c *checker) addf(format string, args ...any) {
	c.issues = append(c.issues, fmt.Sprintf(format, args...))
}

func check(h http.Handler, opt Options) []string {
	c := &checker{h: h, opt: opt}
	opts := c.do("GET", "options", nil)
	c.matches("GET options", opts, 200, "Options")
	var o struct{ Open bool }
	_ = json.Unmarshal(opts.Body.Bytes(), &o)
	if o.Open {
		c.matches("PUT me/password on an open app", c.do("PUT", "me/password", map[string]string{"next": opt.Password, "name": opt.Name}), 200, "")
	}
	c.wantError("an unknown route", c.do("GET", "no/such/route", nil), 404, "notFound")
	c.wantError("POST login with a wrong password", c.do("POST", "login", map[string]string{"name": opt.Name, "password": opt.Password + " wrong"}), 401, "wrongPassword")

	login := c.do("POST", "login", map[string]string{"name": opt.Name, "password": opt.Password})
	c.matches("POST login", login, 200, "")
	c.sessionCookie(login)
	if c.cookie == nil {
		return c.issues
	}
	c.matches("GET me", c.do("GET", "me", nil), 200, "Me")
	c.matches("GET me/sessions", c.do("GET", "me/sessions", nil), 200, "")
	c.wantError("POST logout from another site", c.do("POST", "logout", map[string]string{}, "Sec-Fetch-Site", "cross-site"), 403, "crossSite")
	c.wantError("POST logout as a form", c.do("POST", "logout", map[string]string{}, "Content-Type", "text/plain"), 415, "notJSON")
	c.matches("POST logout", c.do("POST", "logout", map[string]string{}), 200, "")
	c.wantError("GET me after the sign-out", c.do("GET", "me", nil), 401, "signInFirst")
	return c.issues
}

func (c *checker) do(method, path string, body any, header ...string) *httptest.ResponseRecorder {
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	r := httptest.NewRequest(method, "https://app.test"+signin.APIPrefix+path, bytes.NewReader(raw))
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(header); i += 2 {
		r.Header.Set(header[i], header[i+1])
	}
	if c.cookie != nil {
		r.AddCookie(c.cookie)
	}
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, r)
	return w
}

func (c *checker) matches(what string, w *httptest.ResponseRecorder, status int, schema string) {
	if w.Code != status {
		c.addf("%s answered %d %s, want %d", what, w.Code, strings.TrimSpace(w.Body.String()), status)
		return
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		c.addf("%s answered %q, want JSON", what, ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		c.addf("%s may be cached: Cache-Control %q", what, cc)
	}
	if schema != "" {
		c.schema(what, schema, w.Body.Bytes())
	}
}

func (c *checker) wantError(what string, w *httptest.ResponseRecorder, status int, code string) {
	c.matches(what, w, status, "Error")
	var e struct{ Error string }
	if json.Unmarshal(w.Body.Bytes(), &e) == nil && w.Code == status && e.Error != code {
		c.addf("%s answered the code %q, want %q", what, e.Error, code)
	}
}

func (c *checker) sessionCookie(w *httptest.ResponseRecorder) {
	for _, ck := range w.Result().Cookies() {
		if !strings.HasPrefix(ck.Name, "__Host-") || !strings.HasSuffix(ck.Name, "-session") {
			continue
		}
		if !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteLaxMode || ck.Path != "/" || ck.Domain != "" {
			c.addf("the session cookie %s needs HttpOnly, Secure, SameSite=Lax, Path=/ and no Domain", ck.Name)
		}
		c.cookie = &http.Cookie{Name: ck.Name, Value: ck.Value}
		return
	}
	c.addf("POST login over https set no __Host- session cookie")
}

var contract = sync.OnceValue(func() *jsonschema.Compiler {
	var doc any
	if err := yaml.Unmarshal(signin.OpenAPI, &doc); err != nil {
		panic(fmt.Sprintf("signintest: openapi.yaml: %v", err))
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		panic(fmt.Sprintf("signintest: openapi.yaml: %v", err))
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		panic(fmt.Sprintf("signintest: openapi.yaml: %v", err))
	}
	cmp := jsonschema.NewCompiler()
	if err := cmp.AddResource("openapi.json", inst); err != nil {
		panic(fmt.Sprintf("signintest: openapi.yaml: %v", err))
	}
	return cmp
})

func (c *checker) schema(what, name string, body []byte) {
	sch, err := contract().Compile("openapi.json#/components/schemas/" + name)
	if err != nil {
		c.addf("signintest: schema %s: %v", name, err)
		return
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if err != nil {
		c.addf("%s is not JSON: %v", what, err)
		return
	}
	if err := sch.Validate(inst); err != nil {
		c.addf("%s does not match %s: %v", what, name, err)
	}
}
