package signintest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// Person is who signs in at a Provider.
type Person struct {
	Subject       string
	Name          string
	Email         string
	EmailVerified bool
	// Groups nil leaves the groups claim out, an empty list sends it empty.
	Groups []string
}

// Provider is a sign-in service over OIDC that runs in the test, behind TLS
// with a certificate of its own. It checks PKCE and the client secret like a
// real one, signs ID tokens with RS256 and answers every authorization at
// once for Next.
type Provider struct {
	URL      string // the issuer
	ClientID string
	Secret   string
	// CA is the PEM certificate an app has to trust to reach it.
	CA []byte

	mu   sync.Mutex
	srv  *httptest.Server
	key  *rsa.PrivateKey
	next Person
	// signedOut makes an authorization with prompt=none answer
	// login_required, as when the person signed out at the service.
	signedOut bool
	codes     map[string]grant
	tokens    map[string]Person
	// Tamper changes the claims of the next ID tokens.
	tamper func(claims map[string]any)
	// otherKey signs ID tokens with a key the JWKS does not list.
	otherKey *rsa.PrivateKey
	// iss replaces the iss parameter of the redirect back.
	iss string
	// userInfo answers the UserInfo endpoint for another subject.
	userInfo *Person
	// groupsInUserInfo leaves the groups out of the ID token.
	groupsInUserInfo bool
	// like names the preset whose endpoint paths discovery shows.
	like string
}

// endpoints are where each kind of sign-in service has its authorization
// and token endpoints, as their discovery documents name them.
var endpoints = map[string][2]string{
	"":          {"/authorize", "/token"},
	"pocket-id": {"/authorize", "/api/oidc/token"},
	"authentik": {"/application/o/authorize/", "/application/o/token/"},
	"authelia":  {"/api/oidc/authorization", "/api/oidc/token"},
	"keycloak":  {"/realms/home/protocol/openid-connect/auth", "/realms/home/protocol/openid-connect/token"},
	"kanidm":    {"/ui/oauth2", "/oauth2/token"},
	"zitadel":   {"/oauth/v2/authorize", "/oauth/v2/token"},
}

// Like makes the provider's discovery name its endpoints where the sign-in
// service with the preset id has them, such as "keycloak". Empty is paths
// no preset uses.
func (p *Provider) Like(id string) {
	p.mu.Lock()
	p.like = id
	p.mu.Unlock()
}

type grant struct {
	person    Person
	nonce     string
	challenge string
	redirect  string
}

// NewProvider starts a provider that the test closes.
func NewProvider(t testing.TB) *Provider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &Provider{ClientID: "app", Secret: "client secret", key: key, codes: map[string]grant{}, tokens: map[string]Person{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	seen := map[string]bool{}
	for _, e := range endpoints {
		if !seen[e[0]] {
			mux.HandleFunc("GET "+e[0], p.authorize)
		}
		if !seen[e[1]] {
			mux.HandleFunc("POST "+e[1], p.token)
		}
		seen[e[0]], seen[e[1]] = true, true
	}
	mux.HandleFunc("GET /userinfo", p.userinfo)
	mux.HandleFunc("GET /jwks", p.jwks)
	p.srv = httptest.NewTLSServer(mux)
	t.Cleanup(p.srv.Close)
	p.URL = p.srv.URL
	p.CA = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.srv.Certificate().Raw})
	return p
}

// Client is an HTTP client that trusts the provider, for a test that plays
// the browser on the provider's side.
func (p *Provider) Client() *http.Client {
	c := *p.srv.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

// Next sets who signs in at the next authorization.
func (p *Provider) Next(person Person) {
	p.mu.Lock()
	p.next = person
	p.signedOut = false
	p.mu.Unlock()
}

// SignOut makes the provider forget the person, so a silent renewal fails.
func (p *Provider) SignOut() {
	p.mu.Lock()
	p.signedOut = true
	p.mu.Unlock()
}

// Tamper changes the claims of every later ID token.
func (p *Provider) Tamper(change func(claims map[string]any)) {
	p.mu.Lock()
	p.tamper = change
	p.mu.Unlock()
}

// SignWithAnotherKey signs later ID tokens with a key the app cannot know.
func (p *Provider) SignWithAnotherKey() {
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	p.mu.Lock()
	p.otherKey = other
	p.mu.Unlock()
}

// SendIssuer names another issuer in the redirect back, as a sign-in service
// that mixes up its clients would.
func (p *Provider) SendIssuer(iss string) {
	p.mu.Lock()
	p.iss = iss
	p.mu.Unlock()
}

// GroupsOnlyInUserInfo leaves the groups out of the ID token, as some
// services do, so the app has to ask UserInfo. With someone set, UserInfo
// answers for that person instead.
func (p *Provider) GroupsOnlyInUserInfo(someone *Person) {
	p.mu.Lock()
	p.groupsInUserInfo = true
	p.userInfo = someone
	p.mu.Unlock()
}

func (p *Provider) discovery(w http.ResponseWriter, _ *http.Request) {
	p.mu.Lock()
	e := endpoints[p.like]
	p.mu.Unlock()
	writeJSON(w, map[string]any{
		"issuer":                                p.URL,
		"authorization_endpoint":                p.URL + e[0],
		"token_endpoint":                        p.URL + e[1],
		"userinfo_endpoint":                     p.URL + "/userinfo",
		"jwks_uri":                              p.URL + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirect, err := url.Parse(q.Get("redirect_uri"))
	if err != nil || q.Get("client_id") != p.ClientID || q.Get("response_type") != "code" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	back := redirect.Query()
	back.Set("state", q.Get("state"))
	p.mu.Lock()
	signedOut, person, iss := p.signedOut, p.next, p.iss
	p.mu.Unlock()
	if iss == "" {
		iss = p.URL
	}
	back.Set("iss", iss)
	switch {
	case q.Get("prompt") == "none" && signedOut:
		back.Set("error", "login_required")
	case q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "":
		back.Set("error", "invalid_request")
	default:
		code := randomString()
		p.mu.Lock()
		p.codes[code] = grant{person: person, nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: redirect.String()}
		p.mu.Unlock()
		back.Set("code", code)
	}
	redirect.RawQuery = back.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, secret, ok := r.BasicAuth()
	if ok {
		// RFC 6749 form-encodes both before they go into the header.
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	p.mu.Lock()
	g, found := p.codes[r.PostForm.Get("code")]
	delete(p.codes, r.PostForm.Get("code"))
	p.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	switch {
	case id != p.ClientID || secret != p.Secret:
		writeError(w, "invalid_client")
		return
	case !found || g.redirect != r.PostForm.Get("redirect_uri"):
		writeError(w, "invalid_grant")
		return
	case base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge:
		writeError(w, "invalid_grant")
		return
	}
	access := randomString()
	p.mu.Lock()
	p.tokens[access] = g.person
	p.mu.Unlock()
	writeJSON(w, map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": 300, "id_token": p.idToken(g)})
}

func (p *Provider) claims(person Person) map[string]any {
	c := map[string]any{"sub": person.Subject, "preferred_username": person.Name}
	if person.Groups != nil {
		c["groups"] = person.Groups
	}
	if person.Email != "" {
		c["email"], c["email_verified"] = person.Email, person.EmailVerified
	}
	return c
}

func (p *Provider) idToken(g grant) string {
	now := time.Now()
	c := p.claims(g.person)
	c["iss"], c["aud"], c["nonce"] = p.URL, p.ClientID, g.nonce
	c["iat"], c["exp"], c["auth_time"] = now.Unix(), now.Add(5*time.Minute).Unix(), now.Unix()
	p.mu.Lock()
	tamper, key, onlyInfo := p.tamper, p.key, p.groupsInUserInfo
	if p.otherKey != nil {
		key = p.otherKey
	}
	p.mu.Unlock()
	if onlyInfo {
		delete(c, "groups")
	}
	if tamper != nil {
		tamper(c)
	}
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "test"})
	body, _ := json.Marshal(c)
	signed := b64.EncodeToString(header) + "." + b64.EncodeToString(body)
	sum := sha256.Sum256([]byte(signed))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	return signed + "." + b64.EncodeToString(sig)
}

func (p *Provider) userinfo(w http.ResponseWriter, r *http.Request) {
	access := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	p.mu.Lock()
	person, ok := p.tokens[access]
	if p.userInfo != nil {
		person = *p.userInfo
	}
	p.mu.Unlock()
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	writeJSON(w, p.claims(person))
}

func (p *Provider) jwks(w http.ResponseWriter, _ *http.Request) {
	pub := p.key.PublicKey
	writeJSON(w, map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "test",
		"n": b64.EncodeToString(pub.N.Bytes()), "e": b64.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func randomString() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return b64.EncodeToString(b)
}
