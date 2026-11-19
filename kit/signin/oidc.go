package signin

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/junkerderprovinz/parleyport/kit/signin/internal/token"
)

const (
	oidcPath   = BrowserPrefix + "oidc/"
	flowLife   = 10 * time.Minute
	ticketLife = 5 * time.Minute
	oidcWait   = 10 * time.Second
	maxTickets = 1000
)

// What a trip to the sign-in service is for.
const (
	forSignIn = "signin"
	forRenew  = "renew"
	forTest   = "test"
	forLink   = "link"
)

var newcomers = rule{window: time.Hour, max: 10}

// flow is one trip to a sign-in service, sealed in a cookie of the browser
// that started it, so a code from that trip counts only in that browser.
type flow struct {
	State    string    `json:"state"`
	Nonce    string    `json:"nonce"`
	Verifier string    `json:"verifier"`
	Service  string    `json:"service"`
	Purpose  string    `json:"purpose"`
	Return   string    `json:"return"`
	Account  string    `json:"account,omitempty"`
	Session  string    `json:"session,omitempty"`
	Epoch    int       `json:"epoch,omitempty"`
	Expires  time.Time `json:"expires"`
}

// ticket lets a signed-in admin's browser start a test sign-in or the
// linking of an identity, which a plain link from another site must not
// start.
type ticket struct {
	account string
	service string
	purpose string
	expires time.Time
}

type tickets struct {
	mu sync.Mutex
	m  map[string]ticket
}

func (t *tickets) put(key string, tk ticket, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m == nil {
		t.m = map[string]ticket{}
	}
	for k, v := range t.m {
		if now.After(v.expires) {
			delete(t.m, k)
		}
	}
	if len(t.m) < maxTickets {
		t.m[key] = tk
	}
}

func (t *tickets) take(key string, now time.Time) (ticket, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	tk, ok := t.m[key]
	delete(t.m, key)
	return tk, ok && now.Before(tk.expires)
}

// safeReturn keeps a way back that stays on the app: a path from its root,
// never an address of its own or one a browser reads as one.
func safeReturn(s string) string {
	if !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.ContainsAny(s, "\\\r\n") {
		return "/"
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return "/"
	}
	return u.RequestURI()
}

func withCode(ret, code string) string {
	sep := "?"
	if strings.Contains(ret, "?") {
		sep = "&"
	}
	return ret + sep + "signin=" + url.QueryEscape(code)
}

func (a *Auth) back(w http.ResponseWriter, r *http.Request, ret, code string) {
	w.Header().Set("Cache-Control", "no-store")
	if code != "" {
		ret = withCode(ret, code)
	}
	http.Redirect(w, r, ret, http.StatusFound)
}

// httpClient is how the app talks to a service: with a timeout, and with the
// service's own CA next to the system's where it has one, never by
// skipping the check.
func (a *Auth) httpClient(s *service) *http.Client {
	c := &http.Client{Timeout: oidcWait}
	if s.CA != "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		pool.AppendCertsFromPEM([]byte(s.CA))
		c.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	}
	return c
}

type remote struct {
	ctx      context.Context
	provider *oidc.Provider
	config   oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// dial reads the service's discovery document and sets up the client for
// one trip.
func (a *Auth) dial(ctx context.Context, s *service) (*remote, error) {
	// The calls end with the client's timeout, not with the browser's request,
	// so a browser that goes away cannot cut a code exchange in half.
	ctx = oidc.ClientContext(context.WithoutCancel(ctx), a.httpClient(s))
	p, err := oidc.NewProvider(ctx, s.Issuer)
	if err != nil {
		return nil, err
	}
	secret, err := a.openFor("service-secret", s.ID, s.Secret)
	if err != nil {
		return nil, err
	}
	var meta struct {
		Algs []string `json:"id_token_signing_alg_values_supported"`
	}
	if err := p.Claims(&meta); err != nil {
		return nil, err
	}
	algs := slices.DeleteFunc(meta.Algs, func(alg string) bool { return alg == "none" || strings.HasPrefix(alg, "HS") })
	return &remote{
		ctx: ctx, provider: p,
		config: oauth2.Config{
			ClientID: s.ClientID, ClientSecret: string(secret), Endpoint: p.Endpoint(),
			RedirectURL: a.redirectURI(), Scopes: strings.Fields(s.Scopes),
		},
		verifier: p.Verifier(&oidc.Config{ClientID: s.ClientID, SupportedSigningAlgs: algs}),
	}, nil
}

func (a *Auth) getOIDCStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	f := a.foundIn(r)
	q := r.URL.Query()
	ret := safeReturn(q.Get("return"))
	s := new(service)
	if err := a.load(ctx, kindService, r.PathValue("id"), s); err != nil {
		a.back(w, r, ret, "serviceUnknown")
		return
	}
	fl := flow{Service: s.ID, Purpose: forSignIn, Return: ret, Expires: a.now().Add(flowLife)}
	var opts []oauth2.AuthCodeOption
	switch {
	case q.Get("ticket") != "":
		tk, good := a.tickets.take(a.macHex("ticket", q.Get("ticket")), a.now())
		if !good || tk.service != s.ID || !f.ok || f.v.Account != tk.account {
			a.back(w, r, ret, "flowExpired")
			return
		}
		fl.Purpose, fl.Account, fl.Session, fl.Epoch = tk.purpose, tk.account, f.v.session, f.v.epoch
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "login"))
	case q.Get("renew") != "":
		if f.renew != s.ID || f.cookie == "" {
			a.back(w, r, ret, "flowExpired")
			return
		}
		fl.Purpose, fl.Session = forRenew, a.sessionID(f.cookie)
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "none"))
	}
	if a.open.Load() || (fl.Purpose != forTest && !s.On) {
		a.back(w, r, ret, "serviceOff")
		return
	}
	if a.public() == nil {
		a.back(w, r, ret, "addressMissing")
		return
	}
	rem, err := a.dial(ctx, s)
	if err != nil {
		a.log.Warn("signin: reaching a sign-in service", "service", s.ID, "err", err)
		a.back(w, r, ret, "serviceUnreachable")
		return
	}
	fl.State, fl.Nonce, fl.Verifier = token.Random(24), token.Random(24), oauth2.GenerateVerifier()
	if err := a.sealFlow(w, r, fl); err != nil {
		a.internal(w, err)
		return
	}
	opts = append(opts, oauth2.S256ChallengeOption(fl.Verifier), oidc.Nonce(fl.Nonce))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, rem.config.AuthCodeURL(fl.State, opts...), http.StatusFound)
}

func (a *Auth) sealFlow(w http.ResponseWriter, r *http.Request, fl flow) error {
	plain, err := json.Marshal(fl)
	if err != nil {
		return err
	}
	sealed, err := a.sealFor("oidc-flow", "", plain)
	if err != nil {
		return err
	}
	a.setCookie(w, r, "oidc", base64.RawURLEncoding.EncodeToString(sealed), oidcPath, flowLife)
	return nil
}

func (a *Auth) openFlow(w http.ResponseWriter, r *http.Request) (*flow, bool) {
	raw := a.readCookie(r, "oidc", oidcPath)
	a.clearCookie(w, r, "oidc", oidcPath)
	sealed, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || raw == "" {
		return nil, false
	}
	plain, err := a.openFor("oidc-flow", "", sealed)
	if err != nil {
		return nil, false
	}
	fl := new(flow)
	if json.Unmarshal(plain, fl) != nil || !a.now().Before(fl.Expires) {
		return nil, false
	}
	return fl, true
}

// person is what a sign-in service said about who signed in.
type person struct {
	issuer  string
	subject string
	name    string
	groups  []string
}

func (a *Auth) getOIDCCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	fl, good := a.openFlow(w, r)
	if !good || !equal(q.Get("state"), fl.State) {
		a.back(w, r, "/", "flowExpired")
		return
	}
	s := new(service)
	if err := a.load(ctx, kindService, fl.Service, s); err != nil {
		a.back(w, r, fl.Return, "serviceUnknown")
		return
	}
	if e := q.Get("error"); e != "" {
		if fl.Purpose == forRenew {
			a.endSession(ctx, fl.Session)
			a.back(w, r, fl.Return, "renewNeeded")
			return
		}
		a.note(ctx, r, Entry{Via: ViaService, Service: s.ID, Result: "serviceRefused"})
		a.back(w, r, fl.Return, "serviceRefused")
		return
	}
	who, err := a.exchange(ctx, s, fl, q)
	if err != nil {
		a.log.Info("signin: a sign-in service answer does not count", "service", s.ID, "err", err)
		a.note(ctx, r, Entry{Via: ViaService, Service: s.ID, Result: "serviceRefused"})
		if fl.Purpose == forRenew {
			a.endSession(ctx, fl.Session)
		}
		a.back(w, r, fl.Return, "serviceRefused")
		return
	}
	switch fl.Purpose {
	case forTest, forLink:
		a.bindService(w, r, s, fl, who)
	case forRenew:
		a.renewService(w, r, s, fl, who)
	default:
		a.serviceSignIn(w, r, s, fl, who)
	}
}

// exchange turns the code into the person, from an ID token that the
// service signed for this client and this trip. UserInfo only adds claims,
// and only for the same subject.
func (a *Auth) exchange(ctx context.Context, s *service, fl *flow, q url.Values) (*person, error) {
	if iss := q.Get("iss"); iss != "" && iss != s.Issuer {
		return nil, errors.New("the answer names another issuer")
	}
	rem, err := a.dial(ctx, s)
	if err != nil {
		return nil, err
	}
	tok, err := rem.config.Exchange(rem.ctx, q.Get("code"), oauth2.VerifierOption(fl.Verifier))
	if err != nil {
		return nil, err
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return nil, errors.New("no ID token")
	}
	idt, err := rem.verifier.Verify(rem.ctx, raw)
	if err != nil {
		return nil, err
	}
	if !equal(idt.Nonce, fl.Nonce) {
		return nil, errors.New("the ID token is for another sign-in")
	}
	claims := map[string]any{}
	if err := idt.Claims(&claims); err != nil {
		return nil, err
	}
	if aud, _ := claims["aud"].([]any); len(aud) > 1 && claims["azp"] != s.ClientID {
		return nil, errors.New("the ID token was issued to another party")
	}
	if claim(claims, s.GroupsClaim) == nil || claim(claims, s.NameClaim) == nil {
		if info, err := rem.provider.UserInfo(rem.ctx, oauth2.StaticTokenSource(tok)); err == nil && info.Subject == idt.Subject {
			extra := map[string]any{}
			if info.Claims(&extra) == nil {
				for k, v := range extra {
					if _, have := claims[k]; !have {
						claims[k] = v
					}
				}
			}
		}
	}
	return &person{issuer: s.Issuer, subject: idt.Subject, name: nameFrom(claims, s.NameClaim), groups: groupsFrom(claims, s.GroupsClaim)}, nil
}

// claim finds a claim by its name, or by a dotted path into nested claims
// such as realm_access.roles.
func claim(c map[string]any, path string) any {
	if v, ok := c[path]; ok {
		return v
	}
	var cur any = c
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		if cur, ok = m[part]; !ok {
			return nil
		}
	}
	return cur
}

// nameFrom is the name in claim, but an email only once the service says it
// verified it.
func nameFrom(c map[string]any, path string) string {
	name, _ := claim(c, path).(string)
	if path == "email" && c["email_verified"] != true {
		return ""
	}
	return strings.TrimSpace(name)
}

// groupsFrom reads a list of groups, one group, or an object whose keys are
// the groups.
func groupsFrom(c map[string]any, path string) []string {
	var out []string
	switch v := claim(c, path).(type) {
	case []any:
		for _, g := range v {
			if s, ok := g.(string); ok {
				out = append(out, s)
			}
		}
	case string:
		out = []string{v}
	case map[string]any:
		for k := range v {
			out = append(out, k)
		}
		sort.Strings(out)
	}
	return out
}

func (a *Auth) serviceSignIn(w http.ResponseWriter, r *http.Request, s *service, fl *flow, who *person) {
	ctx := r.Context()
	now := a.now()
	note := func(e Entry, code string) {
		e.Via, e.Service, e.Result = ViaService, s.ID, code
		a.note(ctx, r, e)
		a.back(w, r, fl.Return, code)
	}
	a.mu.Lock()
	if !a.serviceOn(ctx, s) {
		a.mu.Unlock()
		note(Entry{Name: a.typedName(ctx, who.name)}, "serviceOff")
		return
	}
	id := identityID(identityService, who.issuer, who.subject)
	idn := new(identity)
	err := a.load(ctx, kindIdentity, id, idn)
	var acc *account
	var docs []Doc
	switch {
	case err == nil:
		if acc, err = a.account(ctx, idn.Account); err != nil {
			a.mu.Unlock()
			note(Entry{Name: who.name}, "noAccount")
			return
		}
		if acc.Blocked {
			a.mu.Unlock()
			note(Entry{Account: acc.ID, Name: acc.Name}, "blocked")
			return
		}
		verdict, ended, err := a.judge(r, acc, s.rules, who.groups)
		if err != nil {
			a.mu.Unlock()
			a.internal(w, err)
			return
		}
		if verdict == shuts {
			err = a.cfg.Store.Apply(ctx, ended...)
			a.mu.Unlock()
			if err != nil {
				a.log.Warn("signin: ending the ways in of an account that left its group", "err", err)
			}
			a.runEndings(ctx)
			note(Entry{Account: acc.ID, Name: acc.Name}, "noGroup")
			return
		}
		docs = append(docs, ended...)
		if verdict == lowers {
			defer a.runEndings(ctx)
		}
		idn.Seen, idn.Name = now, who.name
		docs = append(docs, a.doc(kindIdentity, id, idn))
	case errors.Is(err, ErrNotFound):
		if !s.CreateOnFirst {
			a.mu.Unlock()
			note(Entry{Name: a.typedName(ctx, who.name)}, "noAccount")
			return
		}
		role, _ := a.roleFor(s.rules, who.groups)
		if role == "" {
			a.mu.Unlock()
			note(Entry{Name: a.typedName(ctx, who.name)}, "noGroup")
			return
		}
		if !validName(who.name) {
			a.mu.Unlock()
			note(Entry{}, "nameMissing")
			return
		}
		if _, err := a.byName(ctx, who.name); err == nil {
			a.mu.Unlock()
			note(Entry{Name: who.name}, "nameTaken")
			return
		}
		if a.limits.wait(newcomers, "newcomers", now) > 0 {
			a.mu.Unlock()
			note(Entry{Name: a.typedName(ctx, who.name)}, "throttled")
			return
		}
		a.limits.fail(newcomers, "newcomers", now)
		acc = &account{ID: newID(), Name: who.name, Role: role, Via: ViaService, Service: s.ID, Created: now}
		docs = append(docs, a.doc(kindIdentity, id, identity{
			Kind: identityService, Service: s.ID, Issuer: who.issuer, Subject: who.subject, Name: who.name, Account: acc.ID, Linked: now, Seen: now,
		}))
		defer a.note(ctx, r, Entry{Account: acc.ID, Name: acc.Name, Via: ViaService, Service: s.ID, Result: "newAccount"})
	default:
		a.mu.Unlock()
		a.internal(w, err)
		return
	}
	acc.Checked, acc.Groups, acc.Seen = now, who.groups, now
	ss := sessionOf(acc, ViaService, s.ID)
	ss.Checked = now
	docs = append(docs, a.doc(kindAccount, acc.ID, acc))
	docs = append(docs, a.newSession(w, r, a.foundIn(r), ss)...)
	err = a.cfg.Store.Apply(ctx, docs...)
	a.mu.Unlock()
	if err != nil {
		a.internal(w, err)
		return
	}
	v := a.visitorOf(acc, ViaService, s.ID)
	a.note(ctx, r, Entry{Account: acc.ID, Name: acc.Name, Via: ViaService, Service: s.ID, Result: "ok"})
	if a.cfg.Hooks.SignedIn != nil {
		a.cfg.Hooks.SignedIn(ctx, v, who.groups)
	}
	a.back(w, r, fl.Return, "")
}

// shutOut ends every way in of acc once its service groups stop letting
// it in. The caller holds mu.
func (a *Auth) shutOut(r *http.Request, acc *account) ([]Doc, error) {
	docs, err := a.endAll(r, acc.ID)
	if err != nil {
		return nil, err
	}
	acc.Epoch++
	return append(docs, a.doc(kindAccount, acc.ID, acc), a.ending(acc.ID, EndService)), nil
}

// renewService confirms a session that ran out of its day without asking the
// person anything. It never makes an account, and a different subject ends
// the session.
func (a *Auth) renewService(w http.ResponseWriter, r *http.Request, s *service, fl *flow, who *person) {
	ctx := r.Context()
	a.mu.Lock()
	sess := new(session)
	idn := new(identity)
	err := a.load(ctx, kindSession, fl.Session, sess)
	if err == nil {
		err = a.load(ctx, kindIdentity, identityID(identityService, who.issuer, who.subject), idn)
	}
	if err != nil || idn.Account != sess.Account || sess.Service != s.ID {
		a.mu.Unlock()
		a.endSession(ctx, fl.Session)
		a.back(w, r, fl.Return, "renewNeeded")
		return
	}
	acc, err := a.account(ctx, sess.Account)
	if err != nil || acc.Blocked || acc.Epoch != sess.Epoch || !a.serviceOn(ctx, s) {
		a.mu.Unlock()
		a.back(w, r, fl.Return, "renewNeeded")
		return
	}
	verdict, ended, err := a.judge(r, acc, s.rules, who.groups)
	if err == nil && verdict != keeps {
		if verdict == lowers {
			ended = append(ended, a.doc(kindAccount, acc.ID, acc))
		}
		err = a.cfg.Store.Apply(ctx, ended...)
	}
	if err != nil {
		a.mu.Unlock()
		a.internal(w, err)
		return
	}
	if verdict != keeps {
		a.mu.Unlock()
		a.runEndings(ctx)
		code := map[string]string{shuts: "noGroup", lowers: "renewNeeded"}[verdict]
		a.note(ctx, r, Entry{Account: acc.ID, Name: acc.Name, Via: ViaService, Service: s.ID, Result: code})
		a.back(w, r, fl.Return, code)
		return
	}
	now := a.now()
	sess.Checked, sess.Seen = now, now
	acc.Checked, acc.Groups = now, who.groups
	err = a.cfg.Store.Apply(ctx, a.doc(kindSession, fl.Session, sess), a.doc(kindAccount, acc.ID, acc))
	a.mu.Unlock()
	if err != nil {
		a.internal(w, err)
		return
	}
	a.back(w, r, fl.Return, "")
}

// bindService finishes a test sign-in or the linking of an identity: the
// person at the service becomes a way into the account that started it.
// A test sign-in also turns the service on, since it just proved that
// address, client and secret work together.
func (a *Auth) bindService(w http.ResponseWriter, r *http.Request, s *service, fl *flow, who *person) {
	ctx := r.Context()
	now := a.now()
	a.mu.Lock()
	acc, err := a.account(ctx, fl.Account)
	if err != nil || acc.Blocked || a.open.Load() || !a.sameSession(ctx, r, fl, acc) {
		a.mu.Unlock()
		a.back(w, r, fl.Return, "signInFirst")
		return
	}
	if err := a.load(ctx, kindService, s.ID, s); err != nil || (fl.Purpose == forLink && !s.On) {
		a.mu.Unlock()
		a.back(w, r, fl.Return, "serviceOff")
		return
	}
	id := identityID(identityService, who.issuer, who.subject)
	idn := new(identity)
	if err := a.load(ctx, kindIdentity, id, idn); err == nil && idn.Account != acc.ID {
		a.mu.Unlock()
		a.back(w, r, fl.Return, "identityTaken")
		return
	}
	docs := []Doc{a.doc(kindIdentity, id, identity{
		Kind: identityService, Service: s.ID, Issuer: who.issuer, Subject: who.subject, Name: who.name, Account: acc.ID, Linked: now, Seen: now,
	})}
	code := "linked"
	if fl.Purpose == forTest {
		s.TestedFor, s.Tested, s.TestedBy = s.Fingerprint, now, acc.ID
		s.On, s.Paused = true, false
		docs = append(docs, a.doc(kindService, s.ID, s))
		code = "testOk"
	}
	err = a.cfg.Store.Apply(ctx, docs...)
	a.mu.Unlock()
	if err != nil {
		a.internal(w, err)
		return
	}
	a.note(ctx, r, Entry{Account: acc.ID, Name: acc.Name, Via: ViaService, Service: s.ID, Result: code})
	a.back(w, r, fl.Return, code)
}

// What a service's groups mean for an account it already knows.
const (
	keeps  = "keeps"
	lowers = "lowers"
	shuts  = "shuts"
)

// judge applies groups under rl to acc. The owner's role never comes from
// outside. A lower role or no matching group ends acc's sessions and tokens,
// and the docs for that come back to apply. The caller holds mu.
func (a *Auth) judge(r *http.Request, acc *account, rl rules, groups []string) (string, []Doc, error) {
	role, mapped := a.roleFor(rl, groups)
	if acc.Owner || !mapped {
		return keeps, nil, nil
	}
	if role == "" {
		docs, err := a.shutOut(r, acc)
		return shuts, docs, err
	}
	lower := slices.Index(a.roles, role) > slices.Index(a.roles, acc.Role)
	acc.Role = role
	if !lower {
		return keeps, nil, nil
	}
	docs, err := a.endAll(r, acc.ID)
	acc.Epoch++
	return lowers, append(docs, a.ending(acc.ID, EndRole)), err
}

// serviceOn reads s again under mu and reports whether it still lets people
// in, which a reset or an admin may have changed while the browser was at
// the service.
func (a *Auth) serviceOn(ctx context.Context, s *service) bool {
	if a.open.Load() || a.load(ctx, kindService, s.ID, s) != nil {
		return false
	}
	return s.On
}

// sameSession reports whether the browser finishing a test or a link is
// still in the session that started it, and nothing ended that session on
// the way. The caller holds mu.
func (a *Auth) sameSession(ctx context.Context, r *http.Request, fl *flow, acc *account) bool {
	now := a.foundIn(r)
	if fl.Session == "" || now.cookie == "" || a.sessionID(now.cookie) != fl.Session {
		return false
	}
	s := new(session)
	return a.load(ctx, kindSession, fl.Session, s) == nil && s.Account == acc.ID && s.Epoch == acc.Epoch && s.Epoch == fl.Epoch
}

func (a *Auth) endSession(ctx context.Context, id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.cfg.Store.Apply(ctx, gone(kindSession, id)); err != nil {
		a.log.Warn("signin: ending a session", "err", err)
	}
}

// postServiceTicket hands a fresh admin the address that starts a test
// sign-in with the service, or a member the one that links their account.
func (a *Auth) postServiceTicket(w http.ResponseWriter, r *http.Request, f *found, purpose, id string) {
	var in struct {
		Return string `json:"return"`
	}
	if !readJSON(w, r, smallBody, &in) {
		return
	}
	if !a.fresh(f) {
		fail(w, http.StatusForbidden, "signInAgain")
		return
	}
	s := new(service)
	if err := a.load(r.Context(), kindService, id, s); err != nil {
		a.missing(w, err)
		return
	}
	if purpose == forLink && !s.On {
		fail(w, http.StatusConflict, "serviceOff")
		return
	}
	raw := token.Random(24)
	a.tickets.put(a.macHex("ticket", raw), ticket{account: f.v.Account, service: s.ID, purpose: purpose, expires: a.now().Add(ticketLife)}, a.now())
	q := url.Values{"ticket": {raw}, "return": {safeReturn(in.Return)}}
	ok(w, map[string]string{"url": oidcPath + s.ID + "?" + q.Encode()})
}

func (a *Auth) postServiceTest(w http.ResponseWriter, r *http.Request, f *found) {
	a.postServiceTicket(w, r, f, forTest, r.PathValue("id"))
}

func (a *Auth) postServiceCheck(w http.ResponseWriter, r *http.Request, _ *found) {
	s := new(service)
	if err := a.load(r.Context(), kindService, r.PathValue("id"), s); err != nil {
		a.missing(w, err)
		return
	}
	if _, err := a.dial(r.Context(), s); err != nil {
		fail(w, http.StatusBadGateway, "serviceUnreachable")
		return
	}
	ok(w, nil)
}
