package signin

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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
	Open     bool      `json:"open,omitempty"`
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
	// open marks a test sign-in started while the app was open, for its
	// owner.
	open bool
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

// safeReturn keeps a way back that stays on the app: a path below its base,
// never an address of its own or one a browser reads as one.
func (a *Auth) safeReturn(s string) string {
	if !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.ContainsAny(s, "\\\r\n") {
		return a.base
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "" || u.Host != "" || !strings.HasPrefix(u.Path+"/", a.base) {
		return a.base
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
		Algs  []string `json:"id_token_signing_alg_values_supported"`
		Auth  string   `json:"authorization_endpoint"`
		Token string   `json:"token_endpoint"`
	}
	if err := p.Claims(&meta); err != nil {
		return nil, err
	}
	if s.Provider == "" || s.Provider == "custom" {
		if got := recognise(meta.Auth, meta.Token); got != s.Recognised || s.RecognisedFor != s.Issuer {
			a.remember(ctx, s.ID, s.Issuer, got)
		}
	}
	algs := slices.DeleteFunc(meta.Algs, func(alg string) bool { return alg == "none" || strings.HasPrefix(alg, "HS") })
	return &remote{
		ctx: ctx, provider: p,
		config: oauth2.Config{
			ClientID: s.ClientID, ClientSecret: string(secret), Endpoint: p.Endpoint(),
			RedirectURL: a.redirectURI(s), Scopes: strings.Fields(a.scopesOf(s)),
		},
		verifier: p.Verifier(&oidc.Config{ClientID: s.ClientID, SupportedSigningAlgs: algs}),
	}, nil
}

func (a *Auth) getOIDCStart(w http.ResponseWriter, r *http.Request) {
	a.startService(w, r, r.PathValue("id"), r.URL.Query().Get("return"))
}

// startService sends the browser to the sign-in service id, to come back
// to ret.
func (a *Auth) startService(w http.ResponseWriter, r *http.Request, id, ret string) {
	ctx := r.Context()
	f := a.foundIn(r)
	q := r.URL.Query()
	ret = a.safeReturn(ret)
	s := new(service)
	if err := a.load(ctx, kindService, id, s); err != nil {
		a.back(w, r, ret, "serviceUnknown")
		return
	}
	fl := flow{Service: s.ID, Purpose: forSignIn, Return: ret, Expires: a.now().Add(flowLife)}
	var opts []oauth2.AuthCodeOption
	switch {
	case q.Get("ticket") != "":
		tk, good := a.tickets.take(a.macHex("ticket", q.Get("ticket")), a.now())
		open := f.ok && f.v.Via == ViaAnyone && tk.open
		if !good || tk.service != s.ID || !f.ok || (!open && f.v.Account != tk.account) {
			a.back(w, r, ret, "flowExpired")
			return
		}
		fl.Purpose, fl.Account, fl.Session, fl.Epoch, fl.Open = tk.purpose, tk.account, f.v.session, f.v.epoch, open
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "login"))
	case q.Get("renew") != "":
		if f.renew != s.ID || f.cookie == "" {
			a.back(w, r, ret, "flowExpired")
			return
		}
		fl.Purpose, fl.Session = forRenew, a.sessionID(f.cookie)
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "none"))
	}
	if (a.waits(s) && !fl.Open) || (fl.Purpose != forTest && !s.On) {
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
	if err := a.sealFlow(w, r, fl, s.flowPath()); err != nil {
		a.internal(w, err)
		return
	}
	opts = append(opts, oauth2.S256ChallengeOption(fl.Verifier), oidc.Nonce(fl.Nonce))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, rem.config.AuthCodeURL(fl.State, opts...), http.StatusFound)
}

func (a *Auth) sealFlow(w http.ResponseWriter, r *http.Request, fl flow, path string) error {
	plain, err := json.Marshal(fl)
	if err != nil {
		return err
	}
	sealed, err := a.sealFor("oidc-flow", "", plain)
	if err != nil {
		return err
	}
	a.setCookie(w, r, "oidc", base64.RawURLEncoding.EncodeToString(sealed), path, flowLife)
	return nil
}

func (a *Auth) openFlow(w http.ResponseWriter, r *http.Request, path string) (*flow, bool) {
	raw := a.readCookie(r, "oidc", path)
	a.clearCookie(w, r, "oidc", path)
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
	a.callback(w, r, oidcPath)
}

// callback takes the browser back from a sign-in service on path, which
// the flow cookie and the service of the flow share.
func (a *Auth) callback(w http.ResponseWriter, r *http.Request, path string) {
	ctx := r.Context()
	q := r.URL.Query()
	fl, good := a.openFlow(w, r, path)
	if !good || !equal(q.Get("state"), fl.State) {
		a.back(w, r, a.base, "flowExpired")
		return
	}
	s := new(service)
	if err := a.load(ctx, kindService, fl.Service, s); err != nil || s.flowPath() != path {
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
	want := a.claimsOf(s)
	if claim(claims, want.GroupsClaim) == nil || claim(claims, want.NameClaim) == nil {
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
	return &person{issuer: s.Issuer, subject: idt.Subject, name: nameFrom(claims, want.NameClaim), groups: groupsFrom(claims, want.GroupsClaim)}, nil
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
// the groups. A claim that is there but empty gives an empty list and a
// missing one nil, so the app can tell someone who left every group from a
// service that sent none.
func groupsFrom(c map[string]any, path string) []string {
	var out []string
	switch v := claim(c, path).(type) {
	case []any:
		out = []string{}
		for _, g := range v {
			if s, ok := g.(string); ok {
				out = append(out, s)
			}
		}
	case string:
		out = []string{v}
	case map[string]any:
		out = []string{}
		for k := range v {
			out = append(out, k)
		}
		sort.Strings(out)
	}
	return out
}

func (a *Auth) serviceSignIn(w http.ResponseWriter, r *http.Request, s *service, fl *flow, who *person) {
	ctx := r.Context()
	a.mu.Lock()
	in, err := a.arrive(ctx, s, who)
	if err == nil && in.code != "" && len(in.docs) > 0 {
		err = a.cfg.Store.Apply(ctx, in.docs...)
	}
	if err != nil || in.code != "" {
		a.mu.Unlock()
		if err != nil {
			a.internal(w, err)
			return
		}
		a.runEndings(ctx)
		in.note.Via, in.note.Service, in.note.Result = ViaService, s.ID, in.code
		a.note(ctx, r, in.note)
		a.back(w, r, fl.Return, in.code)
		return
	}
	now := a.now()
	acc := in.acc
	acc.Checked, acc.Groups, acc.Seen = now, who.groups, now
	ss := sessionOf(acc, ViaService, s.ID)
	ss.Checked = now
	docs := append(in.docs, a.doc(kindAccount, acc.ID, acc))
	docs = append(docs, a.newSession(w, r, a.foundIn(r), ss)...)
	err = a.cfg.Store.Apply(ctx, docs...)
	a.mu.Unlock()
	if err != nil {
		a.internal(w, err)
		return
	}
	a.runEndings(ctx)
	if in.note.Result != "" {
		a.note(ctx, r, in.note)
	}
	v := a.visitorOf(acc, ViaService, s.ID)
	a.note(ctx, r, Entry{Account: acc.ID, Name: acc.Name, Via: ViaService, Service: s.ID, Result: "ok"})
	if a.cfg.Hooks.SignedIn != nil {
		a.cfg.Hooks.SignedIn(ctx, v, who.groups)
	}
	a.back(w, r, fl.Return, "")
}

// arrival is where someone a sign-in service let through ends up: an
// account and the docs for it, or a code that turns them away. note is
// what the log says about either.
type arrival struct {
	acc  *account
	docs []Doc
	note Entry
	code string
}

// arrive finds the account of who at s, by the binding, a claim by name or
// as a newcomer, and asks the app whether who may come in. The caller
// holds mu.
func (a *Auth) arrive(ctx context.Context, s *service, who *person) (arrival, error) {
	now := a.now()
	if !a.serviceOn(ctx, s) {
		return arrival{note: Entry{Name: a.typedName(ctx, who.name)}, code: "serviceOff"}, nil
	}
	id := identityID(identityService, who.issuer, who.subject)
	bound := identity{Kind: identityService, Service: s.ID, Issuer: who.issuer, Subject: who.subject, Name: who.name, Linked: now, Seen: now}
	var in arrival
	idn := new(identity)
	switch err := a.load(ctx, kindIdentity, id, idn); {
	case err == nil:
		if in.acc, err = a.account(ctx, idn.Account); err != nil {
			return arrival{note: Entry{Name: who.name}, code: "noAccount"}, nil
		}
		idn.Seen, idn.Name = now, who.name
		in.docs = append(in.docs, a.doc(kindIdentity, id, idn))
	case errors.Is(err, ErrNotFound):
		if in.acc, err = a.claimed(ctx, who); err != nil {
			return arrival{}, err
		}
		if in.acc != nil {
			bound.Account = in.acc.ID
			in.docs = append(in.docs, gone(kindClaim, claimID(who.issuer, who.name)), a.doc(kindIdentity, id, bound))
			in.note = Entry{Account: in.acc.ID, Name: in.acc.Name, Via: ViaService, Service: s.ID, Result: "claimed"}
		}
	default:
		return arrival{}, err
	}
	if in.acc != nil && in.acc.Blocked {
		return arrival{note: Entry{Account: in.acc.ID, Name: in.acc.Name}, code: "blocked"}, nil
	}
	if in.acc == nil {
		if !validName(who.name) {
			return arrival{code: "nameMissing"}, nil
		}
		free, err := a.nameFree(ctx, who.name, "")
		if err != nil {
			return arrival{}, err
		}
		if !free {
			return arrival{note: Entry{Name: who.name}, code: "nameTaken"}, nil
		}
		if a.limits.wait(newcomers, "newcomers", now) > 0 {
			return arrival{note: Entry{Name: a.typedName(ctx, who.name)}, code: "throttled"}, nil
		}
		in.acc = &account{Name: who.name, Role: a.roleOf(s), Via: ViaService, Service: s.ID, Created: now}
	}
	ended, err := a.admit(ctx, s, who, in.acc)
	if errors.Is(err, errNotAdmitted) {
		return arrival{docs: ended, note: Entry{Account: in.acc.ID, Name: who.name}, code: "notAdmitted"}, nil
	}
	if err != nil {
		return arrival{}, err
	}
	in.docs = append(in.docs, ended...)
	if in.acc.ID == "" {
		a.limits.fail(newcomers, "newcomers", now)
		if err := a.newcomer(ctx, in.acc, who); err != nil {
			a.log.Warn("signin: the app took no new account", "service", s.ID, "err", err)
			return arrival{note: Entry{Name: who.name}, code: "noAccount"}, nil
		}
		bound.Account = in.acc.ID
		in.docs = append(in.docs, a.doc(kindIdentity, id, bound))
		in.note = Entry{Account: in.acc.ID, Name: in.acc.Name, Via: ViaService, Service: s.ID, Result: "newAccount"}
	}
	return in, nil
}

var errNotAdmitted = errors.New("signin: the app turned the visitor away")

// admit asks Hooks.Admit whether who may come in through s as acc, whose
// id is empty for a newcomer, and applies the role it gives. Turning away
// an account that is not the owner ends its sessions and tokens, and so
// does a lower role. It returns the docs for that. The caller holds mu.
func (a *Auth) admit(ctx context.Context, s *service, who *person, acc *account) ([]Doc, error) {
	if a.cfg.Hooks.Admit == nil {
		return nil, nil
	}
	in := Arrival{Service: s.ID, Issuer: who.issuer, Subject: who.subject, Name: who.name, Groups: who.groups}
	if acc.ID != "" {
		in.Account, in.Role = acc.ID, a.visitorOf(acc, acc.Via, acc.Service).Role
	}
	role, err := a.cfg.Hooks.Admit(ctx, in)
	if err == nil && role != "" && !slices.Contains(a.roles, role) {
		err = fmt.Errorf("signin: Admit gave the unknown role %q", role)
	}
	if err != nil {
		a.log.Info("signin: the app turned away someone a sign-in service let through", "service", s.ID, "err", err)
		if in.Account == "" || acc.Owner {
			return nil, errNotAdmitted
		}
		docs, err := a.endWays(ctx, acc, EndRefused)
		if err != nil {
			return nil, err
		}
		return docs, errNotAdmitted
	}
	if role == "" || acc.Owner || role == acc.Role {
		return nil, nil
	}
	lower := slices.Index(a.roles, role) > slices.Index(a.roles, acc.Role)
	acc.Role = role
	if in.Account == "" {
		return nil, nil
	}
	if err := a.changing(ctx, changeOf(ChangeRole, acc)); err != nil {
		return nil, err
	}
	if !lower {
		return nil, nil
	}
	return a.endWays(ctx, acc, EndRole)
}

// endWays raises acc's epoch and ends its sessions and tokens for why. The
// caller holds mu.
func (a *Auth) endWays(ctx context.Context, acc *account, why Ending) ([]Doc, error) {
	acc.Epoch++
	docs, err := a.endAll(ctx, acc.ID)
	if err != nil {
		return nil, err
	}
	docs = append(docs, a.endingsOf(acc, why)...)
	return append(docs, a.doc(kindAccount, acc.ID, acc)), nil
}

// newcomer gives acc, which a sign-in service brings for who, an id and
// tells the app. The caller holds mu.
func (a *Auth) newcomer(ctx context.Context, acc *account, who *person) error {
	id, err := a.newAccountID(ctx)
	if err != nil {
		return err
	}
	acc.ID = id
	c := changeOf(ChangeCreate, acc)
	c.Issuer, c.Subject = who.issuer, who.subject
	return a.changing(ctx, c)
}

// renewService confirms a session that ran out of its day without asking the
// person anything, and asks the app again whether they may come in. It
// never makes an account, and a different subject ends the session.
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
	docs, err := a.admit(ctx, s, who, acc)
	if errors.Is(err, errNotAdmitted) || (err == nil && acc.Epoch != sess.Epoch) {
		code := "renewNeeded"
		if err != nil {
			code = "notAdmitted"
		}
		err = a.cfg.Store.Apply(ctx, append(docs, gone(kindSession, fl.Session))...)
		a.mu.Unlock()
		if err != nil {
			a.internal(w, err)
			return
		}
		a.runEndings(ctx)
		a.back(w, r, fl.Return, code)
		return
	}
	if err != nil {
		a.mu.Unlock()
		a.internal(w, err)
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
	if a.cfg.Hooks.SignedIn != nil {
		v := a.visitorOf(acc, ViaService, s.ID)
		v.session, v.signedAt, v.epoch = fl.Session, sess.SignedAt, sess.Epoch
		a.cfg.Hooks.SignedIn(ctx, v, who.groups)
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
	stillOpen := fl.Open && a.Anyone()
	if err != nil || acc.Blocked || (!stillOpen && (a.waits(s) || !a.sameSession(ctx, r, fl, acc))) {
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
	if stillOpen && fl.Purpose == forTest {
		closing, err := a.closeByService(w, r, s, acc)
		if err != nil {
			a.mu.Unlock()
			a.internal(w, err)
			return
		}
		docs = append(docs, closing...)
	}
	err = a.cfg.Store.Apply(ctx, docs...)
	if err == nil {
		err = a.refreshOpen(ctx)
	}
	a.mu.Unlock()
	if err != nil {
		a.internal(w, err)
		return
	}
	a.runEndings(ctx)
	a.note(ctx, r, Entry{Account: acc.ID, Name: acc.Name, Via: ViaService, Service: s.ID, Result: code})
	a.back(w, r, fl.Return, code)
}

// closeByService is what closes an open app when its first sign-in service
// passed the test with acc, its owner: what was made while it was open
// ends, and the browser is signed in through the service. The caller
// holds mu and applies the docs.
func (a *Auth) closeByService(w http.ResponseWriter, r *http.Request, s *service, acc *account) ([]Doc, error) {
	docs, err := a.openTokens(r.Context())
	if err != nil {
		return nil, err
	}
	now := a.now()
	acc.Checked, acc.Seen = now, now
	docs = append(docs, a.endingsOf(acc, EndFirstPassword)...)
	docs = append(docs, a.doc(kindAccount, acc.ID, acc))
	ss := sessionOf(acc, ViaService, s.ID)
	ss.Checked = now
	return append(docs, a.newSession(w, r, a.foundIn(r), ss)...), nil
}

// serviceOn reads s again under mu and reports whether it still lets people
// in, which a reset or an admin may have changed while the browser was at
// the service.
func (a *Auth) serviceOn(ctx context.Context, s *service) bool {
	if a.load(ctx, kindService, s.ID, s) != nil || a.waits(s) {
		return false
	}
	return s.On
}

// waits reports whether s lets nobody in because the app is open. A
// service an admin added closes the app once it is on.
func (a *Auth) waits(*service) bool { return a.Anyone() }

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
		a.notFresh(w, r, f)
		return
	}
	s := new(service)
	if err := a.load(r.Context(), kindService, id, s); err != nil {
		a.missing(w, err)
		return
	}
	if purpose == forTest && s.Pinned {
		fail(w, http.StatusConflict, "fromConfig")
		return
	}
	if purpose == forLink && !s.On {
		fail(w, http.StatusConflict, "serviceOff")
		return
	}
	tk := ticket{account: f.v.Account, service: s.ID, purpose: purpose, expires: a.now().Add(ticketLife)}
	if f.v.Via == ViaAnyone {
		a.mu.Lock()
		acc, docs, err := a.openOwner(r.Context())
		if err == nil && len(docs) > 0 {
			err = a.cfg.Store.Apply(r.Context(), docs...)
		}
		a.mu.Unlock()
		if err != nil {
			a.answer(w, r, f, err)
			return
		}
		tk.account, tk.open = acc.ID, true
	}
	raw := token.Random(24)
	a.tickets.put(a.macHex("ticket", raw), tk, a.now())
	q := url.Values{"ticket": {raw}, "return": {a.safeReturn(in.Return)}}
	ok(w, map[string]string{"url": a.under(oidcPath) + s.ID + "?" + q.Encode()})
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
