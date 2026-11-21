package signin

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ServiceSpec is a sign-in service the app sets up itself. It lets people
// in without a test sign-in, the contract cannot change or remove it, and
// after a reset it waits until an admin turns it on again, also across
// restarts. Provider is a preset whose scopes and claims fill in what is
// empty. StartPath and CallbackPath, paths below Config.Base, are where the
// service already knows the app, for an app that spoke to it before it
// used the package; the app mounts Handler on them too.
type ServiceSpec struct {
	ID, Provider, Name             string
	Issuer, ClientID, Secret, CA   string
	Scopes, NameClaim, GroupsClaim string
	StartPath, CallbackPath        string
}

var serviceIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

type service struct {
	ID          string    `json:"id"`
	Provider    string    `json:"provider"`
	Name        string    `json:"name"`
	Issuer      string    `json:"issuer"`
	ClientID    string    `json:"clientId"`
	Secret      []byte    `json:"secret"`
	Scopes      string    `json:"scopes"`
	NameClaim   string    `json:"nameClaim"`
	GroupsClaim string    `json:"groupsClaim"`
	CA          string    `json:"ca,omitempty"`
	On          bool      `json:"on"`
	Paused      bool      `json:"paused,omitempty"`
	Fingerprint string    `json:"fingerprint"`
	TestedFor   string    `json:"testedFor,omitempty"`
	Tested      time.Time `json:"tested,omitzero"`
	TestedBy    string    `json:"testedBy,omitempty"`
	Created     time.Time `json:"created"`
	// Pinned marks one of Config.Services.
	Pinned       bool   `json:"pinned,omitempty"`
	CallbackPath string `json:"callbackPath,omitempty"`
}

// flowPath is where the service sends the browser back, which the flow
// cookie is scoped to.
func (s *service) flowPath() string {
	if s.CallbackPath != "" {
		return s.CallbackPath
	}
	return oidcPath
}

func (s *service) tested() bool { return s.TestedFor != "" && s.TestedFor == s.Fingerprint }

type serviceView struct {
	ID          string    `json:"id"`
	Provider    string    `json:"provider"`
	Name        string    `json:"name"`
	Issuer      string    `json:"issuer"`
	ClientID    string    `json:"clientId"`
	SecretSet   bool      `json:"secretSet"`
	Scopes      string    `json:"scopes"`
	NameClaim   string    `json:"nameClaim"`
	GroupsClaim string    `json:"groupsClaim"`
	CA          bool      `json:"ca"`
	On          bool      `json:"on"`
	Paused      bool      `json:"paused"`
	Tested      bool      `json:"tested"`
	TestedAt    time.Time `json:"testedAt,omitzero"`
	Redirect    string    `json:"redirect"`
	FromConfig  bool      `json:"fromConfig"`
}

func (a *Auth) viewService(s *service) serviceView {
	return serviceView{
		ID: s.ID, Provider: s.Provider, Name: s.Name, Issuer: s.Issuer, ClientID: s.ClientID, SecretSet: len(s.Secret) > 0,
		Scopes: s.Scopes, NameClaim: s.NameClaim, GroupsClaim: s.GroupsClaim, CA: s.CA != "", On: s.On, Paused: s.Paused,
		Tested: s.tested(), TestedAt: s.Tested, Redirect: a.redirectURI(s), FromConfig: s.Pinned,
	}
}

func (a *Auth) redirectURI(s *service) string {
	u := a.public()
	if u == nil {
		return ""
	}
	path := s.flowPath()
	if path == oidcPath {
		path += "callback"
	}
	return u.Scheme + "://" + u.Host + a.under(path)
}

// pin writes Config.Services into the store, keeping whether a reset
// paused them, and removes the ones the app no longer names, with their
// sessions. The caller holds mu.
func (a *Auth) pin(ctx context.Context) error {
	stored, err := a.services(ctx)
	if err != nil {
		return fmt.Errorf("signin: reading the store: %w", err)
	}
	have := map[string]*service{}
	for _, s := range stored {
		have[s.ID] = s
	}
	named := map[string]bool{}
	var docs []Doc
	for _, spec := range a.cfg.Services {
		s, err := a.pinned(spec)
		if err != nil {
			return err
		}
		if named[s.ID] {
			return fmt.Errorf("signin: the service %q is given twice", s.ID)
		}
		named[s.ID] = true
		if old := have[s.ID]; old != nil {
			if !old.Pinned {
				return fmt.Errorf("signin: the service %q is also one an admin added", s.ID)
			}
			s.Created, s.Paused, s.On = old.Created, old.Paused, !old.Paused
		}
		docs = append(docs, a.doc(kindService, s.ID, s))
	}
	for _, s := range stored {
		if s.Pinned && !named[s.ID] {
			ended, err := a.serviceSessions(ctx, s.ID)
			if err != nil {
				return err
			}
			docs = append(append(docs, ended...), gone(kindService, s.ID))
		}
	}
	if len(docs) == 0 {
		return nil
	}
	return a.cfg.Store.Apply(ctx, docs...)
}

func (a *Auth) pinned(spec ServiceSpec) (*service, error) {
	bad := func(what string) (*service, error) {
		return nil, fmt.Errorf("signin: the service %q has %s", spec.ID, what)
	}
	p, known := preset(spec.Provider)
	switch {
	case !serviceIDRE.MatchString(spec.ID):
		return bad("an id that is not letters, digits, - and _")
	case !known:
		return bad("an unknown provider")
	case !validIssuer(spec.Issuer):
		return bad("an issuer that is not https")
	case spec.ClientID == "" || spec.Secret == "":
		return bad("no client id or secret")
	case spec.CA != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(spec.CA)):
		return bad("a CA that is not PEM")
	}
	for _, path := range []string{spec.StartPath, spec.CallbackPath} {
		if path != "" && (!strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#{}")) {
			return bad("a path that is not one")
		}
	}
	or := func(v, def string) string {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
		return def
	}
	s := &service{
		ID: spec.ID, Provider: p.ID, Name: or(spec.Name, p.ID), Issuer: spec.Issuer, ClientID: spec.ClientID,
		Scopes: or(spec.Scopes, p.Scopes), NameClaim: or(spec.NameClaim, p.NameClaim), GroupsClaim: or(spec.GroupsClaim, p.GroupsClaim),
		CA: spec.CA, On: true, Created: a.now(), Pinned: true, CallbackPath: spec.CallbackPath,
	}
	if !strings.Contains(" "+s.Scopes+" ", " openid ") {
		s.Scopes = "openid " + s.Scopes
	}
	sealed, err := a.sealFor("service-secret", s.ID, []byte(spec.Secret))
	if err != nil {
		return nil, err
	}
	s.Secret = sealed
	s.Fingerprint = shortID(s.Issuer, s.ClientID, a.macHex("service-secret", spec.Secret))
	s.TestedFor = s.Fingerprint
	return s, nil
}

func (a *Auth) services(ctx context.Context) ([]*service, error) {
	m, ids, err := listOf[service](ctx, a, kindService)
	if err != nil {
		return nil, err
	}
	out := make([]*service, 0, len(ids))
	for _, id := range ids {
		out = append(out, m[id])
	}
	return out, nil
}

func (a *Auth) getServices(w http.ResponseWriter, r *http.Request, _ *found) {
	all, err := a.services(r.Context())
	if err != nil {
		a.internal(w, err)
		return
	}
	out := []serviceView{}
	for _, s := range all {
		out = append(out, a.viewService(s))
	}
	ok(w, map[string]any{"services": out})
}

// serviceInput is what an admin sets on a sign-in service. Absent fields
// stay as they are.
type serviceInput struct {
	Provider    *string `json:"provider"`
	Name        *string `json:"name"`
	Issuer      *string `json:"issuer"`
	ClientID    *string `json:"clientId"`
	Secret      *string `json:"secret"`
	Scopes      *string `json:"scopes"`
	NameClaim   *string `json:"nameClaim"`
	GroupsClaim *string `json:"groupsClaim"`
	CA          *string `json:"ca"`
	On          *bool   `json:"on"`
}

func (a *Auth) postService(w http.ResponseWriter, r *http.Request, f *found) {
	var in serviceInput
	if !readJSON(w, r, smallBody, &in) {
		return
	}
	if in.Provider == nil {
		fail(w, http.StatusBadRequest, "serviceUnknown")
		return
	}
	p, known := preset(*in.Provider)
	if !known {
		fail(w, http.StatusBadRequest, "serviceUnknown")
		return
	}
	if in.Secret == nil || *in.Secret == "" {
		fail(w, http.StatusBadRequest, "secretMissing")
		return
	}
	s := &service{ID: newID(), Provider: p.ID, Name: p.ID, Scopes: p.Scopes, NameClaim: p.NameClaim, GroupsClaim: p.GroupsClaim, Created: a.now()}
	a.saveService(w, r, f, s, in, true)
}

func (a *Auth) patchService(w http.ResponseWriter, r *http.Request, f *found) {
	var in serviceInput
	if !readJSON(w, r, smallBody, &in) {
		return
	}
	s := new(service)
	if err := a.load(r.Context(), kindService, r.PathValue("id"), s); err != nil {
		a.missing(w, err)
		return
	}
	if s.Pinned {
		a.confirmPinned(w, r, f, s, in)
		return
	}
	a.saveService(w, r, f, s, in, false)
}

// confirmPinned turns a service of Config.Services on again after a reset
// paused it, which is all the contract may change about it.
func (a *Auth) confirmPinned(w http.ResponseWriter, r *http.Request, f *found, s *service, in serviceInput) {
	if in != (serviceInput{On: in.On}) || in.On == nil || !*in.On {
		fail(w, http.StatusConflict, "fromConfig")
		return
	}
	err := a.Mint(r, func() error {
		if err := a.load(r.Context(), kindService, s.ID, s); err != nil {
			return err
		}
		s.On, s.Paused = true, false
		return a.cfg.Store.Apply(r.Context(), a.doc(kindService, s.ID, s))
	})
	if err != nil {
		a.answer(w, r, f, err)
		return
	}
	ok(w, map[string]any{"service": a.viewService(s)})
}

// saveService applies in to s and writes it. A new issuer or client needs
// the secret again, so an admin session cannot point the stored secret at a
// server of its own, and any change to where the app signs in takes the
// service off until a new test sign-in.
func (a *Auth) saveService(w http.ResponseWriter, r *http.Request, f *found, s *service, in serviceInput, fresh bool) {
	if a.noPassword.Load() {
		fail(w, http.StatusConflict, "setPasswordFirst")
		return
	}
	set := func(dst *string, src *string) {
		if src != nil {
			*dst = strings.TrimSpace(*src)
		}
	}
	oldIssuer, oldClient := s.Issuer, s.ClientID
	set(&s.Name, in.Name)
	set(&s.Issuer, in.Issuer)
	set(&s.ClientID, in.ClientID)
	set(&s.Scopes, in.Scopes)
	set(&s.NameClaim, in.NameClaim)
	set(&s.GroupsClaim, in.GroupsClaim)
	set(&s.CA, in.CA)
	if !validIssuer(s.Issuer) {
		fail(w, http.StatusBadRequest, "issuerInvalid")
		return
	}
	if s.ClientID == "" || s.Name == "" || s.NameClaim == "" {
		fail(w, http.StatusBadRequest, "badRequest")
		return
	}
	if !strings.Contains(" "+s.Scopes+" ", " openid ") {
		s.Scopes = strings.TrimSpace("openid " + s.Scopes)
	}
	if s.CA != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(s.CA)) {
		fail(w, http.StatusBadRequest, "caInvalid")
		return
	}
	if (s.Issuer != oldIssuer || s.ClientID != oldClient) && !fresh && (in.Secret == nil || *in.Secret == "") {
		fail(w, http.StatusBadRequest, "secretAgain")
		return
	}
	if in.Secret != nil && *in.Secret != "" {
		sealed, err := a.sealFor("service-secret", s.ID, []byte(*in.Secret))
		if err != nil {
			a.internal(w, err)
			return
		}
		s.Secret = sealed
		s.Fingerprint = shortID(s.Issuer, s.ClientID, a.macHex("service-secret", *in.Secret))
	}
	wasOn := s.On
	if !s.tested() {
		s.On = false
	}
	if in.On != nil {
		if *in.On && !s.tested() {
			fail(w, http.StatusConflict, "serviceUntested")
			return
		}
		s.On = *in.On
		if s.On {
			s.Paused = false
		}
	}
	err := a.Mint(r, func() error {
		docs := []Doc{a.doc(kindService, s.ID, s)}
		if wasOn && !s.On {
			ended, err := a.serviceSessions(r.Context(), s.ID)
			if err != nil {
				return err
			}
			docs = append(docs, ended...)
		}
		return a.cfg.Store.Apply(r.Context(), docs...)
	})
	if errors.Is(err, ErrNotFresh) {
		a.notFresh(w, r, f)
		return
	}
	if err != nil {
		a.internal(w, err)
		return
	}
	ok(w, map[string]any{"service": a.viewService(s)})
}

func (a *Auth) deleteService(w http.ResponseWriter, r *http.Request, f *found) {
	id := r.PathValue("id")
	a.mu.Lock()
	if _, err := a.stillValid(r.Context(), f); err != nil {
		a.mu.Unlock()
		fail(w, http.StatusUnauthorized, "signInFirst")
		return
	}
	s := new(service)
	err := a.load(r.Context(), kindService, id, s)
	if err == nil && s.Pinned {
		a.mu.Unlock()
		fail(w, http.StatusConflict, "fromConfig")
		return
	}
	var docs []Doc
	if err == nil {
		docs, err = a.serviceSessions(r.Context(), id)
	}
	if err == nil {
		err = a.cfg.Store.Apply(r.Context(), append(docs, gone(kindService, id))...)
	}
	a.mu.Unlock()
	if err != nil {
		a.missing(w, err)
		return
	}
	ok(w, nil)
}

func validIssuer(issuer string) bool {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	return u.Scheme == "http" && (host == "localhost" || (ip != nil && ip.IsLoopback()))
}

// pauseOutside takes every sign-in service off and forgets the test
// sign-ins, for a reset or for an app that opens up again. Each service needs a new test sign-in before
// it lets anyone in, so whoever knew the old password cannot have left a
// working one behind. It returns how many services were on. The caller
// holds mu.
func (a *Auth) pauseOutside(ctx context.Context) (docs []Doc, services int, err error) {
	all, err := a.services(ctx)
	if err != nil {
		return nil, 0, err
	}
	for _, s := range all {
		if s.On {
			services++
		}
		if s.On || s.TestedFor != "" {
			s.Paused = s.Paused || s.On
			s.On, s.TestedFor = false, ""
			docs = append(docs, a.doc(kindService, s.ID, s))
		}
	}
	return docs, services, nil
}

// serviceSessions returns deletes for every session that came in through
// the sign-in service id. The caller holds mu.
func (a *Auth) serviceSessions(ctx context.Context, id string) ([]Doc, error) {
	return a.wipe(ctx, kindSession, func(b []byte) bool {
		var s session
		return json.Unmarshal(b, &s) == nil && s.Via == ViaService && s.Service == id
	})
}

func (a *Auth) offeredServices(ctx context.Context) ([]map[string]string, error) {
	out := []map[string]string{}
	all, err := a.services(ctx)
	if err != nil {
		return nil, err
	}
	for _, s := range all {
		if s.On && !a.waits(s) {
			out = append(out, map[string]string{"id": s.ID, "provider": s.Provider, "name": s.Name})
		}
	}
	return out, nil
}
