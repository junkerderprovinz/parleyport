package signin

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// groupRole maps one service group to a role.
type groupRole struct {
	Group string `json:"group"`
	Role  string `json:"role"`
}

// rules are who a sign-in service or the proxy lets in and as what.
type rules struct {
	// CreateOnFirst makes an account for someone the app does not know yet.
	CreateOnFirst bool `json:"createOnFirst"`
	// Everyone lets in anybody the service knows, with the lowest role.
	Everyone bool        `json:"everyone"`
	Groups   []groupRole `json:"groups"`
}

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
	rules
}

func (s *service) tested() bool { return s.TestedFor != "" && s.TestedFor == s.Fingerprint }

type serviceView struct {
	ID          string      `json:"id"`
	Provider    string      `json:"provider"`
	Name        string      `json:"name"`
	Issuer      string      `json:"issuer"`
	ClientID    string      `json:"clientId"`
	SecretSet   bool        `json:"secretSet"`
	Scopes      string      `json:"scopes"`
	NameClaim   string      `json:"nameClaim"`
	GroupsClaim string      `json:"groupsClaim"`
	CA          bool        `json:"ca"`
	On          bool        `json:"on"`
	Paused      bool        `json:"paused"`
	Tested      bool        `json:"tested"`
	TestedAt    time.Time   `json:"testedAt,omitzero"`
	Redirect    string      `json:"redirect"`
	Groups      []groupRole `json:"groups"`
	Create      bool        `json:"createOnFirst"`
	Everyone    bool        `json:"everyone"`
}

func (a *Auth) viewService(s *service) serviceView {
	groups := s.Groups
	if groups == nil {
		groups = []groupRole{}
	}
	return serviceView{
		ID: s.ID, Provider: s.Provider, Name: s.Name, Issuer: s.Issuer, ClientID: s.ClientID, SecretSet: len(s.Secret) > 0,
		Scopes: s.Scopes, NameClaim: s.NameClaim, GroupsClaim: s.GroupsClaim, CA: s.CA != "", On: s.On, Paused: s.Paused,
		Tested: s.tested(), TestedAt: s.Tested, Redirect: a.redirectURI(), Groups: groups, Create: s.CreateOnFirst, Everyone: s.Everyone,
	}
}

func (a *Auth) redirectURI() string {
	u := a.public()
	if u == nil {
		return ""
	}
	return strings.TrimSuffix(u.String(), "/") + oidcPath + "callback"
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
	Provider    *string      `json:"provider"`
	Name        *string      `json:"name"`
	Issuer      *string      `json:"issuer"`
	ClientID    *string      `json:"clientId"`
	Secret      *string      `json:"secret"`
	Scopes      *string      `json:"scopes"`
	NameClaim   *string      `json:"nameClaim"`
	GroupsClaim *string      `json:"groupsClaim"`
	CA          *string      `json:"ca"`
	On          *bool        `json:"on"`
	Create      *bool        `json:"createOnFirst"`
	Everyone    *bool        `json:"everyone"`
	Groups      *[]groupRole `json:"groups"`
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
	a.saveService(w, r, f, s, in, false)
}

// saveService applies in to s and writes it. A new issuer or client needs
// the secret again, so an admin session cannot point the stored secret at a
// server of its own, and any change to where the app signs in takes the
// service off until a new test sign-in.
func (a *Auth) saveService(w http.ResponseWriter, r *http.Request, f *found, s *service, in serviceInput, fresh bool) {
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
	if code := a.setRules(&s.rules, in.Create, in.Everyone, in.Groups); code != "" {
		fail(w, http.StatusBadRequest, code)
		return
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
		fail(w, http.StatusForbidden, "signInAgain")
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
	err := a.load(r.Context(), kindService, id, new(service))
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

// setRules applies a change to who gets in. Making accounts on first
// sign-in needs groups that say who, or, where the app has a role below
// admin, the choice of everyone. With admin as the only role, everyone would
// make every stranger who registers at the service an admin.
func (a *Auth) setRules(r *rules, create, everyone *bool, groups *[]groupRole) string {
	if groups != nil {
		var clean []groupRole
		for _, g := range *groups {
			g.Group = strings.TrimSpace(g.Group)
			if g.Group == "" {
				continue
			}
			if !slices.Contains(a.roles, g.Role) {
				return "roleUnknown"
			}
			clean = append(clean, g)
		}
		r.Groups = clean
	}
	if everyone != nil {
		r.Everyone = *everyone
	}
	if create != nil {
		r.CreateOnFirst = *create
	}
	if r.Everyone && len(a.roles) == 1 {
		return "everyoneWouldBeAdmin"
	}
	if r.CreateOnFirst && len(r.Groups) == 0 && !r.Everyone {
		return "groupsMissing"
	}
	return ""
}

// roleFor is the role groups give under r: the highest role of a matching
// group. mapped is false when r maps no groups at all.
func (a *Auth) roleFor(r rules, groups []string) (role string, mapped bool) {
	if len(r.Groups) == 0 {
		if r.Everyone {
			return a.roles[len(a.roles)-1], false
		}
		return "", false
	}
	best := -1
	for _, g := range r.Groups {
		if slices.Contains(groups, g.Group) {
			if i := slices.Index(a.roles, g.Role); best < 0 || i < best {
				best = i
			}
		}
	}
	if best < 0 {
		return "", true
	}
	return a.roles[best], true
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

// pauseOutside takes every sign-in service and the proxy off, stops them
// from making accounts and forgets their test sign-ins, for a reset or for
// an app that opens up again. Each service needs a new test sign-in before
// it lets anyone in, so whoever knew the old password cannot have left a
// working one behind. It returns how many services and whether the proxy
// were on. The caller holds mu.
func (a *Auth) pauseOutside(ctx context.Context) (docs []Doc, services int, proxy bool, err error) {
	all, err := a.services(ctx)
	if err != nil {
		return nil, 0, false, err
	}
	for _, s := range all {
		if s.On {
			services++
		}
		if s.On || s.CreateOnFirst || s.TestedFor != "" {
			s.Paused = s.Paused || s.On
			s.On, s.CreateOnFirst, s.TestedFor = false, false, ""
			docs = append(docs, a.doc(kindService, s.ID, s))
		}
	}
	p, err := a.proxySettings(ctx)
	if err != nil {
		return nil, 0, false, err
	}
	if proxy = p.On; p.On || p.CreateOnFirst {
		p.On, p.Paused, p.CreateOnFirst = false, true, false
		docs = append(docs, a.doc(kindProxy, proxyID, p))
	}
	return docs, services, proxy, nil
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
	if a.open.Load() {
		return out, nil
	}
	all, err := a.services(ctx)
	if err != nil {
		return nil, err
	}
	for _, s := range all {
		if s.On {
			out = append(out, map[string]string{"id": s.ID, "provider": s.Provider, "name": s.Name})
		}
	}
	return out, nil
}
