package signin

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/fortress"
	"github.com/junkerderprovinz/parleyport/kit/signin/internal/token"
)

const (
	defaultSecretHeader = "X-Proxy-Secret"
	maxGroups           = 64
	maxGroupLen         = 128
	minProbe            = 16
)

var headerRE = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_|~-]{1,64}$`)

// tunnel is the address every request opened through the fortress comes
// from. It can never be the proxy.
var tunnel = netip.MustParsePrefix("192.0.2.0/24")

// proxySettings are the trusted proxy: its one address, the headers it sets
// and the secret it sends along, which keeps another container that gets
// the proxy's old address after a restart from speaking for it.
type proxySettings struct {
	On           bool      `json:"on"`
	Paused       bool      `json:"paused,omitempty"`
	Preset       string    `json:"preset"`
	Address      string    `json:"address"`
	UserHeader   string    `json:"userHeader"`
	GroupsHeader string    `json:"groupsHeader"`
	SecretHeader string    `json:"secretHeader"`
	Secret       []byte    `json:"secret,omitempty"`
	Logout       string    `json:"logout"`
	Changed      time.Time `json:"changed,omitzero"`
	rules
}

func (a *Auth) proxySettings(ctx context.Context) (*proxySettings, error) {
	p := new(proxySettings)
	if err := a.load(ctx, kindProxy, proxyID, p); err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if p.SecretHeader == "" {
		p.SecretHeader = defaultSecretHeader
	}
	return p, nil
}

func (a *Auth) proxyLogout(ctx context.Context) string {
	p, err := a.proxySettings(ctx)
	if err != nil {
		return ""
	}
	return p.Logout
}

// proxyLook is what one request said through the proxy headers.
type proxyLook struct {
	from    netip.Addr
	through bool // from the proxy's address and not through the fortress tunnel
	secret  bool
	users   []string
	groups  []string
}

func (l proxyLook) user() string {
	if !l.through || !l.secret || len(l.users) != 1 {
		return ""
	}
	return l.users[0]
}

// lookAtProxy reads the proxy headers of r and takes them off the request,
// every request, so no handler or log after the guard can take a header a
// client set for one the proxy set.
func (a *Auth) lookAtProxy(ctx context.Context, r *http.Request) (*proxySettings, proxyLook) {
	p, err := a.proxySettings(ctx)
	if err != nil {
		a.log.Warn("signin: reading the proxy settings", "err", err)
		p = &proxySettings{}
	}
	look := proxyLook{from: peer(r)}
	if p.UserHeader == "" {
		return p, look
	}
	_, opened := fortress.Opened(r)
	addr, err := netip.ParseAddr(p.Address)
	look.through = err == nil && !opened && look.from == addr.Unmap()
	if len(p.Secret) > 0 {
		if secret, err := a.openFor("proxy-secret", "", p.Secret); err == nil {
			sent := r.Header.Values(p.SecretHeader)
			look.secret = len(sent) == 1 && equal(a.macHex("proxy-secret", sent[0]), a.macHex("proxy-secret", string(secret)))
		}
	}
	for _, v := range r.Header.Values(p.UserHeader) {
		look.users = append(look.users, strings.TrimSpace(v))
	}
	if p.GroupsHeader != "" {
		look.groups = splitGroups(r.Header.Values(p.GroupsHeader))
	}
	for _, h := range []string{p.UserHeader, p.GroupsHeader, p.SecretHeader} {
		if h != "" {
			r.Header.Del(h)
		}
	}
	return p, look
}

func splitGroups(values []string) []string {
	var out []string
	for _, v := range values {
		for _, g := range strings.Split(v, ",") {
			g = strings.TrimSpace(g)
			if g != "" && len(g) <= maxGroupLen && len(out) < maxGroups {
				out = append(out, g)
			}
		}
	}
	return out
}

// byProxy finds the visitor the proxy names. A name the proxy has not been
// bound to stays out, unless the proxy may make accounts and the groups let
// the name in.
func (a *Auth) byProxy(r *http.Request, p *proxySettings, look proxyLook) (Visitor, bool) {
	ctx := r.Context()
	name := look.user()
	if !p.On || name == "" || !validName(name) {
		return Visitor{}, false
	}
	now := a.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	id := identityID(identityProxy, "", name)
	idn := new(identity)
	err := a.load(ctx, kindIdentity, id, idn)
	role, _ := a.roleFor(p.rules, look.groups)
	var acc *account
	var ended []Doc
	switch {
	case err == nil:
		if acc, err = a.account(ctx, idn.Account); err != nil || acc.Blocked {
			return Visitor{}, false
		}
		was := acc.Role
		verdict, docs, err := a.judge(r, acc, p.rules, look.groups)
		if err != nil {
			return Visitor{}, false
		}
		if verdict == shuts {
			if err := a.cfg.Store.Apply(ctx, docs...); err != nil {
				a.log.Warn("signin: ending the ways in of an account that left its group", "err", err)
			}
			return Visitor{}, false
		}
		if verdict == keeps && acc.Role == was && now.Sub(acc.Checked) < seenEvery {
			return a.visitorOf(acc, ViaProxy, p.Preset), true
		}
		ended = docs
	case errors.Is(err, ErrNotFound):
		if !p.CreateOnFirst || role == "" {
			return Visitor{}, false
		}
		if _, err := a.byName(ctx, name); err == nil || a.limits.wait(newcomers, "newcomers", now) > 0 {
			return Visitor{}, false
		}
		a.limits.fail(newcomers, "newcomers", now)
		acc = &account{ID: newID(), Name: name, Role: role, Via: ViaProxy, Service: p.Preset, Created: now}
		idn = &identity{Kind: identityProxy, Subject: name, Name: name, Account: acc.ID, Linked: now}
		defer a.note(ctx, r, Entry{Account: acc.ID, Name: name, Via: ViaProxy, Service: p.Preset, Result: "newAccount"})
	default:
		return Visitor{}, false
	}
	acc.Checked, acc.Seen, acc.Groups = now, now, look.groups
	idn.Seen = now
	if err := a.cfg.Store.Apply(ctx, append(ended, a.doc(kindAccount, acc.ID, acc), a.doc(kindIdentity, id, idn))...); err != nil {
		a.log.Warn("signin: noting a visit through the proxy", "err", err)
		return Visitor{}, false
	}
	return a.visitorOf(acc, ViaProxy, p.Preset), true
}

type proxyView struct {
	On           bool        `json:"on"`
	Paused       bool        `json:"paused"`
	Preset       string      `json:"preset"`
	Address      string      `json:"address"`
	UserHeader   string      `json:"userHeader"`
	GroupsHeader string      `json:"groupsHeader"`
	SecretHeader string      `json:"secretHeader"`
	SecretSet    bool        `json:"secretSet"`
	Logout       string      `json:"logout"`
	Create       bool        `json:"createOnFirst"`
	Everyone     bool        `json:"everyone"`
	Groups       []groupRole `json:"groups"`
}

func viewProxy(p *proxySettings) proxyView {
	groups := p.Groups
	if groups == nil {
		groups = []groupRole{}
	}
	return proxyView{
		On: p.On, Paused: p.Paused, Preset: p.Preset, Address: p.Address, UserHeader: p.UserHeader, GroupsHeader: p.GroupsHeader,
		SecretHeader: p.SecretHeader, SecretSet: len(p.Secret) > 0, Logout: p.Logout, Create: p.CreateOnFirst, Everyone: p.Everyone, Groups: groups,
	}
}

func (a *Auth) getProxy(w http.ResponseWriter, r *http.Request, _ *found) {
	p, err := a.proxySettings(r.Context())
	if err != nil {
		a.internal(w, err)
		return
	}
	ok(w, map[string]any{"proxy": viewProxy(p)})
}

// validProxyAddress takes one plain address, never a range: nothing but
// the proxy itself may set the header.
func validProxyAddress(s string) bool {
	ip, err := netip.ParseAddr(strings.TrimSpace(s))
	return err == nil && !ip.IsUnspecified() && !ip.IsMulticast() && !tunnel.Contains(ip.Unmap()) && ip.Zone() == ""
}

func (a *Auth) putProxy(w http.ResponseWriter, r *http.Request, f *found) {
	var in struct {
		Preset       string       `json:"preset"`
		Address      string       `json:"address"`
		UserHeader   string       `json:"userHeader"`
		GroupsHeader string       `json:"groupsHeader"`
		SecretHeader string       `json:"secretHeader"`
		Logout       string       `json:"logout"`
		Create       *bool        `json:"createOnFirst"`
		Everyone     *bool        `json:"everyone"`
		Groups       *[]groupRole `json:"groups"`
	}
	if !readJSON(w, r, smallBody, &in) {
		return
	}
	if !validProxyAddress(in.Address) {
		fail(w, http.StatusBadRequest, "proxyAddressInvalid")
		return
	}
	if in.SecretHeader == "" {
		in.SecretHeader = defaultSecretHeader
	}
	for _, h := range []string{in.UserHeader, in.SecretHeader} {
		if !headerRE.MatchString(h) {
			fail(w, http.StatusBadRequest, "headerInvalid")
			return
		}
	}
	if in.GroupsHeader != "" && !headerRE.MatchString(in.GroupsHeader) {
		fail(w, http.StatusBadRequest, "headerInvalid")
		return
	}
	if in.Logout != "" && !strings.HasPrefix(in.Logout, "https://") && !strings.HasPrefix(in.Logout, "http://") {
		fail(w, http.StatusBadRequest, "badRequest")
		return
	}
	a.changeProxy(w, r, f, func(p *proxySettings) string {
		addr := strings.TrimSpace(in.Address)
		if addr != p.Address || in.UserHeader != p.UserHeader || in.GroupsHeader != p.GroupsHeader || in.SecretHeader != p.SecretHeader {
			p.On = false
		}
		p.Preset, p.Address, p.UserHeader, p.GroupsHeader, p.SecretHeader, p.Logout = in.Preset, addr, in.UserHeader, in.GroupsHeader, in.SecretHeader, in.Logout
		return a.setRules(&p.rules, in.Create, in.Everyone, in.Groups)
	})
}

func (a *Auth) postProxySecret(w http.ResponseWriter, r *http.Request, f *found) {
	secret := token.Random(32)
	sealed, err := a.sealFor("proxy-secret", "", []byte(secret))
	if err != nil {
		a.internal(w, err)
		return
	}
	a.changeProxy(w, r, f, func(p *proxySettings) string {
		p.Secret, p.On = sealed, false
		return ""
	}, "secret", secret)
}

// patchProxy turns the proxy on or off. On needs the very request to come
// through the proxy with its secret and one name, and that name must not be
// the probe the page sent as that header itself: a proxy that passed the
// probe on lets every client name itself.
func (a *Auth) patchProxy(w http.ResponseWriter, r *http.Request, f *found) {
	var in struct {
		On    bool   `json:"on"`
		Probe string `json:"probe"`
	}
	if !readJSON(w, r, smallBody, &in) {
		return
	}
	if in.On {
		if len(in.Probe) < minProbe {
			fail(w, http.StatusBadRequest, "probeMissing")
			return
		}
		look := f.proxy
		switch {
		case !look.through || !look.secret || len(look.users) != 1:
			fail(w, http.StatusConflict, "proxyNotThrough")
			return
		case look.users[0] == in.Probe:
			fail(w, http.StatusConflict, "proxyPassesClientHeader")
			return
		}
	}
	a.changeProxy(w, r, f, func(p *proxySettings) string {
		if in.On && len(p.Secret) == 0 {
			return "proxySecretMissing"
		}
		p.On = in.On
		if in.On {
			p.Paused = false
		}
		return ""
	})
}

// changeProxy applies change to the settings for a fresh admin and answers
// with them, and with extra pairs of key and value.
func (a *Auth) changeProxy(w http.ResponseWriter, r *http.Request, f *found, change func(*proxySettings) string, extra ...string) {
	if !a.fresh(f) {
		fail(w, http.StatusForbidden, "signInAgain")
		return
	}
	ctx := r.Context()
	var p *proxySettings
	code := ""
	err := a.Mint(r, func() error {
		var err error
		if p, err = a.proxySettings(ctx); err != nil {
			return err
		}
		if code = change(p); code != "" {
			return nil
		}
		p.Changed = a.now()
		return a.cfg.Store.Apply(ctx, a.doc(kindProxy, proxyID, p))
	})
	switch {
	case errors.Is(err, ErrNotFresh):
		fail(w, http.StatusForbidden, "signInAgain")
	case err != nil:
		a.internal(w, err)
	case code == "proxySecretMissing":
		fail(w, http.StatusConflict, code)
	case code != "":
		fail(w, http.StatusBadRequest, code)
	default:
		out := map[string]any{"proxy": viewProxy(p)}
		for i := 0; i+1 < len(extra); i += 2 {
			out[extra[i]] = extra[i+1]
		}
		ok(w, out)
	}
}

func (a *Auth) postProxyCheck(w http.ResponseWriter, r *http.Request, f *found) {
	var in struct {
		Probe string `json:"probe"`
	}
	if !readJSON(w, r, smallBody, &in) {
		return
	}
	look := f.proxy
	groups := look.groups
	if groups == nil {
		groups = []string{}
	}
	out := map[string]any{
		"from": look.from.String(), "viaProxy": look.through, "secret": look.secret,
		"users": len(look.users), "groups": groups,
		"passesClientHeader": in.Probe != "" && len(look.users) > 0 && look.users[0] == in.Probe,
	}
	if len(look.users) == 1 {
		out["user"] = look.users[0]
	}
	ok(w, out)
}

// postProxyIdentity binds the name the proxy gives this request to the
// signed-in account, so that name signs in as it from then on.
func (a *Auth) postProxyIdentity(w http.ResponseWriter, r *http.Request, f *found) {
	name := f.proxy.user()
	if name == "" || !validName(name) {
		fail(w, http.StatusConflict, "proxyNotThrough")
		return
	}
	if f.v.session == "" {
		fail(w, http.StatusForbidden, "forbidden")
		return
	}
	ctx := r.Context()
	id := identityID(identityProxy, "", name)
	taken := false
	err := a.Mint(r, func() error {
		idn := new(identity)
		if err := a.load(ctx, kindIdentity, id, idn); err == nil && idn.Account != f.v.Account {
			taken = true
			return nil
		}
		now := a.now()
		return a.cfg.Store.Apply(ctx, a.doc(kindIdentity, id, identity{Kind: identityProxy, Subject: name, Name: name, Account: f.v.Account, Linked: now, Seen: now}))
	})
	switch {
	case errors.Is(err, ErrNotFresh):
		fail(w, http.StatusForbidden, "signInAgain")
	case err != nil:
		a.internal(w, err)
	case taken:
		fail(w, http.StatusConflict, "identityTaken")
	default:
		ok(w, map[string]string{"name": name})
	}
}
