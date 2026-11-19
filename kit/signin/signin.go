package signin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/keys"
	"github.com/junkerderprovinz/parleyport/kit/signin/internal/password"
	"github.com/junkerderprovinz/parleyport/kit/signin/internal/token"
)

// Via is the way a visitor came in.
type Via string

const (
	ViaAnyone   Via = "open" // nobody can sign in, so everyone is admin
	ViaPassword Via = "password"
	ViaPasskey  Via = "passkey"
	ViaService  Via = "service" // a sign-in service over OIDC
	ViaProxy    Via = "proxy"
	ViaToken    Via = "token"
	ViaDoor     Via = "door" // a way in the app keeps for itself
)

// Ending is why the package ended an account's ways in, for Hooks.Ended.
type Ending string

const (
	EndFirstPassword Ending = "firstPassword" // what was set up while the app was open
	EndPassword      Ending = "password"      // the password changed
	EndEverywhere    Ending = "everywhere"    // signed out everywhere
	EndReset         Ending = "reset"
	EndBlocked       Ending = "blocked"
	EndRemoved       Ending = "removed"
	EndOpened        Ending = "opened"  // the last password was removed
	EndService       Ending = "service" // the sign-in service turned the account away
	EndRole          Ending = "role"    // a lower role from the sign-in service or an admin
)

// ErrNotFresh is what Mint returns when the visitor has to sign in again
// before making a new lasting way in.
var ErrNotFresh = errors.New("signin: sign in again first")

// Config is what an app gives Open.
type Config struct {
	// Domain prefixes every label the package MACs and seals under, and
	// names the cookies. Lower-case letters and digits, as the app's
	// keys.Domain.
	Domain keys.Domain
	// Name is what authenticator apps and passkey prompts show, such as the
	// app's name. Empty is the domain.
	Name string
	// Store keeps the documents, Seal is the app's own key.
	Store Store
	Seal  Sealer
	// Roles are the app's roles, most rights first. Roles[0] is the admin.
	// Empty is just "admin".
	Roles []string
	// Owner is for apps with one local account. Its sign-in asks for no
	// name, and every other account comes from a sign-in service or the
	// proxy.
	Owner bool
	// Scopes are what an API token can be narrowed to. Empty is "read" and
	// "all".
	Scopes []string
	// TokenPrefix starts every API token, two to eight lower-case letters,
	// so secret scanners can find them.
	TokenPrefix string
	// Public is where people reach the app. Passkeys and sign-in services
	// need it, and it never comes from the request's Host.
	Public func() *url.URL
	// Proxies are the proxies whose X-Forwarded-For and X-Forwarded-Proto
	// count for the client address and for https. A trusted proxy for
	// sign-in is set apart, in the contract.
	Proxies []netip.Prefix
	// MinPassword is the shortest password in characters. Zero is 12.
	MinPassword int
	// Import returns the accounts the app had before it used the package.
	// It runs once, on a store without the package's documents, and what
	// it returns is written in one batch, so a failed import leaves nothing
	// behind and runs again on the next start.
	Import func(ctx context.Context) ([]Imported, error)
	Legacy Legacy
	Hooks  Hooks
	// Logger gets what goes wrong inside, and the reset code. Nil is
	// slog.Default.
	Logger *slog.Logger
	// Now is the clock, for tests. Nil is time.Now.
	Now func() time.Time
}

// Hooks are where the app takes part in sign-in.
type Hooks struct {
	// Ended runs after the package ended ways in for account, so the app
	// ends its own: paired phones, keys of its own, shares. It runs again,
	// also after a restart, until it returns nil.
	Ended func(ctx context.Context, account string, what Ending) error
	// SignedIn runs after every sign-in with the service groups the sign-in
	// service or proxy reported.
	SignedIn func(ctx context.Context, v Visitor, groups []string)
	// Doors are the ways in the app keeps for itself, such as a paired
	// phone, asked in order after the package found nobody.
	Doors []Door
	// Logged gets every entry of the sign-in log, for notifications.
	Logged func(ctx context.Context, e Entry)
}

// Door is a way in the app keeps for itself. It returns the account a
// request comes from, and Service and Scopes as the app sees them.
type Door func(r *http.Request) (Visitor, bool)

// Visitor is who a request comes from.
type Visitor struct {
	Account string   `json:"account,omitempty"`
	Name    string   `json:"name,omitempty"`
	Role    string   `json:"role"`
	Via     Via      `json:"via"`
	Service string   `json:"service,omitempty"` // the sign-in service or proxy, for ViaService and ViaProxy
	Scopes  []string `json:"scopes,omitempty"`  // ViaToken only

	roles    []string
	session  string
	signedAt time.Time
	epoch    int
}

// AtLeast reports whether v's role has at least the rights of role.
func (v Visitor) AtLeast(role string) bool {
	have, need := slices.Index(v.roles, v.Role), slices.Index(v.roles, role)
	return have >= 0 && need >= 0 && have <= need
}

// Auth is the sign-in of one app.
type Auth struct {
	cfg     Config
	d       string
	roles   []string
	scopes  []string
	minPass int
	now     func() time.Time
	log     *slog.Logger

	// mu covers every read, decide and write, so a reset cannot cross a
	// sign-in and two first passwords cannot both win.
	mu       sync.Mutex
	open     atomic.Bool
	imported time.Time

	argon   chan struct{}
	dummy   string
	limits  *limits
	steps   *steps
	reset   resetState
	logs    logState
	endMu   sync.Mutex
	used    usedChallenges
	tickets tickets

	handler http.Handler
	stop    chan struct{}
	done    sync.WaitGroup
}

var domainRE = regexp.MustCompile(`^[a-z][a-z0-9]{1,31}$`)

// Open checks cfg, runs nothing it does not need to, and returns the
// sign-in. A store it cannot read is an error, so a broken store never looks
// like an app without a password.
func Open(cfg Config) (*Auth, error) {
	if cfg.Store == nil || cfg.Seal == nil {
		return nil, errors.New("signin: Config needs a Store and a Seal")
	}
	if !domainRE.MatchString(string(cfg.Domain)) {
		return nil, fmt.Errorf("signin: domain %q must be lower-case letters and digits", cfg.Domain)
	}
	a := &Auth{cfg: cfg, d: string(cfg.Domain), now: cfg.Now, log: cfg.Logger, roles: cfg.Roles, scopes: cfg.Scopes, minPass: cfg.MinPassword}
	if a.now == nil {
		a.now = time.Now
	}
	if a.log == nil {
		a.log = slog.Default()
	}
	if len(a.roles) == 0 {
		a.roles = []string{"admin"}
	}
	if len(a.scopes) == 0 {
		a.scopes = []string{"read", "all"}
	}
	if a.minPass == 0 {
		a.minPass = 12
	}
	if a.cfg.Name == "" {
		a.cfg.Name = a.d
	}
	if a.cfg.TokenPrefix == "" {
		a.cfg.TokenPrefix = defaultPrefix(a.d)
	}
	if !token.ValidPrefix(a.cfg.TokenPrefix) {
		return nil, fmt.Errorf("signin: token prefix %q must be 2 to 8 lower-case letters", a.cfg.TokenPrefix)
	}
	if err := distinct("role", a.roles); err != nil {
		return nil, err
	}
	if err := distinct("scope", a.scopes); err != nil {
		return nil, err
	}
	dummy, err := password.Hash(a.passwordInput("not a password"))
	if err != nil {
		return nil, err
	}
	a.dummy = dummy
	a.argon = make(chan struct{}, min(4, max(2, runtime.GOMAXPROCS(0))))
	a.limits = newLimits()
	a.steps = newSteps()
	a.logs.last = map[string]logMark{}

	ctx := context.Background()
	if err := a.start(ctx); err != nil {
		return nil, err
	}
	a.runEndings(ctx)
	a.handler = a.routes()
	a.stop = make(chan struct{})
	a.done.Go(a.endLoop)
	return a, nil
}

// Close stops the package's background work.
func (a *Auth) Close() error {
	if a.stop != nil {
		select {
		case <-a.stop:
		default:
			close(a.stop)
		}
		a.done.Wait()
	}
	return nil
}

// Anyone reports whether nobody can sign in, so every visitor is admin.
func (a *Auth) Anyone() bool { return a.open.Load() }

// From returns the visitor Guard found for the request of ctx.
func From(ctx context.Context) (Visitor, bool) {
	f, ok := ctx.Value(ctxKey{}).(*found)
	if !ok || !f.ok {
		return Visitor{}, false
	}
	return f.v, true
}

// Mint runs mint, the making of a new lasting way in such as a key of the
// app's own, when the visitor of r signed in moments ago. It holds the lock
// a reset waits for, so nothing minted slips past a reset that runs at the
// same time. It returns ErrNotFresh when the visitor has to sign in again.
func (a *Auth) Mint(r *http.Request, mint func() error) error {
	f := a.foundIn(r)
	if !a.fresh(f) {
		return ErrNotFresh
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if f.v.Via != ViaAnyone {
		if _, err := a.stillValid(r.Context(), f); err != nil {
			return ErrNotFresh
		}
	} else if !a.open.Load() {
		return ErrNotFresh
	}
	return mint()
}

func (a *Auth) start(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	var m meta
	err := a.load(ctx, kindMeta, metaID, &m)
	if errors.Is(err, ErrNotFound) {
		m = meta{Version: 1, Created: a.now()}
		docs, err := a.importAll(ctx, &m)
		if err != nil {
			return err
		}
		if err := a.cfg.Store.Apply(ctx, append(docs, a.doc(kindMeta, metaID, m))...); err != nil {
			return fmt.Errorf("signin: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("signin: reading the store: %w", err)
	}
	a.imported = m.Imported
	return a.refreshOpen(ctx)
}

// refreshOpen works out from the store whether anyone can sign in. The
// caller holds mu.
func (a *Auth) refreshOpen(ctx context.Context) error {
	accounts, err := a.accounts(ctx)
	if err != nil {
		return fmt.Errorf("signin: reading the store: %w", err)
	}
	open := true
	for _, acc := range accounts {
		if acc.hasPassword() {
			open = false
		}
	}
	a.open.Store(open)
	return nil
}

func defaultPrefix(domain string) string {
	var b []byte
	for i := 0; i < len(domain) && len(b) < 8; i++ {
		if c := domain[i]; c >= 'a' && c <= 'z' {
			b = append(b, c)
		}
	}
	if len(b) < 2 {
		return "tok"
	}
	return string(b)
}

func distinct(what string, list []string) error {
	seen := map[string]bool{}
	for _, s := range list {
		if s == "" || seen[s] {
			return fmt.Errorf("signin: %s %q is empty or given twice", what, s)
		}
		seen[s] = true
	}
	return nil
}
