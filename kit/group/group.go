// Package group connects the instances of one app that share a phrase.
//
// Members on one network call each other directly, found by their multicast
// announce, by a sweep of the network or through the address a browser used.
// Members elsewhere call each other through a relay. Either way every call and
// answer is sealed under the frame key and signed with the member's own key,
// and a direct call is tagged with the peer-auth key on top, so neither a
// relay nor the network in between can read, forge or replay one.
//
// The phrase only lets a device in to ask. Its key is pinned on its first
// signed call and refused until somebody at an instance approves it there.
// The approval, and a removal, are passed on to the other instances, which
// take them only from an instance they approved themselves.
//
// A fortress builds on a Group without changing it: it opens one under its
// own domain, wraps the handler with its permissions, which it looks up by
// CallerOf, and reads Members for the instances of every app.
package group

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/keys"
	"github.com/junkerderprovinz/parleyport/kit/lan"
	"github.com/junkerderprovinz/parleyport/kit/member"
	"github.com/junkerderprovinz/parleyport/kit/relay"
)

// DirectPath is where an app mounts DirectHandler.
const DirectPath = "/api/group/call"

// MaxCallBytes is the most a call may carry. It keeps a call small enough for
// the direct route of every member, whatever wraps it on the way.
const MaxCallBytes = 1 << 20

// RelayMode is which relay a group uses for members it cannot reach directly.
type RelayMode string

// The relay modes. The zero value is RelayProject.
const (
	RelayProject RelayMode = "project"
	RelayOwn     RelayMode = "own"
	RelayOff     RelayMode = "off"
)

// Self is what the other members see of this instance.
type Self struct {
	Name string
	// Deployment is how it runs, such as "container" or "desktop".
	Deployment string
	// Address is where its web interface is.
	Address string
	// DirectURL is where DirectHandler answers, as far as the app can tell. An
	// address learned by NoteAddress takes its place.
	DirectURL string
}

// Store keeps a group's state under the app's seal: who is approved, who was
// removed and the address learned for this instance. Load returns nothing for
// a group that never saved.
type Store interface {
	Load() ([]byte, error)
	Save([]byte) error
}

// Config is what a Group runs on. Domain, Secret, Identity and Store are
// required.
type Config struct {
	Domain keys.Domain
	// Signing names the labels calls and answers are signed under; the zero
	// value means Domain.Signing().
	Signing keys.Signing
	// Secret is what the phrase encodes.
	Secret []byte
	// Identity is this instance's member key, of kind member.KindInstance.
	Identity member.Identity
	Self     Self
	Relay    RelayMode
	// RelayURL is the own relay's address, for RelayOwn.
	RelayURL string
	// LAN is where members on this network announce themselves, already
	// started by the app; nil finds them through the relay alone.
	LAN   *lan.Service
	Store Store
	// OnRemoved runs, at most once and on its own goroutine, when an approved
	// instance says this one was taken out of the group. The app leaves it.
	OnRemoved func()
}

// State is where a member stands with this instance.
type State string

// The states of a member.
const (
	// StateUnknown is a member this instance sees but that never signed a
	// call here.
	StateUnknown State = ""
	// StatePending is a member whose key is pinned and waits for approval.
	StatePending State = "pending"
	// StateApproved is a member whose calls are served.
	StateApproved State = "approved"
)

// Member is another member of the group as this instance knows it.
type Member struct {
	ID         string
	Kind       member.Kind
	Name       string
	Deployment string
	// Address is where its web interface is.
	Address string
	// Key is its member key once it signed a call here.
	Key   ed25519.PublicKey
	State State
	// Direct means it is reachable on this network now, Relay that it is on
	// the relay now. A member with neither is away.
	Direct bool
	Relay  bool
	// Awaiting means it said recently that this instance waits for its
	// approval there.
	Awaiting bool
	LastSeen time.Time
}

// Online reports whether m can be called now.
func (m Member) Online() bool { return m.Direct || m.Relay }

// Errors of Call, Approve and Remove.
var (
	ErrUnreachable  = errors.New("group: the member is not reachable")
	ErrTooLarge     = errors.New("group: the call carries more than MaxCallBytes")
	ErrNoSuchMember = errors.New("group: no member with that id signed a call here")
	ErrRemoved      = errors.New("group: that member was taken out of the group")
)

// Group is this instance's side of its group.
type Group struct {
	serve     http.Handler
	self      string
	identity  member.Identity
	signing   keys.Signing
	frameKey  []byte
	peerAuth  []byte
	headers   headers
	info      Self
	store     Store
	lan       *lan.Service
	client    *relay.Client
	onRemoved func()

	replay  *relay.ReplayGuard
	limits  *memberLimits
	hc      *http.Client
	slots   chan struct{}
	probing chan struct{}
	kick    chan struct{}
	removed sync.Once

	mu       sync.Mutex
	st       state
	dirty    bool
	closed   bool
	addrs    map[string]*remoteAddr
	failed   map[string]time.Time
	awaiting map[string]time.Time
	heard    map[string]bool
	greeted  map[string]time.Time
	synced   map[string]time.Time
	swept    time.Time

	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	closeOnce sync.Once
	closeErr  error
}

// Open joins the group cfg names and answers the calls of its members with
// serve, which sees each caller through CallerOf. It returns at once; the
// relay, the network and the members are reached in the background.
func Open(cfg Config, serve http.Handler) (*Group, error) {
	switch {
	case cfg.Domain == "":
		return nil, errors.New("group: no domain")
	case len(cfg.Secret) == 0:
		return nil, errors.New("group: no secret")
	case cfg.Identity.Kind() != member.KindInstance:
		return nil, errors.New("group: the identity has to be an instance's")
	case cfg.Store == nil:
		return nil, errors.New("group: no store")
	}
	signing := cfg.Signing
	if signing == (keys.Signing{}) {
		signing = cfg.Domain.Signing()
	}
	groupKey := cfg.Domain.GroupKey(cfg.Secret)
	raw, err := cfg.Store.Load()
	if err != nil {
		return nil, fmt.Errorf("group: reading the store: %w", err)
	}
	st, err := loadState(raw, groupKey)
	if err != nil {
		return nil, err
	}
	cfg.Self.Name = relay.ClipName(cfg.Self.Name)
	cfg.Self.Address = relay.FitAddress(cfg.Self.Address)

	ctx, cancel := context.WithCancel(context.Background())
	g := &Group{
		serve:     serve,
		self:      cfg.Identity.ID(),
		identity:  cfg.Identity,
		signing:   signing,
		frameKey:  cfg.Domain.FrameKey(cfg.Secret),
		peerAuth:  cfg.Domain.PeerAuthKey(cfg.Secret),
		headers:   headersFor(cfg.Domain),
		info:      cfg.Self,
		store:     cfg.Store,
		lan:       cfg.LAN,
		onRemoved: cfg.OnRemoved,
		replay:    relay.NewReplayGuard(),
		limits:    newMemberLimits(),
		hc:        directClient(),
		slots:     make(chan struct{}, maxDirectCalls),
		probing:   make(chan struct{}, maxProbeBacks),
		kick:      make(chan struct{}, 1),
		st:        st,
		addrs:     map[string]*remoteAddr{},
		failed:    map[string]time.Time{},
		awaiting:  map[string]time.Time{},
		heard:     map[string]bool{},
		greeted:   map[string]time.Time{},
		synced:    map[string]time.Time{},
		ctx:       ctx,
		cancel:    cancel,
	}
	url, err := relayURL(cfg)
	if err == nil && url != "" {
		g.client, err = g.dial(cfg, url, groupKey)
	}
	if err != nil {
		cancel()
		return nil, err
	}
	if g.lan != nil {
		g.lan.SetAccept(g.acceptAnnounce)
		g.announce()
	}
	if g.client != nil {
		g.client.Start()
	}
	g.wg.Go(g.run)
	return g, nil
}

// relayURL is the relay cfg names, "" for none.
func relayURL(cfg Config) (string, error) {
	switch cfg.Relay {
	case RelayProject, "":
		return relay.DefaultURL, nil
	case RelayOwn:
		return cfg.RelayURL, nil
	case RelayOff:
		return "", nil
	}
	return "", fmt.Errorf("group: unknown relay mode %q", cfg.Relay)
}

func (g *Group) dial(cfg Config, url, groupKey string) (*relay.Client, error) {
	id := cfg.Identity
	return relay.NewClient(relay.ClientOptions{
		URL:      url,
		Key:      groupKey,
		FrameKey: g.frameKey,
		Signing:  g.signing,
		Self:     relay.Announce{Name: cfg.Self.Name, Deployment: cfg.Self.Deployment, Address: cfg.Self.Address},
		Identity: &id,
		Trusts:   g.trustsAnswer,
		Serve:    g.handle,
		OnChange: g.poke,
	})
}

// directClient calls members on this network. Instances serve self-signed
// certificates, so there is nothing to verify against: calls and answers are
// sealed under the frame key and signed with member keys, and the channel
// relies on TLS for neither secrecy nor authenticity.
func directClient() *http.Client {
	return &http.Client{
		Timeout: callTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext:         (&net.Dialer{Timeout: directDialTimeout}).DialContext,
			TLSHandshakeTimeout: directDialTimeout,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // G402: see the comment above
		},
	}
}

// Close leaves the relay and the network, waits for every call this group
// serves or makes in the background, and saves what changed. A closed group
// answers direct calls like an instance in no group.
func (g *Group) Close() error {
	g.closeOnce.Do(func() {
		g.look(time.Now())
		g.mu.Lock()
		g.closed = true
		g.mu.Unlock()
		g.cancel()
		if g.client != nil {
			_ = g.client.Close()
		}
		if g.lan != nil {
			g.lan.SetSelf(lan.Peer{}, nil)
			g.lan.SetAccept(nil)
		}
		g.wg.Wait()
		g.mu.Lock()
		if g.dirty {
			g.closeErr = g.saveLocked()
		}
		g.mu.Unlock()
		g.hc.CloseIdleConnections()
	})
	return g.closeErr
}

// enter counts one more piece of work Close has to wait for, or reports false
// once the group is closed. Every enter that returns true is ended by
// g.wg.Done.
func (g *Group) enter() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return false
	}
	g.wg.Add(1)
	return true
}

// poke asks the background loop to look around now rather than at its next
// tick, such as when somebody arrives on the relay.
func (g *Group) poke() {
	select {
	case g.kick <- struct{}{}:
	default:
	}
}

// RelayConnected reports whether the relay socket is up, which an empty member
// list cannot tell.
func (g *Group) RelayConnected() bool {
	return g.client != nil && g.client.Connected()
}

// Members lists every member this instance can call now or knows from before,
// this one excluded, sorted by name.
func (g *Group) Members() []Member {
	view := g.look(time.Now())
	out := make([]Member, 0, len(view))
	for _, m := range view {
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// look merges what the network, the relay and the store say about each
// member, and records in the store what it saw of the ones known there.
func (g *Group) look(now time.Time) map[string]*Member {
	var peers []lan.Peer
	if g.lan != nil {
		peers = g.lan.Members()
	}
	var sibs []relay.Announce
	if g.client != nil {
		sibs = g.client.Siblings()
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	view := map[string]*Member{}
	get := func(id string, kind member.Kind) *Member {
		m := view[id]
		if m == nil {
			m = &Member{ID: id, Kind: kind}
			view[id] = m
		}
		return m
	}
	for _, p := range peers {
		m := get(p.ID, member.KindInstance)
		fill(m, p.Name, p.Deployment, p.Address)
		m.Direct = !g.downLocked(p.URL, now)
	}
	for _, s := range sibs {
		id, kind := s.InstanceID, member.KindInstance
		if s.Client {
			if s.Member != "" {
				id = s.Member
			}
			if kind = member.Kind(s.Deployment); kindOfID(id) != kind {
				continue
			}
		}
		m := get(id, kind)
		fill(m, s.Name, s.Deployment, s.Address)
		m.Relay = true
	}
	for id, a := range g.addrs {
		if g.confirmedLocked(a, now) {
			m := get(id, member.KindInstance)
			fill(m, a.name, a.deployment, "")
			m.Direct = true
		}
	}
	for id, rec := range g.st.Members {
		m := get(id, rec.Kind)
		m.Key, m.State = rec.Key, StatePending
		if rec.Approved {
			m.State = StateApproved
		}
		if m.Online() {
			if rec.seenAs(m, now) {
				g.st.Members[id] = rec
				g.dirty = true
			}
		} else {
			fill(m, rec.Name, rec.Deployment, rec.Address)
			m.LastSeen = rec.Seen
			if rec.Used.After(m.LastSeen) {
				m.LastSeen = rec.Used
			}
		}
	}
	for id, m := range view {
		if _, gone := g.st.Removed[id]; gone || id == g.self {
			delete(view, id)
			continue
		}
		if m.Online() {
			m.LastSeen = now
		}
		if at, ok := g.awaiting[id]; ok && now.Sub(at) < awaitWindow {
			m.Awaiting = true
		}
	}
	return view
}

// fill sets what m does not know yet.
func fill(m *Member, name, deployment, address string) {
	if m.Name == "" {
		m.Name = name
	}
	if m.Deployment == "" {
		m.Deployment = deployment
	}
	if m.Address == "" {
		m.Address = address
	}
}

// Caller is the member a call came from: the id its pinned key speaks for.
type Caller struct {
	ID   string
	Kind member.Kind
	Key  ed25519.PublicKey
}

type callerKey struct{}

// CallerOf returns the member a call into this instance came from. Every call
// the handler given to Open serves has one.
func CallerOf(ctx context.Context) (Caller, bool) {
	c, ok := ctx.Value(callerKey{}).(Caller)
	return c, ok
}

// hello is what a member tells another that asks who it is.
type hello struct {
	ID         string `json:"id"`
	Name       string `json:"name,omitempty"`
	Deployment string `json:"deployment,omitempty"`
	URL        string `json:"url,omitempty"`
	Address    string `json:"address,omitempty"`
}

func (g *Group) hello() []byte {
	b, _ := json.Marshal(hello{ID: g.self, Name: g.info.Name, Deployment: g.info.Deployment, URL: g.directURL(), Address: g.info.Address})
	return b
}
