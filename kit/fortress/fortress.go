// Package fortress joins the apps of one household under one phrase.
//
// The phrase is the only way in. The fortress derives its keys from it under
// Domain, and every app derives the keys of its own pairing from it under its
// own domain, as it did from a phrase of its own. So joining the fortress
// pairs an instance with the other instances of its app as well. An instance
// signs with one member key in both groups, and a member approved or taken
// out in one is approved or taken out in the other.
//
// Members see each other's status and log without asking. Anything more is an
// action: an app offers actions by name and runs them for the members that
// call, unless somebody switched off the permission for the calling app. Every
// permission is on until then, and a switch made at any instance reaches all
// of them.
//
// The phrase only lets a device ask. Somebody approves it at one instance and
// the others follow, and a member taken out is refused by all of them. A
// member names its app itself and keeps the first name it gave, so the
// permissions keep apps apart, not members that lie about their app.
package fortress

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/group"
	"github.com/junkerderprovinz/parleyport/kit/keys"
	"github.com/junkerderprovinz/parleyport/kit/lan"
	"github.com/junkerderprovinz/parleyport/kit/member"
	"github.com/junkerderprovinz/parleyport/kit/status"
)

// Domain is what the fortress derives its own keys under. No app goes by it.
const Domain keys.Domain = "fortress"

// Multicast is where the members of a fortress announce themselves on the
// network, apart from the address each app pairs its instances on.
var Multicast = netip.MustParseAddrPort("239.255.77.53:8753")

// The routes the fortress answers for its members. They travel only inside
// sealed calls.
const (
	prefix          = "/kit/fortress/v1/"
	aboutPath       = prefix + "about"
	permissionsPath = prefix + "permissions"
	actPrefix       = prefix + "act/"
	movePath        = prefix + "move"
)

const (
	// tickEvery is how often the fortress looks after its members: it learns
	// what the new ones are, keeps the pairing in step and fetches the
	// permissions of the instances it has not asked for a while.
	tickEvery = time.Second
	// describeEvery and syncEvery are how often a member is asked again for
	// what it is and for its permissions; retryAfter is how soon after a call
	// that got no good answer.
	describeEvery = 10 * time.Minute
	syncEvery     = 2 * time.Minute
	retryAfter    = 2 * time.Second
	greetEvery    = 30 * time.Second
	callTimeout   = 15 * time.Second
	// maxNames bounds the actions an app offers or uses, and maxText each
	// name and version, so a member cannot make the others keep much.
	maxNames = 64
	maxText  = 64
)

var (
	appPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	actionPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
)

func validApp(id string) bool {
	return len(id) <= maxText && appPattern.MatchString(id) && id != string(Domain)
}

func validAction(name string) bool {
	return len(name) <= maxText && actionPattern.MatchString(name)
}

// App is the app an instance runs. ID is also the domain the app derives the
// keys of its pairing under, so it never changes.
type App struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Pairing is how the app pairs its own instances. Its keys come from the
// fortress phrase under the app's ID.
type Pairing struct {
	// Signing names the labels the app's instances sign under; the zero value
	// means the domain's own.
	Signing keys.Signing
	// LAN is where the app's instances announce themselves; nil reaches them
	// through the relay alone.
	LAN   *lan.Service
	Store group.Store
	// Serve answers the calls of the app's own instances and phones.
	Serve http.Handler
	// Previous is the secret of the app's own phrase, when the instance joins
	// the fortress already paired. The pairing moves to the fortress phrase
	// and keeps who was approved or taken out.
	Previous []byte
}

// Config is what a Fortress runs on. App, Secret, Identity and Store are
// required.
type Config struct {
	App App
	// Secret is what the phrase encodes.
	Secret []byte
	// Identity is this instance's member key, in the fortress and in the
	// pairing alike.
	Identity member.Identity
	// Self is what the other members see of this instance. Its Name is the
	// device it runs on.
	Self     group.Self
	Relay    group.RelayMode
	RelayURL string
	// LAN is where the fortress announces this instance, a service on
	// Multicast that the app starts; nil reaches the members through the relay
	// alone.
	LAN   *lan.Service
	Store group.Store
	// Pairing pairs the app's own instances; nil for an app that has none.
	Pairing *Pairing
	// Status is what the members read about this instance; nil shows them
	// none.
	Status status.Source
	// Actions are what the app does for other members, Uses the actions it
	// calls at them.
	Actions []Action
	Uses    []string
	// OnRemoved runs, at most once and on its own goroutine, when another
	// member says this instance was taken out of the fortress or its pairing.
	// The app leaves.
	OnRemoved func()
}

func (cfg Config) check() error {
	switch {
	case !validApp(cfg.App.ID):
		return fmt.Errorf("fortress: %q is no app id", cfg.App.ID)
	case len(cfg.Secret) == 0:
		return errors.New("fortress: no secret")
	case cfg.Store == nil:
		return errors.New("fortress: no store")
	case cfg.Pairing != nil && (cfg.Pairing.Store == nil || cfg.Pairing.Serve == nil):
		return errors.New("fortress: a pairing needs a store and a handler")
	case len(cfg.Actions) > maxNames || len(cfg.Uses) > maxNames:
		return errors.New("fortress: too many actions")
	}
	seen := map[string]bool{}
	for _, a := range cfg.Actions {
		if !validAction(a.Name) || a.Run == nil || seen[a.Name] {
			return fmt.Errorf("fortress: action %q needs a name of the form a.b, used once, and a Run", a.Name)
		}
		seen[a.Name] = true
	}
	for _, u := range cfg.Uses {
		if !validAction(u) {
			return fmt.Errorf("fortress: %q is no action", u)
		}
	}
	return nil
}

// Member is another instance in the fortress, of any app, or a viewer that
// only reads, such as a tile.
type Member struct {
	ID   string
	Kind member.Kind
	// App is what the member said it runs, zero until it said so.
	App        App
	Device     string
	Deployment string
	// Address is where its web interface is.
	Address string
	State   group.State
	// Direct means it is reachable on this network now, Relay that it is on
	// the relay now.
	Direct, Relay bool
	// Awaiting means it said recently that this instance waits for its
	// approval there.
	Awaiting bool
	LastSeen time.Time
	// Actions are what its app offers, Uses what it calls at others.
	Actions []string
	Uses    []string
}

// Online reports whether m can be called now.
func (m Member) Online() bool { return m.Direct || m.Relay }

// Fortress is this instance's side of its fortress.
type Fortress struct {
	app       App
	self      string
	about     about
	actions   map[string]Action
	status    http.Handler
	store     *splitStore
	group     *group.Group
	pairing   *group.Group
	onRemoved func()
	removed   sync.Once

	mu        sync.Mutex
	book      book
	dirty     bool
	closed    bool
	early     []string
	described map[string]time.Time
	synced    map[string]time.Time
	greeted   map[string]time.Time

	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	closeOnce sync.Once
	closeErr  error
}

// Open joins the fortress cfg names, and the app's pairing with it. It
// returns at once; the members are reached in the background.
func Open(cfg Config) (*Fortress, error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}
	store := &splitStore{store: cfg.Store}
	if err := store.load(); err != nil {
		return nil, err
	}
	bk, err := loadBook(store.fortress(), Domain.GroupKey(cfg.Secret))
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	f := &Fortress{
		app:       cfg.App,
		self:      cfg.Identity.ID(),
		about:     about{App: cfg.App, Uses: cfg.Uses},
		actions:   map[string]Action{},
		store:     store,
		onRemoved: cfg.OnRemoved,
		book:      bk,
		described: map[string]time.Time{},
		synced:    map[string]time.Time{},
		greeted:   map[string]time.Time{},
		ctx:       ctx,
		cancel:    cancel,
	}
	for _, a := range cfg.Actions {
		f.actions[a.Name] = a
		f.about.Actions = append(f.about.Actions, a.Name)
	}
	sort.Strings(f.about.Actions)
	if cfg.Status != nil {
		f.status = status.Handler(cfg.Status, func(*http.Request) error { return nil })
	}
	if p := cfg.Pairing; p != nil {
		f.pairing, err = group.Open(group.Config{
			Domain:    keys.Domain(cfg.App.ID),
			Signing:   p.Signing,
			Secret:    cfg.Secret,
			Previous:  p.Previous,
			Identity:  cfg.Identity,
			Self:      cfg.Self,
			Relay:     cfg.Relay,
			RelayURL:  cfg.RelayURL,
			LAN:       p.LAN,
			Store:     p.Store,
			OnRemoved: f.leave,
			OnRemove:  f.pairingRemoved,
		}, p.Serve)
		if err != nil {
			cancel()
			return nil, err
		}
	}
	g, err := group.Open(group.Config{
		Domain:    Domain,
		Secret:    cfg.Secret,
		Identity:  cfg.Identity,
		Self:      cfg.Self,
		Relay:     cfg.Relay,
		RelayURL:  cfg.RelayURL,
		LAN:       cfg.LAN,
		Store:     store,
		OnRemoved: f.leave,
		OnRemove:  f.fortressRemoved,
	}, http.HandlerFunc(f.serve))
	if err != nil {
		cancel()
		if f.pairing != nil {
			_ = f.pairing.Close()
		}
		return nil, err
	}
	f.mu.Lock()
	f.group = g
	early := f.early
	f.early = nil
	f.mu.Unlock()
	for _, id := range early {
		f.pairingRemoved(id)
	}
	f.wg.Go(f.run)
	return f, nil
}

// Close leaves the fortress and the pairing and saves what changed.
func (f *Fortress) Close() error {
	f.closeOnce.Do(func() {
		f.mu.Lock()
		f.closed = true
		f.mu.Unlock()
		f.cancel()
		f.wg.Wait()
		err := f.group.Close()
		if f.pairing != nil {
			err = errors.Join(err, f.pairing.Close())
		}
		f.mu.Lock()
		if f.dirty {
			err = errors.Join(err, f.saveLocked())
		}
		f.mu.Unlock()
		f.closeErr = err
	})
	return f.closeErr
}

// Pairing is the app's own group, for calls to its own instances and the
// devices only the app knows, such as phones. It is nil without a pairing.
func (f *Fortress) Pairing() *group.Group { return f.pairing }

// RelayConnected reports whether the fortress is on the relay now.
func (f *Fortress) RelayConnected() bool { return f.group.RelayConnected() }

// NoteAddress learns this instance's direct address from a request a
// signed-in user made, for the fortress and the pairing alike.
func (f *Fortress) NoteAddress(r *http.Request) {
	f.group.NoteAddress(r)
	if f.pairing != nil {
		f.pairing.NoteAddress(r)
	}
}

// DirectHandler answers the direct calls of the fortress and the pairing,
// which arrive on the same path. The app mounts it at group.DirectPath.
func (f *Fortress) DirectHandler() http.Handler {
	own := f.group.DirectHandler()
	var paired http.Handler = http.NotFoundHandler()
	if f.pairing != nil {
		paired = f.pairing.DirectHandler()
	}
	// Every direct call names its sender in a header made from its domain.
	header := http.CanonicalHeaderKey("X-" + string(Domain) + "-Peer")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(header) != "" {
			own.ServeHTTP(w, r)
			return
		}
		paired.ServeHTTP(w, r)
	})
}

// Members lists every other instance in the fortress this one knows, sorted
// by app and device.
func (f *Fortress) Members() []Member {
	listed := f.group.Members()
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Member, 0, len(listed))
	for _, m := range listed {
		if m.Kind != member.KindInstance && m.Kind != member.KindViewer {
			continue
		}
		a := f.book.Members[m.ID]
		out = append(out, Member{
			ID: m.ID, Kind: m.Kind, App: a.App, Device: m.Name, Deployment: m.Deployment, Address: m.Address,
			State: m.State, Direct: m.Direct, Relay: m.Relay, Awaiting: m.Awaiting, LastSeen: m.LastSeen,
			Actions: append([]string(nil), a.Actions...), Uses: append([]string(nil), a.Uses...),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].App.ID != out[j].App.ID {
			return out[i].App.ID < out[j].App.ID
		}
		if out[i].Device != out[j].Device {
			return out[i].Device < out[j].Device
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Approve lets member id into the fortress, and into the pairing when it is
// an instance of this app waiting there under the same key.
func (f *Fortress) Approve(id string) error {
	if err := f.group.Approve(id); err != nil {
		return err
	}
	f.follow(time.Now())
	return nil
}

// Remove takes member id out of the fortress and out of the pairing: its key
// is revoked on every instance, and nothing it sends counts from then on.
func (f *Fortress) Remove(id string) error {
	err := f.group.Remove(id)
	if f.pairing != nil {
		if _, ok := listed(f.pairing, id); ok {
			err = errors.Join(err, f.pairing.Remove(id))
		}
	}
	return err
}

func listed(g *group.Group, id string) (group.Member, bool) {
	for _, m := range g.Members() {
		if m.ID == id {
			return m, true
		}
	}
	return group.Member{}, false
}

func (f *Fortress) leave() {
	if f.onRemoved != nil {
		f.removed.Do(func() { go f.onRemoved() })
	}
}

// fortressRemoved follows a removal in the fortress, made here or passed on,
// into the pairing.
func (f *Fortress) fortressRemoved(id string) {
	f.mu.Lock()
	if _, ok := f.book.Members[id]; ok {
		delete(f.book.Members, id)
		f.dirty = true
	}
	f.mu.Unlock()
	if f.pairing != nil {
		if _, ok := listed(f.pairing, id); ok {
			_ = f.pairing.Remove(id)
		}
	}
}

// pairingRemoved follows a removal in the pairing into the fortress. The
// pairing opens first, so one that comes in before the fortress is open waits
// until it is.
func (f *Fortress) pairingRemoved(id string) {
	f.mu.Lock()
	g := f.group
	if g == nil {
		f.early = append(f.early, id)
	}
	f.mu.Unlock()
	if g == nil {
		return
	}
	if _, ok := listed(g, id); ok {
		_ = g.Remove(id)
	}
}

// follow approves in each group the instances of this app that are approved
// in the other under the same key. Into the pairing goes only a member that
// said it runs this app; into the fortress any instance the pairing approved,
// since only this app's instances pair here. A sibling the pairing sees but
// never heard from is greeted there, so it asks and can be approved.
func (f *Fortress) follow(now time.Time) {
	if f.pairing == nil {
		return
	}
	paired := map[string]group.Member{}
	for _, p := range f.pairing.Members() {
		if p.Kind == member.KindInstance {
			paired[p.ID] = p
		}
	}
	for _, m := range f.group.Members() {
		p, ok := paired[m.ID]
		if !ok {
			continue
		}
		sibling := m.State == group.StateApproved && f.appOf(m.ID) == f.app.ID
		switch {
		case p.State == group.StateUnknown && sibling && p.Online() && f.due(f.greeted, m.ID, now):
			f.again(f.greeted, m.ID, now.Add(greetEvery))
			f.greet(m.ID)
		case !bytes.Equal(p.Key, m.Key) || len(m.Key) == 0:
		case p.State == group.StateApproved && m.State == group.StatePending:
			_ = f.group.Approve(m.ID)
		case p.State == group.StatePending && sibling:
			_ = f.pairing.Approve(m.ID)
		}
	}
}

// greet calls sibling id in the pairing. Any signed call pins this instance's
// key there, and the answer does not matter.
func (f *Fortress) greet(id string) {
	if !f.enter() {
		return
	}
	go func() {
		defer f.wg.Done()
		ctx, cancel := context.WithTimeout(f.ctx, callTimeout)
		defer cancel()
		_, _, _ = f.pairing.Call(ctx, id, http.MethodGet, aboutPath, nil)
	}()
}

func (f *Fortress) appOf(id string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.book.Members[id].App.ID
}

// run looks after the members until Close.
func (f *Fortress) run() {
	t := time.NewTicker(tickEvery)
	defer t.Stop()
	for {
		f.tick(time.Now())
		select {
		case <-f.ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (f *Fortress) tick(now time.Time) {
	var due []string
	for _, m := range f.group.Members() {
		if m.Kind == member.KindInstance && m.State == group.StateApproved && m.Online() {
			due = append(due, m.ID)
		}
	}
	for _, id := range due {
		if f.due(f.described, id, now) {
			f.describe(f.ctx, id, now)
		}
		if f.due(f.synced, id, now) {
			f.pull(f.ctx, id, now)
		}
	}
	f.follow(now)
	f.mu.Lock()
	if f.dirty {
		_ = f.saveLocked()
	}
	f.mu.Unlock()
}

// due reports whether id's next turn in next has come.
func (f *Fortress) due(next map[string]time.Time, id string, now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return !now.Before(next[id])
}

func (f *Fortress) again(next map[string]time.Time, id string, at time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	next[id] = at
}

// describe asks member id what it is and records the answer. The app a
// member said first stays its app.
func (f *Fortress) describe(ctx context.Context, id string, now time.Time) bool {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	body, err := f.get(ctx, id, aboutPath)
	var a about
	if err != nil || json.Unmarshal(body, &a) != nil || !a.valid() {
		f.again(f.described, id, now.Add(retryAfter))
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.described[id] = now.Add(describeEvery)
	if old, ok := f.book.Members[id]; ok && old.App.ID != a.App.ID {
		return true
	}
	if f.book.Members == nil {
		f.book.Members = map[string]about{}
	}
	f.book.Members[id] = a
	f.dirty = true
	return true
}

// get calls GET path at member id and returns the body of a 200.
func (f *Fortress) get(ctx context.Context, id, path string) ([]byte, error) {
	status, body, err := f.group.Call(ctx, id, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, refusal(status, body)
	}
	return body, nil
}

// serve answers the calls of the members. The group lets through only
// approved members, each named by CallerOf. A viewer reads and does nothing
// else.
func (f *Fortress) serve(w http.ResponseWriter, r *http.Request) {
	caller, ok := group.CallerOf(r.Context())
	switch {
	case !ok || caller.Kind != member.KindInstance && caller.Kind != member.KindViewer:
		writeError(w, http.StatusForbidden, "forbidden")
		return
	case caller.Kind == member.KindViewer && r.Method != http.MethodGet:
		writeError(w, http.StatusForbidden, "read_only")
		return
	}
	switch path := r.URL.Path; {
	case path == aboutPath && r.Method == http.MethodGet:
		writeJSON(w, f.about)
	case path == permissionsPath && r.Method == http.MethodGet:
		writeJSON(w, f.permissionList())
	case path == permissionsPath && r.Method == http.MethodPost:
		f.takeSwitch(w, r, caller.ID)
	case len(path) > len(actPrefix) && path[:len(actPrefix)] == actPrefix && r.Method == http.MethodPost:
		f.serveAction(w, r, caller.ID, path[len(actPrefix):])
	case (path == status.StatusPath || path == status.LogPath) && f.status != nil:
		f.status.ServeHTTP(w, r)
	default:
		writeError(w, http.StatusNotFound, "not_found")
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}
