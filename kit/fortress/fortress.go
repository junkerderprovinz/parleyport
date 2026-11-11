// Package fortress joins the apps of one household under one phrase.
//
// The phrase is the only way in. The fortress derives its keys from it under
// Domain, and every app derives the keys of its own pairing from it under its
// own domain, as it did from a phrase of its own. So joining the fortress
// pairs an instance with the other instances of its app as well. An instance
// signs with one member key in both groups, and a member taken out of one is
// taken out of the other.
//
// Members see each other's status and log without asking. Anything more is an
// action: an app offers actions by name and runs them for the members that
// call, unless somebody switched off the permission for the calling app. Every
// permission is on until then, and a switch made at any instance reaches all
// of them.
//
// An app that keeps events lets the members whose app may run EventsAction
// read them by cursor. Rules turn them into actions: when a member adds an
// event of some kind, the instance that holds the rule runs one of its own
// actions. Every event carries how many rules led to it, and a chain stops at
// events.MaxDepth, so two apps that answer each other cannot loop.
//
// The phrase is the proof: a device that holds it is a member at once, with
// the permissions as they stand. A member taken out is refused by all the
// others for good, but whoever still holds the phrase can come back under a
// new key until the phrase is changed. A member that holds only the keys,
// such as a plugin, follows a change with NewKeys. A member names its app
// itself and keeps the first name it gave, so the permissions keep apps
// apart, not members that lie about their app.
package fortress

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/events"
	"github.com/junkerderprovinz/parleyport/kit/group"
	"github.com/junkerderprovinz/parleyport/kit/keys"
	"github.com/junkerderprovinz/parleyport/kit/lan"
	"github.com/junkerderprovinz/parleyport/kit/member"
	"github.com/junkerderprovinz/parleyport/kit/relay"
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
	movedPath       = prefix + "moved"
	phrasePath      = prefix + "phrase"
)

const (
	// tickEvery is how often the fortress looks after its members: it learns
	// what the new ones are, keeps the pairing in step and fetches the
	// permissions of the instances it has not asked for a while.
	tickEvery = time.Second
	// describeEvery, syncEvery and greetEvery are how often a member is asked
	// again what it is, for its permissions and, as a sibling, in the
	// pairing; retryAfter is how soon after a call that got no good answer.
	describeEvery = 10 * time.Minute
	syncEvery     = 2 * time.Minute
	greetEvery    = 10 * time.Minute
	retryAfter    = 2 * time.Second
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
	// Group is the pairing as the app would open it with group.Open: Store,
	// and as it needs them Signing, LAN, Kinds, Ports, the answer sizes,
	// OnChange, Stream and Upload. Previous is the secret of the app's own
	// phrase when the instance joins the fortress already paired; the
	// pairing moves to the fortress phrase and keeps who was approved or
	// taken out. Who joins, as whom and where is the fortress's to set, so
	// Domain, Secret, Keys, JoinByPhrase, Self, Relay, RelayURL, OnRemoved,
	// OnRemove and Vouch stay unset: an instance of the app that is in the
	// fortress under the same key is paired without anybody approving it.
	Group group.Config
	// Serve answers the calls of the app's own instances and phones.
	Serve http.Handler
}

// Config is what a Fortress runs on. App, Secret or Keys, Identity and Store
// are required.
type Config struct {
	App App
	// Secret is what the phrase encodes.
	Secret []byte
	// Keys stand in for Secret on a device that keeps only what the fortress
	// derives under Domain. It cannot pair the app's instances, whose keys
	// come from the secret.
	Keys keys.Set
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
	// Previous is the secret of the phrase before ChangePhrase. Members,
	// removals and permissions carry over to Secret, in the pairing as well
	// unless Pairing.Group.Previous says otherwise. For 30 days after the
	// change the fortress also answers on Previous, so that the members that
	// hold only keys can fetch the new ones with NewKeys; the app keeps giving
	// it until then.
	Previous []byte
	// Keeper keeps a new phrase when the fortress changes it; nil for an app
	// that has nowhere safe to keep one, which then enters the new phrase
	// like a new member.
	Keeper Keeper
	// Pairing pairs the app's own instances; nil for an app that has none.
	Pairing *Pairing
	// Status is what the members read about this instance; nil shows them
	// none.
	Status status.Source
	// Actions are what the app does for other members, Uses the actions it
	// calls at them.
	Actions []Action
	Uses    []string
	// Export hands over this instance's backup and its length in bytes when
	// another member fetches it with Fortress.Export and its app may run
	// ExportAction here. It runs only for a member on this network, never
	// through the relay. A *Refusal says no with a code the member sees. nil
	// offers no backup.
	Export func(ctx context.Context, from Caller) (backup io.ReadCloser, n int64, err error)
	// Import takes a backup, n bytes long, that another member hands back
	// with Fortress.Import, if its app may run ImportAction here, which is
	// off until somebody switches it on. It runs only for a member on this
	// network. A read of backup fails with group.ErrStreamBroken where it
	// would end if the backup arrived damaged, so the app keeps it only after
	// reading it to io.EOF. A *Refusal says no with a code the member sees.
	// nil takes no backup.
	Import func(ctx context.Context, from Caller, backup io.Reader, n int64) error
	// Events are what members whose app may run EventsAction here read of
	// this instance; nil keeps none.
	Events *events.Log
	// MaxAnswerBytes and MaxRelayAnswerBytes bound what an action answers,
	// directly and through the relay, here and in the pairing unless
	// Pairing.Group sets its own, as in group.Config.
	MaxAnswerBytes      int
	MaxRelayAnswerBytes int
	// OnRemoved runs, at most once and on its own goroutine, when another
	// member says this instance was taken out of the fortress or its pairing.
	// The app leaves.
	OnRemoved func()
}

// pairingConfig is the app's own settings for its pairing, with who joins,
// as whom and where taken from cfg.
func pairingConfig(cfg Config) group.Config {
	pc := cfg.Pairing.Group
	pc.Domain = keys.Domain(cfg.App.ID)
	pc.Secret = cfg.Secret
	if len(pc.Previous) == 0 {
		pc.Previous = cfg.Previous
	}
	pc.Identity, pc.Self = cfg.Identity, cfg.Self
	pc.Relay, pc.RelayURL = cfg.Relay, cfg.RelayURL
	pc.MaxAnswerBytes = cmp.Or(pc.MaxAnswerBytes, cfg.MaxAnswerBytes)
	pc.MaxRelayAnswerBytes = cmp.Or(pc.MaxRelayAnswerBytes, cfg.MaxRelayAnswerBytes)
	return pc
}

// decided reports whether c sets anything the fortress decides for the
// pairing.
func decided(c group.Config) bool {
	return c.Domain != "" || len(c.Secret) > 0 || c.Keys.Group != "" || len(c.Keys.Frame) > 0 || len(c.Keys.PeerAuth) > 0 ||
		c.JoinByPhrase || c.Self != (group.Self{}) || c.Relay != "" || c.RelayURL != "" || c.OnRemoved != nil || c.OnRemove != nil || c.Vouch != nil
}

func (cfg Config) check() error {
	switch {
	case !validApp(cfg.App.ID):
		return fmt.Errorf("fortress: %q is no app id", cfg.App.ID)
	case len(cfg.Secret) == 0 && !cfg.Keys.Complete():
		return errors.New("fortress: no secret and no complete keys")
	case len(cfg.Secret) == 0 && cfg.Pairing != nil:
		return errors.New("fortress: a pairing needs the secret")
	case cfg.Store == nil:
		return errors.New("fortress: no store")
	case cfg.Pairing != nil && (cfg.Pairing.Group.Store == nil || cfg.Pairing.Serve == nil):
		return errors.New("fortress: a pairing needs a store and a handler")
	case cfg.Pairing != nil && decided(cfg.Pairing.Group):
		return errors.New("fortress: the pairing sets who joins, as whom or where, which is the fortress's to set")
	case len(cfg.Actions) > maxNames || len(cfg.Uses) > maxNames:
		return errors.New("fortress: too many actions")
	}
	seen := map[string]bool{}
	for _, a := range cfg.Actions {
		if a.Name == ExportAction || a.Name == ImportAction || a.Name == EventsAction {
			return fmt.Errorf("fortress: %s is offered through its own field of Config, not as an action", a.Name)
		}
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

// Keeper keeps the secret behind the phrase under the app's own seal, such as
// its main key, so that the app can show the phrase again once its user
// signed in. The fortress keeps no secret itself. Keep may run inside a call
// the fortress serves, so it must not close the fortress; the app opens it
// again afterwards, with the new secret and the old one as Config.Previous.
type Keeper interface {
	Keep(secret []byte) error
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
	LastSeen      time.Time
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
	keeper    Keeper
	export    func(context.Context, Caller) (io.ReadCloser, int64, error)
	importer  func(context.Context, Caller, io.Reader, int64) error
	events    *events.Log
	onRemoved func()
	removed   sync.Once
	// paired is what the pairing derives from the secret, which a phone
	// that follows a move is handed in its place.
	paired keys.Set
	// old is the fortress on the phrase before, open for moveWindow after
	// the change so that its members that hold only keys can fetch set, the
	// keys under the new one. nil when the phrase did not change lately.
	old *group.Group
	set keys.Set

	mu        sync.Mutex
	book      book
	dirty     bool
	closed    bool
	early     []string
	described map[string]time.Time
	synced    map[string]time.Time
	greeted   map[string]time.Time
	watched   map[string]time.Time

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
	set := cfg.Keys
	if len(cfg.Secret) > 0 {
		set = Domain.Keys(cfg.Secret)
	}
	previous := ""
	if len(cfg.Previous) > 0 {
		previous = Domain.GroupKey(cfg.Previous)
	}
	bk, err := loadBook(store.fortress(), set.Group, previous)
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
		keeper:    cfg.Keeper,
		export:    cfg.Export,
		importer:  cfg.Import,
		events:    cfg.Events,
		onRemoved: cfg.OnRemoved,
		book:      bk,
		// A book written at once tells a later change of phrase from a fresh
		// start.
		dirty:     true,
		described: map[string]time.Time{},
		synced:    map[string]time.Time{},
		greeted:   map[string]time.Time{},
		watched:   map[string]time.Time{},
		ctx:       ctx,
		cancel:    cancel,
	}
	for _, a := range cfg.Actions {
		f.actions[a.Name] = a
		f.about.Actions = append(f.about.Actions, a.Name)
	}
	if cfg.Export != nil {
		f.about.Actions = append(f.about.Actions, ExportAction)
	}
	if cfg.Import != nil {
		f.about.Actions = append(f.about.Actions, ImportAction)
	}
	if cfg.Events != nil {
		f.actions[EventsAction] = Action{Name: EventsAction, Run: f.serveEvents}
		f.about.Actions = append(f.about.Actions, EventsAction)
	}
	sort.Strings(f.about.Actions)
	if cfg.Status != nil {
		f.status = status.Handler(cfg.Status, func(*http.Request) error { return nil })
	}
	if cfg.Pairing != nil {
		pc := pairingConfig(cfg)
		pc.OnRemoved, pc.OnRemove, pc.Vouch = f.leave, f.pairingRemoved, f.vouch
		f.paired = pc.Domain.Keys(pc.Secret)
		f.pairing, err = group.Open(pc, cfg.Pairing.Serve)
		if err != nil {
			cancel()
			return nil, err
		}
	}
	g, err := group.Open(group.Config{
		Domain:              Domain,
		Keys:                set,
		Previous:            cfg.Previous,
		JoinByPhrase:        true,
		Identity:            cfg.Identity,
		Self:                cfg.Self,
		Relay:               cfg.Relay,
		RelayURL:            cfg.RelayURL,
		LAN:                 cfg.LAN,
		Store:               store,
		OnRemoved:           f.leave,
		OnRemove:            f.fortressRemoved,
		MaxAnswerBytes:      cfg.MaxAnswerBytes,
		MaxRelayAnswerBytes: cfg.MaxRelayAnswerBytes,
		Stream:              http.HandlerFunc(f.serveExport),
		Upload:              http.HandlerFunc(f.serveImport),
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
	if len(cfg.Secret) > 0 && len(cfg.Previous) > 0 && time.Since(bk.Changed) < moveWindow {
		if err := f.openOld(cfg, set); err != nil {
			cancel()
			_ = g.Close()
			if f.pairing != nil {
				_ = f.pairing.Close()
			}
			return nil, err
		}
	}
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
		if f.old != nil {
			err = errors.Join(err, f.old.Close())
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
	if f.old != nil {
		f.old.NoteAddress(r)
	}
}

// DirectHandler answers the direct calls of the fortress, on the phrase
// before as well for a while after a change, the pairing and the other groups
// given, which all arrive on the same path, such as the app's group on its
// own phrase while its members move into the fortress. The app mounts it at
// group.DirectPath.
func (f *Fortress) DirectHandler(others ...*group.Group) http.Handler {
	return group.Direct(append([]*group.Group{f.group, f.pairing, f.old}, others...)...)
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
			State: m.State, Direct: m.Direct, Relay: m.Relay, LastSeen: m.LastSeen,
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
	if _, ok := f.book.Cursors[id]; ok {
		delete(f.book.Cursors, id)
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

// follow approves in the pairing every member of the fortress that said it
// runs this app and waits there under the same key, which is how holding the
// phrase pairs an app's instances. Every such sibling is greeted in the
// pairing, so that each knows the other's key there.
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
		if sibling && p.Online() && f.due(f.greeted, m.ID, now) {
			f.again(f.greeted, m.ID, now.Add(greetEvery))
			f.greet(m.ID)
		}
		if sibling && p.State == group.StatePending && len(m.Key) > 0 && bytes.Equal(p.Key, m.Key) {
			_ = f.pairing.Approve(m.ID)
		}
	}
}

// vouch lets into the pairing an instance that is a member of the fortress
// under the same key and said it runs this app, as follow would approve it
// a moment later.
func (f *Fortress) vouch(id string, key ed25519.PublicKey) bool {
	f.mu.Lock()
	g, app := f.group, f.book.Members[id].App.ID
	f.mu.Unlock()
	return g != nil && app == f.app.ID && approvedIn(g, id, key)
}

// approvedIn reports whether instance id is approved in g under key.
func approvedIn(g *group.Group, id string, key ed25519.PublicKey) bool {
	m, ok := listed(g, id)
	return ok && m.Kind == member.KindInstance && m.State == group.StateApproved && bytes.Equal(m.Key, key)
}

// greet calls sibling id in the pairing. Any signed call pins this instance's
// key there, so any answer will do; without one it tries again soon.
func (f *Fortress) greet(id string) {
	if !f.enter() {
		return
	}
	go func() {
		defer f.wg.Done()
		ctx, cancel := context.WithTimeout(f.ctx, callTimeout)
		defer cancel()
		_, _, err := f.pairing.Call(ctx, id, http.MethodGet, aboutPath, nil)
		var untrusted *relay.UntrustedAnswer
		if err != nil && !errors.As(err, &untrusted) {
			f.again(f.greeted, id, time.Now().Add(retryAfter))
		}
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
		if m.Kind == member.KindInstance && m.Online() {
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
	f.watch(now)
	f.prune()
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
		return nil, f.refused(id, status, body)
	}
	return body, nil
}

// serve answers the calls of the members. The group lets through only
// members, each named by CallerOf. A viewer reads and does nothing else.
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
	case path == phrasePath && r.Method == http.MethodPost && f.keeper != nil:
		takeSecret(w, r, f.keeper)
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
