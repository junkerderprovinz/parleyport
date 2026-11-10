package group

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/member"
	"github.com/junkerderprovinz/parleyport/kit/relay"
)

const (
	// maxPinned is how many member keys a group keeps. Past it an approved
	// device idle for pinIdle makes room for a new one; otherwise the new one
	// waits until the owner takes a device out. Of them at most maxWaiting
	// wait for approval, so keys anybody holding the phrase can make never
	// fill the list and push out a device the owner approved.
	maxPinned  = 64
	maxWaiting = 16
	pinIdle    = 30 * 24 * time.Hour
	// maxNewPins is how many keys may be pinned within pinWindow, and
	// maxNewPinsPerSource how many of them through one relay connection or one
	// address on the network. A whole group pins its keys within minutes of
	// being paired, each member through its own connection, and every pin is a
	// write of the store.
	maxNewPins          = 64
	maxNewPinsPerSource = 2
	pinWindow           = time.Hour
	// maxForgotten bounds the removed ids and the revoked keys kept; the
	// oldest goes first.
	maxForgotten = 1024
	// perMemberCalls is how many calls of one member key are served at once.
	perMemberCalls = 16
	// lastSeenStep is how far a member's last-seen time may lag before the
	// store is written again, so an open page does not rewrite it on every
	// poll.
	lastSeenStep = time.Minute
	// maxAnswerBytes bounds what the app answers a call with. Sealed and coded
	// for the wire it still fits a relay frame.
	maxAnswerBytes = 4 << 20
)

// The routes a group answers itself, before the app's handler. They travel
// only inside sealed calls.
const (
	internalPrefix = "/kit/group/v1/"
	helloPath      = internalPrefix + "hello"
	decisionPath   = internalPrefix + "decision"
	rosterPath     = internalPrefix + "roster"
)

// state is what a group keeps in its Store.
type state struct {
	// Group is the group key, so a store written under another phrase starts
	// over instead of letting in whoever was approved there.
	Group   string               `json:"group"`
	Members map[string]record    `json:"members,omitempty"`
	Removed map[string]time.Time `json:"removed,omitempty"`
	Revoked map[string]time.Time `json:"revoked,omitempty"`
	// Address is this instance's direct address as NoteAddress learned it.
	Address string `json:"address,omitempty"`
}

// record is a member whose key is pinned here.
type record struct {
	Kind     member.Kind `json:"kind"`
	Key      []byte      `json:"key"`
	Approved bool        `json:"approved"`
	// Used is when the key last signed a call here, Seen when the member was
	// last reachable, each kept to within lastSeenStep.
	Used       time.Time `json:"used"`
	Seen       time.Time `json:"seen"`
	Name       string    `json:"name,omitempty"`
	Deployment string    `json:"deployment,omitempty"`
	Address    string    `json:"address,omitempty"`
}

// seenAs records what m says of the member it is for and reports whether the
// record changed enough to be written; m gets what only the record knows.
func (r *record) seenAs(m *Member, now time.Time) bool {
	changed := false
	if m.Name != "" && m.Name != r.Name {
		r.Name, changed = m.Name, true
	}
	if m.Deployment != "" && m.Deployment != r.Deployment {
		r.Deployment, changed = m.Deployment, true
	}
	if m.Address != "" && m.Address != r.Address {
		r.Address, changed = m.Address, true
	}
	if now.Sub(r.Seen) >= lastSeenStep {
		r.Seen, changed = now, true
	}
	fill(m, r.Name, r.Deployment, r.Address)
	return changed
}

// loadState reads the store written under groupKey, or under previous, the
// group key of the phrase the group moves away from, and reports whether it
// was the latter.
func loadState(raw []byte, groupKey, previous string) (state, bool, error) {
	fresh := state{Group: groupKey}
	if len(bytes.TrimSpace(raw)) == 0 {
		return fresh, false, nil
	}
	var st state
	// A store that is there but does not read is an error rather than an
	// empty group, which would let in again whoever was removed.
	if err := json.Unmarshal(raw, &st); err != nil {
		return state{}, false, fmt.Errorf("group: the store is damaged: %w", err)
	}
	switch st.Group {
	case groupKey:
		return st, false, nil
	case previous:
		if previous != "" {
			st.Group = groupKey
			return st, true, nil
		}
	}
	return fresh, false, nil
}

func (g *Group) saveLocked() error {
	raw, err := json.Marshal(g.st)
	if err != nil {
		return err
	}
	if err := g.store.Save(raw); err != nil {
		return err
	}
	g.dirty = false
	return nil
}

// kindOfID is the kind of member whose ids have id's shape, "" for none. The
// shapes never overlap, so no phone or viewer can be listed or removed under
// an instance's id, nor an instance under theirs.
func kindOfID(id string) member.Kind {
	switch {
	case relay.ValidInstanceID(id):
		return member.KindInstance
	case hashAfter(id, "phone-"):
		return member.KindMobile
	case hashAfter(id, "browser-"):
		return member.KindExtension
	case hashAfter(id, "viewer-"):
		return member.KindViewer
	}
	return ""
}

func hashAfter(id, prefix string) bool {
	rest, ok := strings.CutPrefix(id, prefix)
	if !ok || len(rest) != 2*sha256.Size {
		return false
	}
	_, err := hex.DecodeString(rest)
	return err == nil && strings.ToLower(rest) == rest
}

// claimFits reports whether id is the one key makes for a member of kind.
// Whoever holds the phrase sees every member's id, and only this keeps them
// from pinning a key of their own under one.
func claimFits(id string, kind member.Kind, key []byte) bool {
	return id != "" && member.ID(kind, key) == id
}

// refusal is how a call that is not served is answered.
type refusal struct {
	status int
	body   []byte
}

func refuse(status int, code, text string) *refusal {
	return &refusal{status: status, body: relay.RefusalBody(code, text)}
}

var (
	// removedRefusal stays plain text: devices already in the field read
	// exactly this body as "this device was taken out of the group".
	removedRefusal = &refusal{status: http.StatusGone, body: []byte("removed")}
	// dropped is a call that gets no answer at all: one that is old, or one
	// whose id its key already used.
	dropped         = &refusal{status: relay.StatusDrop}
	pendingRefusal  = refuse(http.StatusForbidden, "memberPending", "this device waits for approval on an instance of the group")
	unsignedRefusal = refuse(http.StatusForbidden, "memberUnsigned", "this device does not sign its calls, which every member of the group has to; update it")
	unnamedRefusal  = refuse(http.StatusForbidden, "memberUnnamed", "a signed call has to name the member it comes from")
	kindRefusal     = refuse(http.StatusForbidden, "memberKind", "this call names an id that its key and kind do not make")
)

// memberLimits counts what each member key has in flight and when keys were
// pinned, and through which source. It lives in memory only.
type memberLimits struct {
	mu       sync.Mutex
	inFlight map[string]int
	pinned   []newPin
}

type newPin struct {
	at     time.Time
	source string
}

func newMemberLimits() *memberLimits {
	return &memberLimits{inFlight: map[string]int{}}
}

func (l *memberLimits) acquire(key []byte) (release func(), ok bool) {
	bucket := string(key)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.inFlight[bucket] >= perMemberCalls {
		return nil, false
	}
	l.inFlight[bucket]++
	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.inFlight[bucket]--; l.inFlight[bucket] <= 0 {
			delete(l.inFlight, bucket)
		}
	}, true
}

// mayPin reports whether one more key may be pinned at now through source, and
// counts it. A transport that cannot tell its sources apart passes "", which
// only the group's hour counts.
func (l *memberLimits) mayPin(source string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	kept := l.pinned[:0]
	fromSource := 0
	for _, p := range l.pinned {
		if now.Sub(p.at) < pinWindow {
			kept = append(kept, p)
			if source != "" && p.source == source {
				fromSource++
			}
		}
	}
	l.pinned = kept
	if fromSource >= maxNewPinsPerSource || len(l.pinned) >= maxNewPins {
		return false
	}
	l.pinned = append(l.pinned, newPin{at: now, source: source})
	return true
}

// handle serves one call another member made, on the relay or directly. The
// call comes from relay.OpenCall, so a signature it carries already holds.
func (g *Group) handle(ctx context.Context, call relay.ProxyCall) (int, []byte) {
	if !g.enter() {
		return relay.StatusDrop, nil
	}
	defer g.wg.Done()
	caller, r := g.admit(call, relay.SourceOf(ctx), time.Now())
	if r != nil {
		return r.status, r.body
	}
	release, ok := g.limits.acquire(call.Key)
	if !ok {
		return http.StatusTooManyRequests, relay.RefusalBody("memberBusy", "this device already has as many calls waiting on this instance as it may")
	}
	defer release()
	if strings.HasPrefix(call.Path, internalPrefix) {
		return g.internal(caller, call)
	}
	return g.serveApp(context.WithValue(ctx, callerKey{}, caller), call)
}

// admit decides whose call this is: whether the id it names is the one its
// key makes, whether that key is approved, and whether the call ran before. A
// call's id is used up only once it is known to come from a pinned key, so a
// stranger fills no record a member needs.
func (g *Group) admit(call relay.ProxyCall, source string, now time.Time) (Caller, *refusal) {
	if !relay.Recent(call, now) {
		return Caller{}, dropped
	}
	if !call.Signed() {
		return Caller{}, unsignedRefusal
	}
	if call.From == "" {
		return Caller{}, unnamedRefusal
	}
	if !claimFits(call.From, call.Kind, call.Key) {
		return Caller{}, kindRefusal
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	st := &g.st
	_, removed := st.Removed[call.From]
	if _, revoked := st.Revoked[hex.EncodeToString(call.Key)]; revoked || removed {
		return Caller{}, removedRefusal
	}
	if rec, ok := st.Members[call.From]; ok {
		if !g.replay.Admit(call) {
			return Caller{}, dropped
		}
		if now.Sub(rec.Used) >= lastSeenStep {
			rec.Used = now
			st.Members[call.From] = rec
			g.dirty = true
		}
		if !rec.Approved && !g.byPhrase {
			return Caller{}, pendingRefusal
		}
		return Caller{ID: call.From, Kind: rec.Kind, Key: rec.Key}, nil
	}
	for _, rec := range st.Members {
		if bytes.Equal(rec.Key, call.Key) {
			return Caller{}, refuse(http.StatusForbidden, "memberKeyChanged", "this key already speaks for another member of the group")
		}
	}
	if waitingLocked(st) >= maxWaiting {
		return Caller{}, refuse(http.StatusTooManyRequests, "groupFull", "as many devices as this instance lists already wait for approval")
	}
	idle := ""
	if len(st.Members) >= maxPinned {
		if idle = idlePinLocked(st, now); idle == "" {
			return Caller{}, refuse(http.StatusTooManyRequests, "groupFull", "this group already knows as many devices as it can")
		}
	}
	if !g.limits.mayPin(source, now) {
		return Caller{}, refuse(http.StatusTooManyRequests, "groupJoinsBusy", "too many new devices joined this group within the hour")
	}
	if err := g.pinLocked(call.From, record{Kind: call.Kind, Key: bytes.Clone(call.Key), Approved: g.byPhrase, Used: now}, idle); err != nil {
		return Caller{}, refuse(http.StatusInternalServerError, "memberNotPinned", "this instance could not record the device's key")
	}
	g.replay.Admit(call)
	if g.byPhrase {
		return Caller{ID: call.From, Kind: call.Kind, Key: bytes.Clone(call.Key)}, nil
	}
	return Caller{}, pendingRefusal
}

// pinLocked stores rec under id in place of idle, if any, and takes both back
// when the store refuses the write.
func (g *Group) pinLocked(id string, rec record, idle string) error {
	st := &g.st
	if st.Members == nil {
		st.Members = map[string]record{}
	}
	before, hadIdle := st.Members[idle]
	delete(st.Members, idle)
	st.Members[id] = rec
	if err := g.saveLocked(); err != nil {
		delete(st.Members, id)
		if hadIdle {
			st.Members[idle] = before
		}
		return err
	}
	return nil
}

// idlePinLocked is the approved device nobody used for longest, once nobody
// used it for pinIdle, "" when there is none. A pin that waits for approval
// is never dropped to make room, and neither is an instance's, which every
// answer from that instance is checked against.
func idlePinLocked(st *state, now time.Time) string {
	idlest := ""
	for id, rec := range st.Members {
		if rec.Approved && rec.Kind != member.KindInstance && now.Sub(rec.Used) >= pinIdle &&
			(idlest == "" || rec.Used.Before(st.Members[idlest].Used)) {
			idlest = id
		}
	}
	return idlest
}

func waitingLocked(st *state) int {
	n := 0
	for _, rec := range st.Members {
		if !rec.Approved {
			n++
		}
	}
	return n
}

// trustsAnswer reports whether an answer signed by key may count as instance
// target's: target is approved here as an instance, under that key. Where the
// phrase is enough, an instance not pinned yet is pinned by its answer, as
// long as its id and key were not taken out.
func (g *Group) trustsAnswer(target string, key ed25519.PublicKey) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	rec, ok := g.st.Members[target]
	if ok || !g.byPhrase {
		return ok && rec.Approved && rec.Kind == member.KindInstance && bytes.Equal(rec.Key, key)
	}
	_, removed := g.st.Removed[target]
	_, revoked := g.st.Revoked[hex.EncodeToString(key)]
	if removed || revoked || !claimFits(target, member.KindInstance, key) || len(g.st.Members) >= maxPinned {
		return false
	}
	for _, rec := range g.st.Members {
		if bytes.Equal(rec.Key, key) {
			return false
		}
	}
	return g.pinLocked(target, record{Kind: member.KindInstance, Key: bytes.Clone(key), Approved: true, Used: time.Now()}, "") == nil
}

// Approve lets member id in, here and, passed on, on every other instance of
// the group that is reachable now. It approves the key pinned here when id
// signed its first call.
func (g *Group) Approve(id string) error {
	g.mu.Lock()
	if _, gone := g.st.Removed[id]; gone {
		g.mu.Unlock()
		return ErrRemoved
	}
	rec, ok := g.st.Members[id]
	if !ok {
		g.mu.Unlock()
		return ErrNoSuchMember
	}
	if rec.Approved {
		g.mu.Unlock()
		return nil
	}
	// Approving counts as use, so a key approved and passed on is not taken
	// for idle before the device first calls.
	rec.Approved, rec.Used = true, time.Now()
	g.st.Members[id] = rec
	if err := g.saveLocked(); err != nil {
		rec.Approved = false
		g.st.Members[id] = rec
		g.mu.Unlock()
		return err
	}
	g.mu.Unlock()
	g.passOn(decision{Op: opApprove, ID: id, Kind: rec.Kind, Key: rec.Key}, g.instancesOnline(id))
	return nil
}

// Remove takes member id out of the group: its key is revoked, its calls are
// turned away from then on, and every other instance reachable now is told,
// the one taken out included. A member waiting for approval is refused the
// same way.
func (g *Group) Remove(id string) error {
	if kindOfID(id) == "" {
		return ErrNoSuchMember
	}
	tell := g.instancesOnline("")
	if err := g.forget(id, time.Now()); err != nil {
		return err
	}
	g.passOn(decision{Op: opRemove, ID: id}, tell)
	return nil
}

// forget removes id here only and tells the app, the first time.
func (g *Group) forget(id string, now time.Time) error {
	newly, err := g.forgetLocally(id, now)
	if newly && g.onRemove != nil {
		g.onRemove(id)
	}
	return err
}

func (g *Group) forgetLocally(id string, now time.Time) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	st := &g.st
	if _, done := st.Removed[id]; done {
		return false, nil
	}
	rec, known := st.Members[id]
	delete(st.Members, id)
	if st.Removed == nil {
		st.Removed = map[string]time.Time{}
	}
	bounded(st.Removed)
	st.Removed[id] = now
	if known {
		if st.Revoked == nil {
			st.Revoked = map[string]time.Time{}
		}
		bounded(st.Revoked)
		st.Revoked[hex.EncodeToString(rec.Key)] = now
	}
	delete(g.addrs, id)
	return true, g.saveLocked()
}

// bounded makes room for one more entry by dropping the oldest.
func bounded(m map[string]time.Time) {
	if len(m) < maxForgotten {
		return
	}
	oldest := ""
	for k, at := range m {
		if oldest == "" || at.Before(m[oldest]) {
			oldest = k
		}
	}
	delete(m, oldest)
}

// instancesOnline lists the approved instances that can be called now, but
// for except.
func (g *Group) instancesOnline(except string) []string {
	var out []string
	for id, m := range g.look(time.Now()) {
		if id != except && m.Kind == member.KindInstance && m.State == StateApproved && m.Online() {
			out = append(out, id)
		}
	}
	return out
}

const (
	opApprove = "approve"
	opRemove  = "remove"
)

// decision is an approval or a removal passed from one instance to another.
type decision struct {
	Op   string      `json:"op"`
	ID   string      `json:"id"`
	Kind member.Kind `json:"kind,omitempty"`
	Key  []byte      `json:"key,omitempty"`
}

// passOn tells every instance in to of d in the background. One that misses it
// catches up from the roster later.
func (g *Group) passOn(d decision, to []string) {
	body, err := json.Marshal(d)
	if err != nil {
		return
	}
	for _, id := range to {
		if !g.enter() {
			return
		}
		go func() {
			defer g.wg.Done()
			ctx, cancel := context.WithTimeout(g.ctx, callTimeout)
			defer cancel()
			_, _, _ = g.Call(ctx, id, http.MethodPost, decisionPath, body)
		}()
	}
}

// internal answers the routes the group serves itself. Only an approved
// instance decides who else is in the group or reads who is.
func (g *Group) internal(caller Caller, call relay.ProxyCall) (int, []byte) {
	instance := caller.Kind == member.KindInstance
	switch {
	case call.Path == helloPath:
		return http.StatusOK, g.hello()
	case call.Path == decisionPath && call.Method == http.MethodPost && instance:
		var d decision
		if json.Unmarshal(call.Body, &d) != nil {
			return http.StatusBadRequest, nil
		}
		g.decide(d, time.Now())
		return http.StatusNoContent, nil
	case call.Path == rosterPath && call.Method == http.MethodGet && instance:
		b, _ := json.Marshal(g.roster())
		return http.StatusOK, b
	}
	return http.StatusNotFound, nil
}

// decide applies d, as an approved instance passed it on.
func (g *Group) decide(d decision, now time.Time) {
	switch d.Op {
	case opRemove:
		if d.ID == g.self {
			if g.onRemoved != nil {
				g.removed.Do(func() { go g.onRemoved() })
			}
			return
		}
		if kindOfID(d.ID) != "" {
			_ = g.forget(d.ID, now)
		}
	case opApprove:
		g.approvePassed(d.ID, d.Kind, d.Key, now)
	}
}

// approvePassed pins key as approved for id unless id was removed, the key was
// revoked, another key is pinned or the key does not make id.
func (g *Group) approvePassed(id string, kind member.Kind, key []byte, now time.Time) {
	if id == g.self || !claimFits(id, kind, key) {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	st := &g.st
	_, removed := st.Removed[id]
	if _, revoked := st.Revoked[hex.EncodeToString(key)]; revoked || removed {
		return
	}
	if rec, ok := st.Members[id]; ok {
		if rec.Approved || !bytes.Equal(rec.Key, key) {
			return
		}
		rec.Approved, rec.Used = true, now
		st.Members[id] = rec
		if g.saveLocked() != nil {
			rec.Approved = false
			st.Members[id] = rec
		}
		return
	}
	idle := ""
	if len(st.Members) >= maxPinned {
		if idle = idlePinLocked(st, now); idle == "" {
			return
		}
	}
	_ = g.pinLocked(id, record{Kind: kind, Key: bytes.Clone(key), Approved: true, Used: now}, idle)
}

// roster is what an instance tells the others of who is approved and who was
// taken out, for one that was away when it was decided.
type roster struct {
	Members []rosterMember       `json:"members"`
	Removed map[string]time.Time `json:"removed,omitempty"`
}

type rosterMember struct {
	ID   string      `json:"id"`
	Kind member.Kind `json:"kind"`
	Key  []byte      `json:"key"`
}

func (g *Group) roster() roster {
	g.mu.Lock()
	defer g.mu.Unlock()
	r := roster{Members: []rosterMember{}, Removed: map[string]time.Time{}}
	for id, rec := range g.st.Members {
		if rec.Approved {
			r.Members = append(r.Members, rosterMember{ID: id, Kind: rec.Kind, Key: bytes.Clone(rec.Key)})
		}
	}
	for id, at := range g.st.Removed {
		r.Removed[id] = at
	}
	return r
}

// merge takes from r, the roster of an approved instance, the approvals and
// removals missing here.
func (g *Group) merge(r roster, now time.Time) {
	for id := range r.Removed {
		if id != g.self && kindOfID(id) != "" {
			_ = g.forget(id, now)
		}
	}
	for i, m := range r.Members {
		if i >= maxPinned {
			break
		}
		g.approvePassed(m.ID, m.Kind, m.Key, now)
	}
}

// serveApp hands call to the app's handler as an HTTP request and records the
// answer. Only a path is accepted, so a call cannot name a host.
func (g *Group) serveApp(ctx context.Context, call relay.ProxyCall) (status int, body []byte) {
	if !strings.HasPrefix(call.Path, "/") || strings.HasPrefix(call.Path, "//") {
		return http.StatusBadRequest, nil
	}
	req, err := http.NewRequestWithContext(ctx, call.Method, call.Path, bytes.NewReader(call.Body))
	if err != nil {
		return http.StatusBadRequest, nil
	}
	req.RequestURI = call.Path
	if len(call.Body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := &recorder{header: http.Header{}}
	// The relay client runs this on a goroutine of its own, where no
	// net/http server would recover a panicking handler.
	defer func() {
		if r := recover(); r != nil {
			slog.Error("group: a handler panicked", "method", call.Method, "path", call.Path, "panic", fmt.Sprint(r))
			status, body = http.StatusInternalServerError, nil
		}
	}()
	g.serve.ServeHTTP(rec, req)
	if rec.tooLarge {
		return http.StatusInternalServerError, relay.RefusalBody("answerTooLarge", "the answer is larger than a member may send")
	}
	if rec.status == 0 {
		rec.status = http.StatusOK
	}
	return rec.status, rec.body.Bytes()
}

var errAnswerTooLarge = errors.New("group: the answer is larger than a member may send")

// recorder is the ResponseWriter the app answers a member's call into.
type recorder struct {
	header   http.Header
	status   int
	body     bytes.Buffer
	tooLarge bool
}

func (r *recorder) Header() http.Header { return r.header }

func (r *recorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
}

func (r *recorder) Write(p []byte) (int, error) {
	r.WriteHeader(http.StatusOK)
	if r.tooLarge || r.body.Len()+len(p) > maxAnswerBytes {
		r.tooLarge = true
		return 0, errAnswerTooLarge
	}
	return r.body.Write(p)
}
