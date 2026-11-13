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
	// maxAnswerBytes bounds what the app answers a call with, unless it
	// allows more.
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
	// Left are the members that left the group themselves.
	Left map[string]time.Time `json:"left,omitempty"`
	// LeftSig is each such member's own signature on its leaving, which
	// lets the others take it from a roster.
	LeftSig map[string][]byte `json:"leftSig,omitempty"`
	// Address is this instance's direct address as NoteAddress learned it.
	Address string `json:"address,omitempty"`
	// Retired is when Retire first ran under this group key.
	Retired time.Time `json:"retired,omitzero"`
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
	// Direct is where the member last answered a direct call, tried first
	// when the group opens again.
	Direct string `json:"direct,omitempty"`
	// Met is when the key first signed a call or an answer here under the
	// group key the state is kept under, Pinned when it was first pinned
	// here under any.
	Met    time.Time `json:"met,omitzero"`
	Pinned time.Time `json:"pinned,omitzero"`
}

// meet records that the key pinned in r signed something here at now.
func (r *record) meet(now time.Time) bool {
	if !r.Met.IsZero() {
		return false
	}
	r.Met = now
	return true
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
			st.Group, st.Retired = groupKey, time.Time{}
			// Nobody signed anything under the new phrase yet.
			for id, rec := range st.Members {
				rec.Met = time.Time{}
				st.Members[id] = rec
			}
			return st, true, nil
		}
	}
	return fresh, false, nil
}

func (g *Group) saveLocked() error {
	g.stir()
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
	// kindNotTakenRefusal answers a device of a kind the app keeps out of its
	// group, such as a phone where only instances pair.
	kindNotTakenRefusal = refuse(http.StatusForbidden, "memberKindRefused", "this group takes no devices of this kind")
	strangerRefusal     = refuse(http.StatusForbidden, "groupClosed", "this instance takes no new members on this phrase")
	newPhraseRefusal    = refuse(http.StatusForbidden, ClosedUntilNewPhrase, "this group takes no new members until its phrase changes")
	// askFirst never leaves the group: admitCall asks MayJoin and admits the
	// call again.
	askFirst = &refusal{}
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
	caller, r := g.admitCall(ctx, call)
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

// admitCall decides whose call this is, as admit does, and asks MayJoin first
// where admit says so.
func (g *Group) admitCall(ctx context.Context, call relay.ProxyCall) (Caller, *refusal) {
	vouched := g.vouched(call.From, call.Kind, call.Key)
	caller, r := g.admit(call, relay.SourceOf(ctx), vouched, false, time.Now())
	if r != askFirst {
		return caller, r
	}
	if !g.mayJoin(ctx, call.From) {
		return Caller{}, strangerRefusal
	}
	return g.admit(call, relay.SourceOf(ctx), vouched, true, time.Now())
}

// vouched reports whether Vouch lets in instance id under key, which is
// asked only of an instance not approved here yet. It runs without g.mu, so
// Vouch may look at another group.
func (g *Group) vouched(id string, kind member.Kind, key ed25519.PublicKey) bool {
	if g.vouch == nil || kind != member.KindInstance || !claimFits(id, kind, key) {
		return false
	}
	g.mu.Lock()
	rec, ok := g.st.Members[id]
	g.mu.Unlock()
	if ok && rec.Approved {
		return false
	}
	return g.vouch(id, key)
}

// admit decides whose call this is: whether the id it names is the one its
// key makes, whether that key is approved, and whether the call ran before. A
// call's id is used up only once it is known to come from a pinned key, so a
// stranger fills no record a member needs. An instance vouched for is
// approved here as it calls. A member the phrase alone would let in is
// refused with askFirst until MayJoin was asked, which asked says.
func (g *Group) admit(call relay.ProxyCall, source string, vouched, asked bool, now time.Time) (Caller, *refusal) {
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
	if !g.takes(call.Kind) {
		return Caller{}, kindNotTakenRefusal
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	st := &g.st
	_, removed := st.Removed[call.From]
	_, left := st.Left[call.From]
	if _, revoked := st.Revoked[hex.EncodeToString(call.Key)]; revoked || removed || left {
		return Caller{}, removedRefusal
	}
	ask := g.mayJoin != nil && g.byPhrase && !vouched && !asked && g.closedSince.IsZero()
	if rec, ok := st.Members[call.From]; ok {
		if g.closedToLocked(rec) && !vouched {
			return Caller{}, g.closedRefusalLocked()
		}
		if ask && rec.Met.IsZero() {
			return Caller{}, askFirst
		}
		if !g.replay.Admit(call) {
			return Caller{}, dropped
		}
		changed := rec.meet(now)
		if now.Sub(rec.Used) >= lastSeenStep {
			rec.Used, changed = now, true
		}
		if !rec.Approved && vouched {
			rec.Approved, changed = true, true
		}
		if changed {
			st.Members[call.From] = rec
			g.dirty = true
		}
		switch {
		case !rec.Approved && g.vouchedOnly:
			return Caller{}, strangerRefusal
		case !rec.Approved && !g.byPhrase:
			return Caller{}, pendingRefusal
		}
		return Caller{ID: call.From, Kind: rec.Kind, Key: rec.Key}, nil
	}
	if (g.vouchedOnly || !g.closedSince.IsZero()) && !vouched {
		return Caller{}, g.closedRefusalLocked()
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
	if ask {
		return Caller{}, askFirst
	}
	if !g.limits.mayPin(source, now) {
		return Caller{}, refuse(http.StatusTooManyRequests, "groupJoinsBusy", "too many new devices joined this group within the hour")
	}
	approved := g.byPhrase || vouched
	if err := g.pinLocked(call.From, record{Kind: call.Kind, Key: bytes.Clone(call.Key), Approved: approved, Used: now, Met: now, Pinned: now}, idle); err != nil {
		return Caller{}, refuse(http.StatusInternalServerError, "memberNotPinned", "this instance could not record the device's key")
	}
	g.replay.Admit(call)
	if approved {
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
// target's: target is approved here as an instance, under that key. An
// instance not pinned yet is pinned by its answer.
func (g *Group) trustsAnswer(target string, key ed25519.PublicKey) bool {
	vouched := g.vouched(target, member.KindInstance, key)
	if g.asks(target, vouched) {
		// MayJoin may be waiting for this very answer, so it gets no longer
		// than a call.
		ctx, cancel := context.WithTimeout(g.ctx, callTimeout)
		ok := g.mayJoin(ctx, target)
		cancel()
		if !ok {
			return false
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	rec, ok := g.st.Members[target]
	if !ok {
		rec, ok = g.pinAnswerLocked(target, key, vouched)
	}
	if !ok || rec.Kind != member.KindInstance || !bytes.Equal(rec.Key, key) {
		return false
	}
	changed := rec.meet(time.Now())
	if !rec.Approved && vouched {
		rec.Approved, changed = true, true
	}
	if changed {
		g.st.Members[target] = rec
		g.dirty = true
	}
	return rec.Approved
}

// pinAnswerLocked pins key for instance id, as an answer id signed with it
// shows, so an instance that cannot be called back still learns of the other:
// approved where the phrase is enough or the instance is vouched for, else
// waiting for approval. It pins nothing that was taken out, a key that speaks
// for another member, or past the room there is and the new keys of the hour.
func (g *Group) pinAnswerLocked(id string, key []byte, vouched bool) (record, bool) {
	st := &g.st
	now := time.Now()
	_, removed := st.Removed[id]
	_, left := st.Left[id]
	_, revoked := st.Revoked[hex.EncodeToString(key)]
	if removed || left || revoked || (g.vouchedOnly || !g.closedSince.IsZero()) && !vouched || !claimFits(id, member.KindInstance, key) || len(st.Members) >= maxPinned ||
		(!g.byPhrase && waitingLocked(st) >= maxWaiting) {
		return record{}, false
	}
	for _, rec := range st.Members {
		if bytes.Equal(rec.Key, key) {
			return record{}, false
		}
	}
	if !g.limits.mayPin("", now) {
		return record{}, false
	}
	rec := record{Kind: member.KindInstance, Key: bytes.Clone(key), Approved: g.byPhrase || vouched, Used: now, Met: now, Pinned: now}
	if g.pinLocked(id, rec, "") != nil {
		return record{}, false
	}
	return rec, true
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

// Leave tells every instance in reach that this one left the group, so they
// drop it at once, and the others hear it from their rosters. Close waits
// until it went out. The app forgets the membership after it.
func (g *Group) Leave() {
	at := time.Now().Unix()
	sig := g.identity.Sign(g.leaveMessage(g.self, at))
	g.passOn(decision{Op: opLeave, ID: g.self, At: at, Sig: sig}, g.instancesOnline(""))
}

// leaveMessage is what member id signs when it leaves, at the Unix time at.
func (g *Group) leaveMessage(id string, at int64) []byte {
	return member.Message(g.signing.Call+"/leave", uint64(at), []byte(id)) //nolint:gosec // G115: the bits of the time are signed as they are
}

// leftInOwnWordsLocked reports whether sig is member id's own signature on
// its leaving at the Unix time at, under the key pinned here for it.
func (g *Group) leftInOwnWordsLocked(id string, at int64, sig []byte) bool {
	rec, ok := g.st.Members[id]
	return ok && len(rec.Key) == ed25519.PublicKeySize && ed25519.Verify(rec.Key, g.leaveMessage(id, at), sig)
}

// dropLeft drops id here only and tells the app, the first time.
func (g *Group) dropLeft(id string, at int64, sig []byte) {
	g.mu.Lock()
	if !g.leftInOwnWordsLocked(id, at, sig) {
		g.mu.Unlock()
		return
	}
	newly := g.leftLocked(id, earliest(time.Unix(at, 0), time.Now()))
	if newly {
		g.keepLeaveLocked(id, sig)
	}
	if newly && g.saveLocked() != nil {
		g.dirty = true
	}
	g.mu.Unlock()
	if newly && g.onLeave != nil {
		g.onLeave(id)
	}
}

// forget removes id here only and tells the app, the first time.
func (g *Group) forget(id string, now time.Time) error {
	g.mu.Lock()
	newly := g.forgetLocked(id, now)
	var err error
	if newly {
		err = g.saveLocked()
	}
	g.mu.Unlock()
	if newly && g.onRemove != nil {
		g.onRemove(id)
	}
	return err
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
	opLeave   = "leave"
)

// decision is an approval, a removal or a leave passed from one instance to
// another.
type decision struct {
	Op   string      `json:"op"`
	ID   string      `json:"id"`
	Kind member.Kind `json:"kind,omitempty"`
	Key  []byte      `json:"key,omitempty"`
	// At and Sig are when a member left and its own signature on it.
	At  int64  `json:"at,omitempty"`
	Sig []byte `json:"sig,omitempty"`
}

// passOn tells every instance in to of d in the background. One that misses it
// catches up from the roster later.
func (g *Group) passOn(d decision, to []string) {
	body, err := json.Marshal(d)
	if err != nil {
		return
	}
	for _, id := range to {
		if !g.enterPassing() {
			return
		}
		go func() {
			defer g.wg.Done()
			defer g.passing.Done()
			ctx, cancel := context.WithTimeout(g.ctx, callTimeout)
			defer cancel()
			_, _, _ = g.Call(ctx, id, http.MethodPost, decisionPath, body)
		}()
	}
}

// enterPassing is enter for a decision passed on, which Close also waits
// for before it cancels the call.
func (g *Group) enterPassing() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return false
	}
	g.wg.Add(1)
	g.passing.Add(1)
	return true
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
		g.decide(d, caller.ID, time.Now())
		return http.StatusNoContent, nil
	case call.Path == rosterPath && call.Method == http.MethodGet && instance:
		b, _ := json.Marshal(g.roster())
		return http.StatusOK, b
	case strings.HasPrefix(call.Path, streamPrefix):
		return http.StatusMisdirectedRequest, relay.RefusalBody("streamDirectOnly", "a stream goes only directly on the local network, never through the relay")
	case strings.HasPrefix(call.Path, uploadPrefix):
		return http.StatusMisdirectedRequest, relay.RefusalBody("uploadDirectOnly", "an upload goes only directly on the local network, as a stream of its own")
	}
	return http.StatusNotFound, nil
}

// decide applies d, as the approved instance from passed it on.
func (g *Group) decide(d decision, from string, now time.Time) {
	switch d.Op {
	case opLeave:
		// Only a member itself leaves. Another one's word would be a removal
		// nobody can see.
		if d.ID == from && d.ID != g.self {
			g.dropLeft(d.ID, d.At, d.Sig)
		}
	case opRemove:
		if d.ID == g.self {
			g.heardRemoved()
			return
		}
		if kindOfID(d.ID) != "" {
			_ = g.forget(d.ID, now)
		}
	case opApprove:
		_ = g.Import(Roster{Members: []Member{{ID: d.ID, Kind: d.Kind, Key: d.Key, State: StateApproved}}})
	}
}

func (g *Group) heardRemoved() {
	if g.onRemoved != nil {
		g.removed.Do(func() { go g.onRemoved() })
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
	rec := &recorder{header: http.Header{}, limit: g.maxRelay}
	if strings.HasPrefix(relay.SourceOf(ctx), directSource) {
		rec.limit = g.maxAnswer
	}
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
	limit    int
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
	if r.tooLarge || r.body.Len()+len(p) > r.limit {
		r.tooLarge = true
		return 0, errAnswerTooLarge
	}
	return r.body.Write(p)
}
