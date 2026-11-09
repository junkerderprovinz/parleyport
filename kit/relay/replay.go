package relay

import (
	"sync"
	"time"
)

// ClockSkew is how far a call's timestamp may be from this instance's clock.
const ClockSkew = 2 * time.Minute

// maxSeenPerMember bounds the ids one member key can have on record. A member
// polling once a second stays far below it within the 2*ClockSkew that ids are
// kept.
const maxSeenPerMember = 4096

// StatusDrop is the status a ProxyHandler returns for a call that gets no
// answer at all, such as one played back a second time.
const StatusDrop = 0

// Recent reports whether call names an id and was sealed close enough to now
// to be taken at all.
func Recent(call ProxyCall, now time.Time) bool {
	d := now.Sub(time.Unix(call.Sent, 0))
	return call.ID != "" && d <= ClockSkew && d >= -ClockSkew
}

// ReplayGuard admits each signed call once and only while its timestamp is
// recent. One guard serves every transport an instance takes calls on, so a
// call captured on one cannot run again on another. Ids are kept per member
// key, so one member can neither use up nor fill another's record; the guard
// is meant for keys the instance has pinned, which bounds the records.
type ReplayGuard struct {
	mu   sync.Mutex
	seen map[string]map[string]struct{}
	// order holds every id on record from order[head] on, oldest first, so
	// the ids that ran out are always at its front.
	order []seenID
	head  int
	now   func() time.Time
}

type seenID struct {
	bucket, id string
	at         time.Time
}

// NewReplayGuard returns a guard that has seen nothing.
func NewReplayGuard() *ReplayGuard {
	return &ReplayGuard{seen: map[string]map[string]struct{}{}, now: time.Now}
}

// Admit reports whether call is recent, signed and new, and records it. Ids
// are kept for twice the skew, which covers every call whose timestamp would
// still pass. The call has to come from OpenCall, which checked its signature.
func (g *ReplayGuard) Admit(call ProxyCall) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	if !Recent(call, now) || !call.Signed() {
		return false
	}
	g.forgetLocked(now)
	bucket := string(call.Key)
	ids := g.seen[bucket]
	if _, dup := ids[call.ID]; dup || len(ids) >= maxSeenPerMember {
		return false
	}
	if ids == nil {
		ids = map[string]struct{}{}
		g.seen[bucket] = ids
	}
	ids[call.ID] = struct{}{}
	g.order = append(g.order, seenID{bucket: bucket, id: call.ID, at: now})
	return true
}

// Len is how many ids the guard has on record.
func (g *ReplayGuard) Len() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.order) - g.head
}

// forgetLocked drops the ids that ran out, which all sit at the front of
// order, so each id costs one step however many members there are.
func (g *ReplayGuard) forgetLocked(now time.Time) {
	for g.head < len(g.order) && now.Sub(g.order[g.head].at) > 2*ClockSkew {
		old := g.order[g.head]
		g.order[g.head] = seenID{}
		g.head++
		ids := g.seen[old.bucket]
		delete(ids, old.id)
		if len(ids) == 0 {
			delete(g.seen, old.bucket)
		}
	}
	if g.head > len(g.order)/2 {
		n := copy(g.order, g.order[g.head:])
		clear(g.order[n:])
		g.order, g.head = g.order[:n], 0
	}
}
