package group

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"maps"
	"strings"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/member"
	"github.com/junkerderprovinz/parleyport/kit/relay"
)

// Roster is what a group keeps of its members: the ones whose key is pinned
// here, the ids taken out and the member keys revoked, each with when.
type Roster struct {
	// Members are the members whose key is pinned here, each StatePending or
	// StateApproved. Direct, Relay and Awaiting mean nothing in a roster.
	Members []Member
	Removed map[string]time.Time
	// Revoked holds every revoked member key in hex.
	Revoked map[string]time.Time
}

// Roster returns what this instance keeps of the group, for an app that shows
// who was taken out or answers instances on a format of its own.
func (g *Group) Roster() Roster {
	g.mu.Lock()
	defer g.mu.Unlock()
	r := Roster{Members: make([]Member, 0, len(g.st.Members)), Removed: maps.Clone(g.st.Removed), Revoked: maps.Clone(g.st.Revoked)}
	for id, rec := range g.st.Members {
		r.Members = append(r.Members, Member{
			ID: id, Kind: rec.Kind, Name: rec.Name, Deployment: rec.Deployment, Address: rec.Address,
			Key: bytes.Clone(rec.Key), State: rec.state(), LastSeen: later(rec.Seen, rec.Used),
		})
	}
	sortMembers(r.Members)
	return r
}

// Import takes from r what this instance lacks, as if it had been decided
// here, and passes nothing on. An app moves a group it kept in a format of its
// own onto this package with it, right after Open, and takes in the same way
// a decision an instance on that format passes on, such as an approval that
// comes with the device's key and kind.
//
// Removed ids and revoked keys come first, and a member they cover stays out.
// A member is pinned only under the id its key and kind make, never in place
// of another key and only while there is room. A member approved here stays approved, and a name or a last-seen time
// replaces the one known here only when it is newer. A time ahead of this
// instance's clock counts as now. The error is the store's.
func (g *Group) Import(r Roster) error {
	now := time.Now()
	g.mu.Lock()
	var gone []string
	changed := false
	for id, at := range r.Removed {
		if id != g.self && kindOfID(id) != "" && g.forgetLocked(id, earliest(at, now)) {
			gone = append(gone, id)
		}
	}
	for key, at := range r.Revoked {
		if !keyHex(key) {
			continue
		}
		at = earliest(at, now)
		for id, rec := range g.st.Members {
			if hex.EncodeToString(rec.Key) == key && g.forgetLocked(id, at) {
				gone = append(gone, id)
			}
		}
		if _, done := g.st.Revoked[key]; !done {
			g.revokeLocked(key, at)
			changed = true
		}
	}
	for _, m := range r.Members {
		if g.takeLocked(m, now) {
			changed = true
		}
	}
	var err error
	if changed || len(gone) > 0 {
		if err = g.saveLocked(); err != nil {
			g.dirty = true
		}
	}
	g.mu.Unlock()
	if g.onRemove != nil {
		for _, id := range gone {
			g.onRemove(id)
		}
	}
	return err
}

// takeLocked pins or updates m as Import describes and reports whether it
// changed anything.
func (g *Group) takeLocked(m Member, now time.Time) bool {
	if m.ID == g.self || (m.State != StatePending && m.State != StateApproved) || kindOfID(m.ID) != m.Kind ||
		!claimFits(m.ID, m.Kind, m.Key) {
		return false
	}
	st := &g.st
	_, removed := st.Removed[m.ID]
	if _, revoked := st.Revoked[hex.EncodeToString(m.Key)]; revoked || removed {
		return false
	}
	approved := m.State == StateApproved
	seen := earliest(m.LastSeen, now)
	rec, ok := st.Members[m.ID]
	if !ok {
		if !approved && waitingLocked(st) >= maxWaiting {
			return false
		}
		if len(st.Members) >= maxPinned {
			idle := idlePinLocked(st, now)
			if idle == "" {
				return false
			}
			delete(st.Members, idle)
		}
		used := seen
		if used.IsZero() {
			used = now
		}
		rec = record{Kind: m.Kind, Key: bytes.Clone(m.Key), Approved: approved, Used: used, Seen: seen}
		rec.describe(m, true)
		if st.Members == nil {
			st.Members = map[string]record{}
		}
		st.Members[m.ID] = rec
		return true
	}
	if !bytes.Equal(rec.Key, m.Key) {
		return false
	}
	changed := false
	if approved && !rec.Approved {
		// Approving counts as use, so a key approved and passed on is not
		// taken for idle before the device first calls.
		rec.Approved, rec.Used, changed = true, now, true
	}
	newer := seen.After(later(rec.Seen, rec.Used))
	if newer {
		rec.Seen = seen
	}
	if rec.describe(m, newer) || newer {
		changed = true
	}
	if changed {
		st.Members[m.ID] = rec
	}
	return changed
}

// describe takes m's name, deployment and address, each only where m has one,
// and where r has none unless over is set. It reports whether r changed.
func (r *record) describe(m Member, over bool) bool {
	changed := false
	set := func(field *string, value string) {
		if value != "" && *field != value && (over || *field == "") {
			*field, changed = value, true
		}
	}
	set(&r.Name, relay.ClipName(m.Name))
	set(&r.Deployment, relay.ClipName(m.Deployment))
	set(&r.Address, relay.FitAddress(m.Address))
	return changed
}

func (r record) state() State {
	if r.Approved {
		return StateApproved
	}
	return StatePending
}

// forgetLocked takes id out of the group as of at and reports whether it was
// not out already: its key is revoked and its address dropped.
func (g *Group) forgetLocked(id string, at time.Time) bool {
	st := &g.st
	if _, done := st.Removed[id]; done {
		return false
	}
	rec, known := st.Members[id]
	delete(st.Members, id)
	if st.Removed == nil {
		st.Removed = map[string]time.Time{}
	}
	bounded(st.Removed)
	st.Removed[id] = at
	if known {
		g.revokeLocked(hex.EncodeToString(rec.Key), at)
	}
	delete(g.addrs, id)
	return true
}

func (g *Group) revokeLocked(key string, at time.Time) {
	if g.st.Revoked == nil {
		g.st.Revoked = map[string]time.Time{}
	}
	bounded(g.st.Revoked)
	g.st.Revoked[key] = at
}

// keyHex reports whether s is a member key in lowercase hex, as the revoked
// list keeps them.
func keyHex(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == ed25519.PublicKeySize && strings.ToLower(s) == s
}

// earliest keeps a time another instance reports from lying ahead of this
// instance's clock.
func earliest(at, now time.Time) time.Time {
	if at.After(now) {
		return now
	}
	return at
}

func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// roster is what an instance tells the others of who is approved and who was
// taken out, for one that was away when it was decided, and of what each
// member goes by and when it was last there, for a phone or a browser the
// other never met.
type roster struct {
	Members []rosterMember       `json:"members"`
	Removed map[string]time.Time `json:"removed,omitempty"`
}

type rosterMember struct {
	ID         string      `json:"id"`
	Kind       member.Kind `json:"kind"`
	Key        []byte      `json:"key"`
	Name       string      `json:"name,omitempty"`
	Deployment string      `json:"deployment,omitempty"`
	Seen       time.Time   `json:"seen,omitzero"`
}

func (g *Group) roster() roster {
	g.mu.Lock()
	defer g.mu.Unlock()
	r := roster{Members: []rosterMember{}, Removed: maps.Clone(g.st.Removed)}
	for id, rec := range g.st.Members {
		if rec.Approved {
			r.Members = append(r.Members, rosterMember{ID: id, Kind: rec.Kind, Key: bytes.Clone(rec.Key),
				Name: rec.Name, Deployment: rec.Deployment, Seen: later(rec.Seen, rec.Used)})
		}
	}
	return r
}

// merge takes from r, the roster of an approved instance, the approvals,
// removals and sightings missing here.
func (g *Group) merge(r roster) {
	in := Roster{Removed: r.Removed}
	for i, m := range r.Members {
		if i >= maxPinned {
			break
		}
		in.Members = append(in.Members, Member{ID: m.ID, Kind: m.Kind, Key: m.Key, State: StateApproved,
			Name: m.Name, Deployment: m.Deployment, LastSeen: m.Seen})
	}
	_ = g.Import(in)
}
