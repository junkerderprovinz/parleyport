package fortress

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/group"
	"github.com/junkerderprovinz/parleyport/kit/keys"
	"github.com/junkerderprovinz/parleyport/kit/member"
	"github.com/junkerderprovinz/parleyport/kit/relay"
)

type movedBody struct {
	Group    string `json:"group"`
	Frame    []byte `json:"frame"`
	PeerAuth []byte `json:"peerAuth"`
}

// Moved serves next to the app's own pairing once this instance moved it
// into the fortress current returns, nil before. It hands the phones,
// extensions and viewers that pairing let in the keys the pairing runs on in
// the fortress, which they fetch with MovedKeys. The secret behind them opens
// the fortress and the pairing of every app in it, so it goes to instances
// alone, with Move.
func Moved(next http.Handler, current func() *Fortress) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != movedPath {
			next.ServeHTTP(w, r)
			return
		}
		caller, ok := group.CallerOf(r.Context())
		if !ok || caller.Kind == member.KindInstance {
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		f := current()
		if f == nil || f.pairing == nil {
			writeError(w, http.StatusNotFound, "not_moved")
			return
		}
		writeJSON(w, movedBody{Group: f.paired.Group, Frame: f.paired.Frame, PeerAuth: f.paired.PeerAuth}) //nolint:gosec // G117: sealed to a member of the pairing
	})
}

// MovedKeys asks instance id, through c on the app's own pairing, for the keys
// the pairing runs on since that instance moved it into a fortress. A phone or
// viewer then joins the pairing with them under its own member key, which the
// pairing still approves.
func MovedKeys(ctx context.Context, c *relay.Client, id string) (keys.Set, error) {
	body, status, err := c.Proxy(ctx, id, http.MethodGet, movedPath, nil)
	if err != nil {
		return keys.Set{}, err
	}
	return movedSet(id, status, body)
}

// movedSet reads the keys instance id answered with status and body at
// movedPath.
func movedSet(id string, status int, body []byte) (keys.Set, error) {
	if status != http.StatusOK {
		return keys.Set{}, refusal(status, body)
	}
	var b movedBody
	if err := json.Unmarshal(body, &b); err != nil {
		return keys.Set{}, fmt.Errorf("fortress: %s answered unreadably: %w", id, err)
	}
	set := keys.Set{Group: b.Group, Frame: b.Frame, PeerAuth: b.PeerAuth}
	if !set.Complete() {
		return keys.Set{}, errors.New("fortress: the keys came incomplete")
	}
	return set, nil
}

// Left lists the members the app's own pairing old let in that the pairing
// in the fortress has not met since it moved there: instances that have not
// followed with Move, and phones and viewers that have not with MovedKeys.
// What the pairing met is kept in its store, so a restart forgets nobody.
func (f *Fortress) Left(old *group.Group) []group.Member {
	met := map[string]bool{}
	if f.pairing != nil {
		for _, m := range f.pairing.Members() {
			if !m.Met.IsZero() {
				met[m.ID] = true
			}
		}
	}
	var out []group.Member
	for _, m := range old.Members() {
		if m.State == group.StateApproved && !met[m.ID] {
			out = append(out, m)
		}
	}
	return out
}

// moveWindow is how long the app's own pairing stays open for the members
// that have not followed it into the fortress.
const moveWindow = 30 * 24 * time.Hour

// Settle reports whether the app closes old, its own pairing from before the
// fortress, now and forgets its phrase: every member old let in has followed,
// or 30 days have passed since Settle first looked at old, which the app does
// as soon as it opens the fortress. The members that had not followed by then
// are listed by Behind.
func (f *Fortress) Settle(old *group.Group) bool {
	left := f.Left(old)
	if len(left) == 0 {
		return true
	}
	if time.Since(old.Retire()) < moveWindow {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.book.Behind == nil {
		f.book.Behind = map[string]straggler{}
	}
	for _, m := range left {
		f.book.Behind[m.ID] = straggler{Kind: m.Kind, Name: m.Name, Deployment: m.Deployment}
	}
	f.dirty = true
	_ = f.saveLocked()
	return true
}

// Behind lists the members the app's own pairing let in that had not followed
// it into the fortress when Settle closed it, sorted by name, until they come
// along under their key or are taken out with Remove. Each carries its ID,
// Kind, Name and Deployment, and nothing else.
func (f *Fortress) Behind() []group.Member {
	f.prune()
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]group.Member, 0, len(f.book.Behind))
	for id, s := range f.book.Behind {
		out = append(out, group.Member{ID: id, Kind: s.Kind, Name: s.Name, Deployment: s.Deployment})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// prune forgets the members left behind that the pairing has met since, or
// lists no more. A pairing that moves to a changed phrase meets everybody
// anew, so one that came along is forgotten rather than skipped.
func (f *Fortress) prune() {
	f.mu.Lock()
	none := len(f.book.Behind) == 0
	f.mu.Unlock()
	if none || f.pairing == nil {
		return
	}
	listed := map[string]group.Member{}
	for _, m := range f.pairing.Members() {
		listed[m.ID] = m
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for id := range f.book.Behind {
		if m, ok := listed[id]; !ok || !m.Met.IsZero() {
			delete(f.book.Behind, id)
			f.dirty = true
		}
	}
}

// phraseChanged is the code a member answers on the phrase the fortress left.
const phraseChanged = "phrase_changed"

// askTimeout bounds how long a newcomer waits while the members met before
// are asked whether the fortress left this phrase.
const askTimeout = 5 * time.Second

// mayJoin lets newcomer id into the fortress on the strength of the phrase
// alone unless a member met before says the fortress left this phrase. Every
// such member in reach is asked anew, once for all the newcomers that arrive
// while it is asked.
func (f *Fortress) mayJoin(ctx context.Context, id string) bool {
	arrived := time.Now()
	select {
	case <-f.opened:
	case <-ctx.Done():
		return false
	}
	select {
	case f.asking <- struct{}{}:
		defer func() { <-f.asking }()
	case <-ctx.Done():
		return false
	}
	f.mu.Lock()
	shut, asked := !f.shutSince.IsZero(), f.asked
	f.mu.Unlock()
	if shut {
		return false
	}
	if !asked.Before(arrived) {
		return true
	}
	started := time.Now()
	var ids []string
	for _, m := range f.group.Members() {
		if m.ID != id && m.Kind == member.KindInstance && m.State == group.StateApproved && m.Online() &&
			!m.Met.IsZero() && m.Met.Before(arrived) {
			ids = append(ids, m.ID)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, askTimeout)
	defer cancel()
	var wg sync.WaitGroup
	for _, other := range ids {
		wg.Go(func() { f.describe(ctx, other, started) })
	}
	wg.Wait()
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.shutSince.IsZero() {
		return false
	}
	f.asked = started
	return true
}

// shut closes the fortress on this phrase to newcomers once a member says it
// took a new one at changed, and turns away whoever was first met since.
func (f *Fortress) shut(changed time.Time) {
	now := time.Now()
	if changed.IsZero() || changed.After(now) {
		changed = now
	}
	f.mu.Lock()
	if !f.shutSince.IsZero() && !changed.Before(f.shutSince) {
		f.mu.Unlock()
		return
	}
	f.shutSince = changed
	g := f.group
	f.mu.Unlock()
	if g != nil {
		g.CloseToNew(changed)
	}
}

// ErrNoNewPhrase is what NewKeys returns when no member in reach says that
// the fortress changed its phrase.
var ErrNoNewPhrase = errors.New("fortress: no member in reach took a new phrase")

// NewKeys fetches the keys the fortress runs on since its phrase changed,
// for a member that holds only keys, such as a plugin: a member that took the
// new phrase hands them, for 30 days, to every instance that was approved
// before the change and has not been taken out. The member opens the
// fortress with them under the same Identity, and the others keep it as the
// member it was. Neither the secret nor the keys of any app's pairing come
// with them.
func (f *Fortress) NewKeys(ctx context.Context) (keys.Set, error) {
	f.mu.Lock()
	current := f.book.Group
	var ids []string
	for id, a := range f.book.Members {
		if a.Moved {
			ids = append(ids, id)
		}
	}
	f.mu.Unlock()
	sort.Strings(ids)
	err := ErrNoNewPhrase
	for _, id := range ids {
		set, e := f.movedKeys(ctx, id)
		switch {
		case e != nil:
			err = e
		case set.Group != current:
			return set, nil
		}
	}
	return keys.Set{}, err
}

// movedKeys asks member id for the keys under the new phrase.
func (f *Fortress) movedKeys(ctx context.Context, id string) (keys.Set, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	status, body, err := f.group.Call(ctx, id, http.MethodGet, movedPath, nil)
	if err != nil {
		return keys.Set{}, err
	}
	return movedSet(id, status, body)
}

// openOld opens the fortress on cfg.Previous for the members from before the
// change that were away for it, which have no way to the new phrase but this.
// The phrase lets nobody in there: only the instances the fortress approved
// under the same key are, and they are handed set or, holding the old phrase,
// the new secret. Whoever else holds the old phrase learns neither this
// instance's name nor who is in the fortress.
func (f *Fortress) openOld(cfg Config, set keys.Set) error {
	f.set, f.previous = set, bytes.Clone(cfg.Previous)
	old, err := group.Open(group.Config{
		Domain:      Domain,
		Secret:      cfg.Previous,
		Identity:    cfg.Identity,
		Relay:       cfg.Relay,
		RelayURL:    cfg.RelayURL,
		Store:       &memory{},
		Vouch:       func(id string, key ed25519.PublicKey) bool { return approvedIn(f.group, id, key) },
		VouchedOnly: true,
	}, http.HandlerFunc(f.serveOld))
	if err != nil {
		return err
	}
	f.old = old
	return nil
}

// serveOld answers the members still on the phrase before: what this
// instance is, marked as moved, the keys under the new phrase and, sealed
// with handNewPhrase, its secret. Whatever else they ask waits until they
// followed. Every call is checked against the fortress as it stands, so a
// member taken out since the change gets nothing.
func (f *Fortress) serveOld(w http.ResponseWriter, r *http.Request) {
	caller, ok := group.CallerOf(r.Context())
	switch {
	case !ok || caller.Kind != member.KindInstance || !approvedIn(f.group, caller.ID, caller.Key):
		writeError(w, http.StatusForbidden, "forbidden")
	case r.URL.Path == aboutPath && r.Method == http.MethodGet:
		a := f.about
		f.mu.Lock()
		a.Moved, a.Changed = true, f.book.Changed
		f.mu.Unlock()
		writeJSON(w, a)
	case (r.URL.Path == movedPath || r.URL.Path == newPhrasePath) && time.Since(f.changed()) >= moveWindow:
		writeError(w, http.StatusGone, phraseChanged)
	case (r.URL.Path == movedPath || r.URL.Path == newPhrasePath) && !f.heardBefore(caller.ID, f.removedSince(f.before())):
		writeError(w, http.StatusForbidden, "forbidden")
	case r.URL.Path == movedPath && r.Method == http.MethodGet:
		writeJSON(w, movedBody{Group: f.set.Group, Frame: f.set.Frame, PeerAuth: f.set.PeerAuth}) //nolint:gosec // G117: sealed to an approved member
	case r.URL.Path == newPhrasePath && r.Method == http.MethodPost:
		f.handNewPhrase(w, r, caller.ID)
	default:
		writeError(w, http.StatusGone, phraseChanged)
	}
}
