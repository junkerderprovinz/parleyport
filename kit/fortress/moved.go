package fortress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
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
