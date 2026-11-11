package fortress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

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
// Once none is left, the app closes old and forgets its phrase.
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
