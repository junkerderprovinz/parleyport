package fortress

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"sync"

	"github.com/junkerderprovinz/parleyport/kit/group"
	"github.com/junkerderprovinz/parleyport/kit/member"
	"github.com/junkerderprovinz/parleyport/kit/phrase"
)

type moveBody struct {
	Secret []byte `json:"secret"`
}

// Move hands the fortress secret to every instance the app's own pairing old
// approved and reaches now, so that the pairing moves into the fortress along
// with the instance that joins it. It returns the ids that took it. An
// instance that was away keeps the app's own phrase until the fortress phrase
// is entered there.
func Move(ctx context.Context, old *group.Group, secret []byte) []string {
	var ids []string
	for _, m := range old.Members() {
		if m.Kind == member.KindInstance && m.State == group.StateApproved && m.Online() {
			ids = append(ids, m.ID)
		}
	}
	return hand(ctx, old, ids, movePath, secret)
}

// Moving serves next to the app's own pairing while the instance is in no
// fortress, and hands the fortress secret an approved sibling passes on with
// Move to keeper. The app then opens its Fortress with the pairing's secret as
// Pairing.Previous. Keep may set off closing the old pairing; the sibling
// still hears that the secret was kept.
func Moving(next http.Handler, keeper Keeper) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != movePath {
			next.ServeHTTP(w, r)
			return
		}
		caller, ok := group.CallerOf(r.Context())
		if !ok || caller.Kind != member.KindInstance {
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		takeSecret(w, r, keeper)
	})
}

// takeSecret hands the secret a member sent to keeper.
func takeSecret(w http.ResponseWriter, r *http.Request, keeper Keeper) {
	var b moveBody
	raw, err := io.ReadAll(r.Body)
	if err != nil || json.Unmarshal(raw, &b) != nil || len(b.Secret) != phrase.SecretLen {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if err := keeper.Keep(b.Secret); err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// hand sends secret to every member in ids at path and returns those that
// kept it.
func hand(ctx context.Context, g *group.Group, ids []string, path string, secret []byte) []string {
	body, err := json.Marshal(moveBody{Secret: secret}) //nolint:gosec // G117: it travels sealed to members only
	if err != nil {
		return nil
	}
	var (
		mu   sync.Mutex
		took []string
		wg   sync.WaitGroup
	)
	for _, id := range ids {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(ctx, callTimeout)
			defer cancel()
			if status, _, err := g.Call(ctx, id, http.MethodPost, path, body); err == nil && status == http.StatusNoContent {
				mu.Lock()
				took = append(took, id)
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	sort.Strings(took)
	return took
}

// ChangePhrase gives the fortress a new phrase. This instance's keeper keeps
// it first, then every instance in reach gets it to keep and the ids of those
// that did come back. A member taken out does not get it, and neither does
// one that is away: it is out until the new phrase is entered there, and then
// in again like any new member. The app opens the fortress again with the new
// secret and the old one as Config.Previous; the old phrase opens nothing
// from then on.
func (f *Fortress) ChangePhrase(ctx context.Context) ([]string, error) {
	if f.keeper == nil {
		return nil, errors.New("fortress: no keeper for a new phrase")
	}
	secret, _, err := phrase.New()
	if err != nil {
		return nil, err
	}
	if err := f.keeper.Keep(secret); err != nil {
		return nil, err
	}
	var ids []string
	for _, m := range f.group.Members() {
		if m.Kind == member.KindInstance && m.Online() {
			ids = append(ids, m.ID)
		}
	}
	return hand(ctx, f.group, ids, phrasePath, secret), nil
}
