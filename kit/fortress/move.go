package fortress

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
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
	body, err := json.Marshal(moveBody{Secret: secret})
	if err != nil {
		return nil
	}
	var (
		mu    sync.Mutex
		moved []string
		wg    sync.WaitGroup
	)
	for _, m := range old.Members() {
		if m.Kind != member.KindInstance || m.State != group.StateApproved || !m.Online() {
			continue
		}
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(ctx, callTimeout)
			defer cancel()
			if status, _, err := old.Call(ctx, m.ID, http.MethodPost, movePath, body); err == nil && status == http.StatusNoContent {
				mu.Lock()
				moved = append(moved, m.ID)
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	return moved
}

// Moving serves next to the app's own pairing while the instance is in no
// fortress, and takes the fortress secret an approved sibling hands over with
// Move. accept keeps the secret; the app then opens its Fortress with the
// pairing's secret as Pairing.Previous. accept runs inside the call, so it
// must not close the pairing itself.
func Moving(next http.Handler, accept func(secret []byte) error) http.Handler {
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
		var b moveBody
		raw, err := io.ReadAll(r.Body)
		if err != nil || json.Unmarshal(raw, &b) != nil || len(b.Secret) != phrase.SecretLen {
			writeError(w, http.StatusBadRequest, "bad_request")
			return
		}
		if err := accept(b.Secret); err != nil {
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
