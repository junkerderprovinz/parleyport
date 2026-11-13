package fortress

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

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
// it first, then every instance in reach that holds the phrase and does not
// wait for approval gets it to keep, sealed for that instance alone, with the
// removals this one knows, and the ids of those that did come back. A member
// taken out does not get it. One that is away gets it to keep from the first
// member it meets that took it, within 30 days of the change, if it holds the
// old phrase and has a Keeper; otherwise it is out until the new phrase is
// entered there, and then in again as the member it was. A member that holds
// only keys follows with NewKeys instead. The app opens the fortress again
// with the new secret and the old one as Config.Previous; the old phrase lets
// nobody new in from then on.
func (f *Fortress) ChangePhrase(ctx context.Context) ([]string, error) {
	if f.keeper == nil || len(f.secret) == 0 {
		return nil, errors.New("fortress: a new phrase needs a keeper and the phrase itself")
	}
	secret, _, err := phrase.New()
	if err != nil {
		return nil, err
	}
	changed := time.Now().Round(0)
	if err := f.moveBook(&handed{Changed: changed}); err != nil {
		return nil, err
	}
	if err := f.keeper.Keep(secret); err != nil {
		_ = f.moveBook(nil)
		return nil, err
	}
	p := f.handing(secret, changed)
	var (
		mu   sync.Mutex
		took []string
		wg   sync.WaitGroup
	)
	f.mu.Lock()
	since := f.book.Changed
	f.mu.Unlock()
	removed := f.removedSince(since)
	for _, m := range f.group.Members() {
		if m.Kind != member.KindInstance || m.State == group.StatePending || !m.Online() {
			continue
		}
		if !f.heardBefore(m.ID, removed) {
			continue
		}
		wg.Go(func() {
			if f.handPhrase(ctx, m.ID, p) == nil {
				mu.Lock()
				took = append(took, m.ID)
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	sort.Strings(took)
	return took, nil
}

// handPhrase hands member id p to take: it asks id for a one-off key and
// sends p sealed for it.
func (f *Fortress) handPhrase(ctx context.Context, id string, p newPhrase) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	status, raw, err := f.group.Call(ctx, id, http.MethodPost, phraseKeyPath, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return refusal(status, raw)
	}
	var key newPhraseAsk
	if err := json.Unmarshal(raw, &key); err != nil {
		return err
	}
	answer, err := sealNewPhrase(key.Key, p, f.secret, f.self, id)
	if err != nil {
		return err
	}
	body, err := json.Marshal(answer)
	if err != nil {
		return err
	}
	status, raw, err = f.group.Call(ctx, id, http.MethodPost, phrasePath, body)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent {
		return refusal(status, raw)
	}
	return nil
}
