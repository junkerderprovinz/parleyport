package signin

import (
	"context"
	"net/http"
	"time"
)

type identityView struct {
	ID      string    `json:"id"`
	Kind    string    `json:"kind"`
	Service string    `json:"service,omitempty"`
	Name    string    `json:"name,omitempty"`
	Linked  time.Time `json:"linked"`
	Seen    time.Time `json:"seen,omitzero"`
}

func (a *Auth) getIdentities(w http.ResponseWriter, r *http.Request, f *found) {
	all, ids, err := listOf[identity](r.Context(), a, kindIdentity)
	if err != nil {
		a.internal(w, err)
		return
	}
	out := []identityView{}
	for _, id := range ids {
		if i := all[id]; i.Account == f.v.Account {
			out = append(out, identityView{ID: id, Kind: i.Kind, Service: i.Service, Name: i.Name, Linked: i.Linked, Seen: i.Seen})
		}
	}
	ok(w, map[string]any{"identities": out})
}

// deleteIdentity unlinks one way in from outside. An account without a
// password keeps its last one, or nobody could sign in as it any more.
func (a *Auth) deleteIdentity(w http.ResponseWriter, r *http.Request, f *found) {
	ctx := r.Context()
	a.mu.Lock()
	err := a.unlink(ctx, f.v.Account, r.PathValue("id"))
	a.mu.Unlock()
	if err != nil {
		a.answer(w, r, f, err)
		return
	}
	a.runEndings(ctx)
	ok(w, nil)
}

// unlink removes the binding id of account. The caller holds mu.
func (a *Auth) unlink(ctx context.Context, account, id string) error {
	idn := new(identity)
	if err := a.load(ctx, kindIdentity, id, idn); err != nil || idn.Account != account {
		return refuse(http.StatusNotFound, "notFound")
	}
	acc, err := a.account(ctx, account)
	if err != nil {
		return err
	}
	if !acc.hasPassword() {
		mine, err := a.wipe(ctx, kindIdentity, owned(acc.ID))
		if err != nil {
			return err
		}
		if len(mine) <= 1 {
			return refuse(http.StatusConflict, "lastWayIn")
		}
	}
	docs, err := a.wayGone(ctx, acc.ID)
	if err != nil {
		return err
	}
	return a.cfg.Store.Apply(ctx, append(docs, gone(kindIdentity, id))...)
}

func (a *Auth) postIdentityLink(w http.ResponseWriter, r *http.Request, f *found) {
	a.postServiceTicket(w, r, f, forLink, r.PathValue("service"))
}
