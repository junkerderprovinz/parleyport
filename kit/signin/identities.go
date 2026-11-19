package signin

import (
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
	id := r.PathValue("id")
	a.mu.Lock()
	defer a.mu.Unlock()
	idn := new(identity)
	if err := a.load(ctx, kindIdentity, id, idn); err != nil || idn.Account != f.v.Account {
		fail(w, http.StatusNotFound, "notFound")
		return
	}
	acc, err := a.account(ctx, f.v.Account)
	if err != nil {
		a.internal(w, err)
		return
	}
	if !acc.hasPassword() {
		mine, err := a.wipe(ctx, kindIdentity, owned(acc.ID))
		if err != nil {
			a.internal(w, err)
			return
		}
		if len(mine) <= 1 {
			fail(w, http.StatusConflict, "lastWayIn")
			return
		}
	}
	if err := a.cfg.Store.Apply(ctx, gone(kindIdentity, id)); err != nil {
		a.internal(w, err)
		return
	}
	ok(w, nil)
}

func (a *Auth) postIdentityLink(w http.ResponseWriter, r *http.Request, f *found) {
	a.postServiceTicket(w, r, f, forLink, r.PathValue("service"))
}
