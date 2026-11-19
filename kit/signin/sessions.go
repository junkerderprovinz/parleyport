package signin

import (
	"encoding/json"
	"net/http"
	"slices"
	"time"
)

type sessionView struct {
	ID      string    `json:"id"`
	Via     Via       `json:"via"`
	Service string    `json:"service,omitempty"`
	Created time.Time `json:"created"`
	Seen    time.Time `json:"seen"`
	From    string    `json:"from,omitempty"`
	Agent   string    `json:"agent,omitempty"`
	Current bool      `json:"current"`
}

func (a *Auth) mySessions(r *http.Request, f *found) (map[string]*session, []string, error) {
	all, ids, err := listOf[session](r.Context(), a, kindSession)
	if err != nil {
		return nil, nil, err
	}
	now := a.now()
	mine := ids[:0]
	for _, id := range ids {
		s := all[id]
		if s.Account == f.v.Account && s.Epoch == f.v.epoch && now.Before(s.Expires) {
			mine = append(mine, id)
		}
	}
	return all, mine, nil
}

func (a *Auth) getSessions(w http.ResponseWriter, r *http.Request, f *found) {
	all, ids, err := a.mySessions(r, f)
	if err != nil {
		a.internal(w, err)
		return
	}
	out := []sessionView{}
	for _, id := range ids {
		s := all[id]
		out = append(out, sessionView{ID: id, Via: s.Via, Service: s.Service, Created: s.Created, Seen: s.Seen, From: s.From, Agent: s.Agent, Current: id == f.v.session})
	}
	slices.SortFunc(out, func(x, y sessionView) int { return y.Seen.Compare(x.Seen) })
	ok(w, map[string]any{"sessions": out})
}

func (a *Auth) deleteSession(w http.ResponseWriter, r *http.Request, f *found) {
	id := r.PathValue("id")
	a.mu.Lock()
	s := new(session)
	err := a.load(r.Context(), kindSession, id, s)
	if err != nil || s.Account != f.v.Account {
		a.mu.Unlock()
		fail(w, http.StatusNotFound, "notFound")
		return
	}
	err = a.cfg.Store.Apply(r.Context(), gone(kindSession, id))
	a.mu.Unlock()
	if err != nil {
		a.internal(w, err)
		return
	}
	if id == f.v.session {
		a.clearCookie(w, r, "session", "/")
	}
	ok(w, nil)
}

// deleteSessions ends every other session of the account, and with them
// the ways in the app keeps for it.
func (a *Auth) deleteSessions(w http.ResponseWriter, r *http.Request, f *found) {
	ctx := r.Context()
	a.mu.Lock()
	docs, err := a.wipe(ctx, kindSession, func(b []byte) bool {
		var s session
		return json.Unmarshal(b, &s) == nil && s.Account == f.v.Account
	})
	if err == nil {
		docs = slices.DeleteFunc(docs, func(d Doc) bool { return d.ID == f.v.session })
		docs = append(docs, a.ending(f.v.Account, EndEverywhere))
		err = a.cfg.Store.Apply(ctx, docs...)
	}
	a.mu.Unlock()
	if err != nil {
		a.internal(w, err)
		return
	}
	a.runEndings(ctx)
	ok(w, map[string]int{"ended": len(docs) - 1})
}

// endAll returns deletes for every session and token of account. The caller
// holds mu.
func (a *Auth) endAll(r *http.Request, account string) ([]Doc, error) {
	belongs := owned(account)
	docs, err := a.wipe(r.Context(), kindSession, belongs)
	if err != nil {
		return nil, err
	}
	more, err := a.wipe(r.Context(), kindToken, belongs)
	return append(docs, more...), err
}

// owned matches the documents that belong to account.
func owned(account string) func([]byte) bool {
	return func(b []byte) bool {
		var v struct{ Account string }
		return json.Unmarshal(b, &v) == nil && v.Account == account
	}
}
