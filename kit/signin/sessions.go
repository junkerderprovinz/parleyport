package signin

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"time"
)

// Session is a session as the contract lists it.
type Session struct {
	ID      string    `json:"id"`
	Via     Via       `json:"via"`
	Service string    `json:"service,omitempty"`
	Created time.Time `json:"created"`
	Seen    time.Time `json:"seen"`
	From    string    `json:"from,omitempty"`
	Agent   string    `json:"agent,omitempty"`
	Current bool      `json:"current"`
}

// sessionsOf lists the sessions of account in epoch that have not run out,
// the last used first, marking current.
func (a *Auth) sessionsOf(r *http.Request, account string, epoch int, current string) ([]Session, error) {
	all, ids, err := listOf[session](r.Context(), a, kindSession)
	if err != nil {
		return nil, err
	}
	now := a.now()
	out := []Session{}
	for _, id := range ids {
		if s := all[id]; s.Account == account && s.Epoch == epoch && now.Before(s.Expires) {
			out = append(out, Session{ID: id, Via: s.Via, Service: s.Service, Created: s.Created, Seen: s.Seen, From: s.From, Agent: s.Agent, Current: id == current})
		}
	}
	slices.SortFunc(out, func(x, y Session) int { return y.Seen.Compare(x.Seen) })
	return out, nil
}

func (a *Auth) getSessions(w http.ResponseWriter, r *http.Request, f *found) {
	out, err := a.sessionsOf(r, f.v.Account, f.v.epoch, f.v.session)
	if err != nil {
		a.internal(w, err)
		return
	}
	ok(w, map[string]any{"sessions": out})
}

func (a *Auth) deleteSession(w http.ResponseWriter, r *http.Request, f *found) {
	id := r.PathValue("id")
	a.mu.Lock()
	err := a.endOwnSession(r.Context(), f.v.Account, id)
	a.mu.Unlock()
	if err != nil {
		a.answer(w, r, f, err)
		return
	}
	if id == f.v.session {
		a.clearCookie(w, r, "session", "/")
	}
	ok(w, nil)
}

// endOwnSession ends the session id of account. The caller holds mu.
func (a *Auth) endOwnSession(ctx context.Context, account, id string) error {
	s := new(session)
	if err := a.load(ctx, kindSession, id, s); err != nil || s.Account != account {
		return refuse(http.StatusNotFound, "notFound")
	}
	return a.cfg.Store.Apply(ctx, gone(kindSession, id))
}

// deleteSessions ends every other session of the account, old ones it was
// imported with included, and the ways in the app keeps for it. This
// browser gets a new session in the next epoch.
func (a *Auth) deleteSessions(w http.ResponseWriter, r *http.Request, f *found) {
	ctx := r.Context()
	a.mu.Lock()
	acc, err := a.stillValid(ctx, f)
	if err != nil {
		a.mu.Unlock()
		fail(w, http.StatusUnauthorized, "signInFirst")
		return
	}
	docs, err := a.wipe(ctx, kindSession, owned(acc.ID))
	ended := max(0, len(docs)-1)
	if err == nil {
		acc.Epoch++
		docs = append(docs, a.endingsOf(acc, EndEverywhere)...)
		docs = append(docs, a.doc(kindAccount, acc.ID, acc))
		docs = append(docs, a.newSession(w, r, f, a.reissue(r, f, acc))...)
		err = a.cfg.Store.Apply(ctx, docs...)
	}
	a.mu.Unlock()
	if err != nil {
		a.internal(w, err)
		return
	}
	a.runEndings(ctx)
	ok(w, map[string]int{"ended": ended})
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
