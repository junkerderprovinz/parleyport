package signin

import (
	"context"
	"fmt"
	"time"
)

// endingDoc waits in the store until the app took it, so a hook that fails
// or a restart in between never leaves the app's own ways in open. Drop
// marks one for Legacy.Drop rather than Hooks.Ended.
type endingDoc struct {
	Account string    `json:"account"`
	What    Ending    `json:"what"`
	Drop    bool      `json:"drop,omitempty"`
	At      time.Time `json:"at"`
}

// ending is the document for one call of Hooks.Ended or Legacy.Drop, to
// apply together with the change that calls for it.
func (a *Auth) ending(account string, what Ending, drop bool) Doc {
	a.logs.mu.Lock()
	a.logs.seq++
	n := a.logs.seq
	a.logs.mu.Unlock()
	id := fmt.Sprintf("%019d-%06d", a.now().UnixNano(), n%1_000_000)
	return a.doc(kindEnding, id, endingDoc{Account: account, What: what, Drop: drop, At: a.now()})
}

// endingsOf is what the app hears when the package ended ways in of acc:
// Hooks.Ended, and Legacy.Drop while the app still keeps acc's old fields.
// It clears acc.Imported once nothing old is left, so the caller writes acc
// in the same Apply, after this call, and holds mu.
func (a *Auth) endingsOf(acc *account, what Ending) []Doc {
	var docs []Doc
	if what != EndWay {
		docs = append(docs, a.ending(acc.ID, what, false))
	}
	if acc.Imported && a.cfg.Legacy.Drop != nil {
		docs = append(docs, a.ending(acc.ID, what, true))
		if what != EndResetOther {
			acc.Imported = false
		}
	}
	return docs
}

// wayGone is what the app hears when account loses one way in on its own,
// a token, a passkey or a binding: while the app still keeps the account's
// old fields, Legacy.Drop. The caller holds mu and applies the docs.
func (a *Auth) wayGone(ctx context.Context, account string) ([]Doc, error) {
	acc, err := a.account(ctx, account)
	if err != nil {
		return nil, err
	}
	if !acc.Imported || a.cfg.Legacy.Drop == nil {
		return nil, nil
	}
	return append(a.endingsOf(acc, EndWay), a.doc(kindAccount, acc.ID, acc)), nil
}

// runEndings hands every waiting ending to the app, oldest first per
// account. One the app cannot take yet holds back only the later ones of
// the same account. They run apart from the request that caused them, so
// a browser that goes away cannot cut them short.
func (a *Auth) runEndings(ctx context.Context) {
	ctx = context.WithoutCancel(ctx)
	a.endMu.Lock()
	defer a.endMu.Unlock()
	all, ids, err := listOf[endingDoc](ctx, a, kindEnding)
	if err != nil {
		a.log.Warn("signin: reading endings", "err", err)
		return
	}
	stuck := map[string]bool{}
	for _, id := range ids {
		e := all[id]
		if stuck[e.Account] {
			continue
		}
		if err := a.endOne(ctx, e); err != nil {
			stuck[e.Account] = true
			a.endFailed(id, e, err)
			continue
		}
		docs := []Doc{gone(kindEnding, id)}
		if e.What == EndRemoved && !e.Drop {
			docs = append(docs, gone(kindRemoved, e.Account))
		}
		if err := a.cfg.Store.Apply(ctx, docs...); err != nil {
			a.log.Warn("signin: clearing an ending", "err", err)
			return
		}
		delete(a.endFails, id)
	}
}

func (a *Auth) endOne(ctx context.Context, e *endingDoc) error {
	if e.Drop {
		if a.cfg.Legacy.Drop == nil {
			return nil
		}
		return a.cfg.Legacy.Drop(ctx, e.Account, e.What)
	}
	if a.cfg.Hooks.Ended == nil {
		return nil
	}
	return a.cfg.Hooks.Ended(ctx, e.Account, e.What)
}

// endFailed logs an ending the app did not take: at once, and when it is
// still waiting, once an hour. The caller holds endMu.
func (a *Auth) endFailed(id string, e *endingDoc, err error) {
	now := a.now()
	last, seen := a.endFails[id]
	switch {
	case !seen:
		a.log.Warn("signin: the app did not end its ways in", "account", e.Account, "what", e.What, "drop", e.Drop, "err", err)
	case now.Sub(last) >= time.Hour:
		a.log.Error("signin: the app has not ended its ways in for an hour", "account", e.Account, "what", e.What, "drop", e.Drop, "since", e.At, "err", err)
	default:
		return
	}
	a.endFails[id] = now
}

func (a *Auth) endLoop() {
	ctx := context.Background()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-a.stop:
			return
		case <-t.C:
			a.runEndings(ctx)
		}
	}
}
