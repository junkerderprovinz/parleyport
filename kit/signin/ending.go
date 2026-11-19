package signin

import (
	"context"
	"fmt"
	"time"
)

// endingDoc waits in the store until the app's Ended hook took it, so a hook
// that fails or a restart in between never leaves the app's own ways in
// open.
type endingDoc struct {
	Account string    `json:"account"`
	What    Ending    `json:"what"`
	At      time.Time `json:"at"`
}

// ending is the document for one call of Hooks.Ended, to apply together with
// the change that calls for it.
func (a *Auth) ending(account string, what Ending) Doc {
	a.logs.mu.Lock()
	a.logs.seq++
	n := a.logs.seq
	a.logs.mu.Unlock()
	id := fmt.Sprintf("%019d-%06d", a.now().UnixNano(), n%1_000_000)
	return a.doc(kindEnding, id, endingDoc{Account: account, What: what, At: a.now()})
}

// runEndings hands every waiting ending to the app, oldest first.
func (a *Auth) runEndings(ctx context.Context) {
	a.endMu.Lock()
	defer a.endMu.Unlock()
	all, ids, err := listOf[endingDoc](ctx, a, kindEnding)
	if err != nil {
		a.log.Warn("signin: reading endings", "err", err)
		return
	}
	for _, id := range ids {
		e := all[id]
		if hook := a.cfg.Hooks.Ended; hook != nil {
			if err := hook(ctx, e.Account, e.What); err != nil {
				a.log.Warn("signin: the app did not end its ways in", "account", e.Account, "what", e.What, "err", err)
				return
			}
		}
		if err := a.cfg.Store.Apply(ctx, gone(kindEnding, id)); err != nil {
			a.log.Warn("signin: clearing an ending", "err", err)
			return
		}
	}
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

// afterEpoch runs what follows an epoch of acc: the app's endings, and
// once, the removal of the old fields the app imported acc from, so going
// back to the version before cannot bring an ended password back.
func (a *Auth) afterEpoch(ctx context.Context, acc *account) {
	a.runEndings(ctx)
	if !acc.Imported || a.cfg.Legacy.Drop == nil {
		return
	}
	if err := a.cfg.Legacy.Drop(ctx, acc.ID); err != nil {
		a.log.Warn("signin: dropping old sign-in fields", "account", acc.ID, "err", err)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if cur, err := a.account(ctx, acc.ID); err == nil {
		cur.Imported = false
		if err := a.cfg.Store.Apply(ctx, a.doc(kindAccount, cur.ID, cur)); err != nil {
			a.log.Warn("signin: dropping old sign-in fields", "account", acc.ID, "err", err)
		}
	}
}
