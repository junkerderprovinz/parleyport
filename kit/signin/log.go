package signin

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"
)

const (
	logKeep   = 1000
	logAge    = 90 * 24 * time.Hour
	logMerge  = time.Minute
	pruneEach = 50
)

// Entry is one line of the sign-in log. Name is an account's name, or for a
// name that belongs to no account a tag, because people often type their
// password there. Result is a code such as ok, wrongPassword, noGroup or
// newAccount. Count is how many of the same failure from the same address
// within a minute the entry stands for.
type Entry struct {
	At      time.Time `json:"at"`
	Account string    `json:"account,omitempty"`
	Name    string    `json:"name,omitempty"`
	Via     Via       `json:"via,omitempty"`
	Service string    `json:"service,omitempty"`
	From    string    `json:"from,omitempty"`
	Result  string    `json:"result"`
	Agent   string    `json:"agent,omitempty"`
	Count   int       `json:"count,omitempty"`
}

type logMark struct {
	id      string
	e       Entry
	written time.Time
}

type logState struct {
	mu     sync.Mutex
	last   map[string]logMark
	seq    uint64
	writes int
}

// note writes e to the log with the time, address and browser of r. A
// failure that repeats one from the same address within a minute adds to
// that entry instead of writing one more.
func (a *Auth) note(ctx context.Context, r *http.Request, e Entry) {
	e.At = a.now()
	if r != nil {
		e.From, e.Agent = a.client(r).String(), cut(r.UserAgent(), 200)
	}
	e.Count = 1
	l := &a.logs
	l.mu.Lock()
	key := e.From + "\x00" + e.Account + "\x00" + e.Name + "\x00" + e.Result
	id, write := "", true
	m, seen := l.last[key]
	if seen && e.Result != "ok" && e.At.Sub(m.e.At) < logMerge {
		id = m.id
		m.e.Count++
		m.e.At = e.At
		e = m.e
		// A flood of the same failure counts up in memory and reaches the
		// store about once a minute, not once a request.
		write = e.Count < 10 || e.At.Sub(m.written) >= logMerge
	} else {
		l.seq++
		id = fmt.Sprintf("%019d-%06d", e.At.UnixNano(), l.seq%1_000_000)
	}
	if len(l.last) > 1000 {
		clear(l.last)
	}
	mark := logMark{id: id, e: e, written: m.written}
	if write {
		mark.written = e.At
		l.writes++
	}
	l.last[key] = mark
	prune := write && l.writes%pruneEach == 0
	l.mu.Unlock()

	if write {
		if err := a.cfg.Store.Apply(ctx, a.doc(kindLog, id, e)); err != nil {
			a.log.Warn("signin: writing the sign-in log", "err", err)
		}
	}
	if prune {
		a.pruneLog(ctx)
	}
	if a.cfg.Hooks.Logged != nil {
		a.cfg.Hooks.Logged(ctx, e)
	}
}

func (a *Auth) pruneLog(ctx context.Context) {
	all, ids, err := listOf[Entry](ctx, a, kindLog)
	if err != nil {
		return
	}
	cutoff := a.now().Add(-logAge)
	var drop []Doc
	for i, id := range ids {
		if len(ids)-i > logKeep || all[id].At.Before(cutoff) {
			drop = append(drop, gone(kindLog, id))
		}
	}
	if len(drop) > 0 {
		if err := a.cfg.Store.Apply(ctx, drop...); err != nil {
			a.log.Warn("signin: pruning the sign-in log", "err", err)
		}
	}
}

func (a *Auth) getLog(w http.ResponseWriter, r *http.Request, _ *found) {
	limit := 100
	if s := r.URL.Query().Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			fail(w, http.StatusBadRequest, "badRequest")
			return
		}
		limit = min(n, logKeep)
	}
	all, ids, err := listOf[Entry](r.Context(), a, kindLog)
	if err != nil {
		a.internal(w, err)
		return
	}
	slices.Reverse(ids)
	out := []Entry{}
	for _, id := range ids[:min(limit, len(ids))] {
		out = append(out, *all[id])
	}
	ok(w, map[string]any{"entries": out})
}
