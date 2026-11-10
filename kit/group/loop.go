package group

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/member"
)

const (
	// tickEvery is how often a group looks after its members unasked.
	tickEvery = 30 * time.Second
	// greetEvery is how often an instance that has not served a call from
	// this one yet is greeted. The greeting pins this instance's key there,
	// so two instances that meet list each other as waiting for approval.
	greetEvery = tickEvery
	// rosterEvery is how often an approved instance is asked for its roster.
	rosterEvery = 10 * time.Minute
	// The sweep's bounds: sweepConcurrency probes at once, each for at most
	// sweepTimeout, the whole sweep within sweepBudget and no more often than
	// sweepMinInterval.
	sweepConcurrency = 32
	sweepTimeout     = 1500 * time.Millisecond
	sweepBudget      = 45 * time.Second
	sweepMinInterval = 3 * time.Minute
)

// run looks after the members until Close: on every tick, and whenever the
// relay says somebody came or went.
func (g *Group) run() {
	t := time.NewTicker(tickEvery)
	defer t.Stop()
	for {
		g.tick(time.Now())
		select {
		case <-g.ctx.Done():
			return
		case <-t.C:
		case <-g.kick:
		}
	}
}

func (g *Group) tick(now time.Time) {
	g.greet(g.ctx, now)
	g.refresh(g.ctx, now)
	g.syncRosters(g.ctx, now)
	g.maybeSweep(now)
	g.mu.Lock()
	if g.dirty {
		_ = g.saveLocked()
	}
	for id, at := range g.arrived {
		if now.Sub(at) >= addrTTL {
			delete(g.arrived, id)
		}
	}
	g.mu.Unlock()
	// A member on the network ages out of its list without a word.
	g.stir()
}

// greet calls every instance in reach that has not served a call from this
// one yet. It learns where an instance that serves this one takes direct
// calls.
func (g *Group) greet(ctx context.Context, now time.Time) {
	var due []string
	view := g.look(now)
	g.mu.Lock()
	for id, m := range view {
		if m.Kind != member.KindInstance || !m.Online() || g.heard[id] || now.Sub(g.greeted[id]) < greetEvery {
			continue
		}
		g.greeted[id] = now
		due = append(due, id)
	}
	g.mu.Unlock()
	var wg sync.WaitGroup
	for _, id := range due {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(ctx, callTimeout)
			defer cancel()
			status, body, err := g.Call(ctx, id, http.MethodGet, helloPath, nil)
			var h hello
			if err == nil && status == http.StatusOK && json.Unmarshal(body, &h) == nil && h.ID == id && !g.confirmedDirect(id, now) {
				g.noteAddress(id, h.URL)
			}
		})
	}
	wg.Wait()
}

// refresh probes every address on record that has not answered for a while,
// which keeps a member reached by address alone in the list and puts an
// address that failed back to use once it answers again.
func (g *Group) refresh(ctx context.Context, now time.Time) {
	var due []string
	g.mu.Lock()
	for _, a := range g.addrs {
		if a.url != "" && now.Sub(a.confirmed) >= addrTTL/2 {
			due = append(due, a.url)
		}
	}
	g.mu.Unlock()
	for _, url := range due {
		pctx, cancel := context.WithTimeout(ctx, sweepTimeout)
		if _, err := g.probe(pctx, url); err != nil {
			g.directFailed(pctx, url)
		}
		cancel()
	}
}

// syncRosters asks every approved instance in reach for its roster, at most
// once every rosterEvery, so one that was away when a device was approved or
// removed catches up.
func (g *Group) syncRosters(ctx context.Context, now time.Time) {
	for _, id := range g.instancesOnline("") {
		g.mu.Lock()
		due := now.Sub(g.synced[id]) >= rosterEvery
		if due {
			g.synced[id] = now
		}
		g.mu.Unlock()
		if !due {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, callTimeout)
		status, body, err := g.Call(cctx, id, http.MethodGet, rosterPath, nil)
		cancel()
		var r roster
		if err == nil && status == http.StatusOK && json.Unmarshal(body, &r) == nil {
			g.merge(r)
		}
	}
}

// maybeSweep starts a sweep of the network in the background when one is due:
// nobody was found by any route yet, or the relay reaches an instance with no
// direct route.
func (g *Group) maybeSweep(now time.Time) {
	if g.lan == nil {
		return
	}
	needed := true
	for _, m := range g.look(now) {
		if m.Direct {
			needed = false
		}
	}
	if !needed && g.client != nil {
		for _, s := range g.client.Siblings() {
			if !s.Client {
				if urls, _ := g.routesTo(s.InstanceID); len(urls) == 0 {
					needed = true
				}
			}
		}
	}
	g.mu.Lock()
	due := needed && now.Sub(g.swept) >= sweepMinInterval
	if due {
		g.swept = now
	}
	g.mu.Unlock()
	if !due || !g.enter() {
		return
	}
	go func() {
		defer g.wg.Done()
		ctx, cancel := context.WithTimeout(g.ctx, sweepBudget)
		defer cancel()
		g.sweepWith(ctx, g.lan.Neighbours(g.directURL()))
	}()
}

// sweepWith probes every candidate address, a bounded number at once.
func (g *Group) sweepWith(ctx context.Context, candidates []string) {
	sem := make(chan struct{}, sweepConcurrency)
	var wg sync.WaitGroup
	for _, addr := range candidates {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return
		}
		wg.Go(func() {
			defer func() { <-sem }()
			pctx, cancel := context.WithTimeout(ctx, sweepTimeout)
			defer cancel()
			_, _ = g.probe(pctx, addr)
		})
	}
	wg.Wait()
}
