package group

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/relay"
)

const (
	// addrTTL is how long an address that answered keeps counting as direct.
	// It is close to how long a silent announce lingers, so both ways to be
	// "on this network" age out on a similar clock.
	addrTTL = 5 * time.Minute
	// directRetry is how long a call leaves a direct address alone after it
	// failed there, as long as the relay reaches the member instead. Without
	// it every call to a member behind a dead address would wait out the dial
	// before the relay got its turn. The refresh keeps probing the address and
	// puts it back to use as soon as it answers.
	directRetry = addrTTL
	// awaitWindow is how long an answer saying "waits for approval" stands.
	awaitWindow = 2 * time.Minute
)

// remoteAddr is a member's direct address as far as this instance knows it:
// confirmed when the member answered there, only noted when the member named
// it, which is no proof it works.
type remoteAddr struct {
	url        string
	name       string
	deployment string
	confirmed  time.Time
	noted      time.Time
}

// Call asks member id and returns its answer: the status and body its app
// gave, once the key id is made from signed it.
//
// A member on this network is asked directly first, then at an address a
// sweep or the member itself named, then over the relay. The routes are
// tried one after another rather than raced, since a call can change
// something and must not arrive twice. An error means no answer came, or
// that the answer came from a member not approved here: then it is a
// *relay.UntrustedAnswer, which the caller may read only for what cannot
// hurt it, such as that this instance waits for approval there.
func (g *Group) Call(ctx context.Context, id, method, path string, body []byte) (int, []byte, error) {
	if len(body) > MaxCallBytes {
		return 0, nil, ErrTooLarge
	}
	urls, relayed := g.routesTo(id)
	if len(urls) == 0 && !relayed {
		return 0, nil, ErrUnreachable
	}
	call := relay.ProxyCall{Method: method, Path: path, Body: body}
	dctx, cancel := directContext(ctx, relayed)
	defer cancel()
	var directErr error
	for _, u := range urls {
		if relayed && g.down(u, time.Now()) {
			continue
		}
		res, err := g.callDirect(dctx, u, id, call)
		if err != nil {
			g.directFailed(ctx, u)
			directErr = err
			continue
		}
		g.confirm(id, u, "", "", time.Now())
		if !g.trustsAnswer(id, res.Key) {
			err = &relay.UntrustedAnswer{Target: id, Status: res.Status, Body: res.Body}
		} else {
			g.noteRemoval(path, res.Status, res.Body)
		}
		g.noteAnswer(id, res.Status, res.Body, time.Now())
		return res.Status, res.Body, err
	}
	if !relayed {
		return 0, nil, directErr
	}
	out, status, err := g.client.Proxy(ctx, id, method, path, body)
	var untrusted *relay.UntrustedAnswer
	switch {
	case err == nil:
		g.noteRemoval(path, status, out)
		g.noteAnswer(id, status, out, time.Now())
	case errors.As(err, &untrusted):
		g.noteAnswer(id, untrusted.Status, untrusted.Body, time.Now())
	}
	return status, out, err
}

// routesTo is every direct address of id, the announced one first, and
// whether the relay reaches it.
func (g *Group) routesTo(id string) ([]string, bool) {
	var urls []string
	if g.lan != nil {
		for _, p := range g.lan.Members() {
			if p.ID == id {
				urls = append(urls, p.URL)
			}
		}
	}
	relayed := false
	if g.client != nil {
		for _, s := range g.client.Siblings() {
			if s.InstanceID == id && !s.Client {
				relayed = true
			}
		}
	}
	g.mu.Lock()
	if a := g.addrs[id]; a != nil && a.url != "" && (len(urls) == 0 || urls[0] != a.url) {
		urls = append(urls, a.url)
	}
	g.mu.Unlock()
	return urls, relayed
}

// directContext bounds the direct attempts of one call. A member on the relay
// as well keeps half of the call's time for the relay, so an address that
// accepts and never answers cannot use up the fallback.
func directContext(ctx context.Context, relayed bool) (context.Context, context.CancelFunc) {
	budget := callTimeout
	if deadline, ok := ctx.Deadline(); ok {
		budget = min(budget, time.Until(deadline))
	}
	if relayed {
		budget /= 2
	}
	return context.WithTimeout(ctx, budget)
}

// noteAnswer records whether member id said that this instance waits for its
// approval there, and whether it served a call from this one at all.
func (g *Group) noteAnswer(id string, status int, body []byte, now time.Time) {
	defer g.stir()
	g.mu.Lock()
	defer g.mu.Unlock()
	if status == http.StatusForbidden && bytes.Contains(body, []byte(`"memberPending"`)) {
		g.awaiting[id] = now
	} else {
		delete(g.awaiting, id)
	}
	if status >= 200 && status < 300 {
		g.heard[id] = true
	}
	if status == http.StatusForbidden && bytes.Contains(body, []byte(`"`+ClosedUntilNewPhrase+`"`)) {
		g.shutOut = now
	}
	if status == http.StatusForbidden && (bytes.Contains(body, []byte(`"groupClosed"`)) || bytes.Contains(body, []byte(`"`+ClosedUntilNewPhrase+`"`))) {
		g.strangerTo[id] = true
		if _, ok := g.st.Members[id]; ok {
			delete(g.st.Members, id)
			g.dirty = true
		}
	}
}

// noteRemoval takes an approved instance's word that this one was removed
// while it was away, when the decision itself never reached it. Only the
// group's own routes count, since an app's answer may say anything.
func (g *Group) noteRemoval(path string, status int, body []byte) {
	if status == http.StatusGone && strings.HasPrefix(path, internalPrefix) && bytes.Equal(body, removedRefusal.body) {
		g.heardRemoved()
	}
}

// noteAddress records url as where id might take direct calls, without taking
// it as reachable yet.
func (g *Group) noteAddress(id, url string) {
	url = strings.TrimSpace(url)
	if id == g.self || url == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	a := g.addrs[id]
	if a == nil {
		a = &remoteAddr{}
		g.addrs[id] = a
	}
	if a.url != url {
		a.url, a.confirmed = url, time.Time{}
	}
	a.noted = time.Now()
}

// confirm records that id answered a direct call at url at now. An empty name
// or deployment leaves what is known.
func (g *Group) confirm(id, url, name, deployment string, now time.Time) {
	if id == g.self {
		return
	}
	// Only an address the group would dial when it is named is kept for the
	// next start, which dials it unasked.
	_, keep := g.nearby(url)
	defer g.stir()
	g.mu.Lock()
	defer g.mu.Unlock()
	a := g.addrs[id]
	if a == nil {
		a = &remoteAddr{}
		g.addrs[id] = a
	}
	a.url = url
	if name != "" {
		a.name = relay.ClipName(name)
	}
	if deployment != "" {
		a.deployment = relay.ClipName(deployment)
	}
	a.confirmed, a.noted = now, now
	delete(g.failed, url)
	if rec, ok := g.st.Members[id]; ok && keep && rec.Direct != url {
		rec.Direct = url
		g.st.Members[id] = rec
		g.dirty = true
	}
}

// directFailed records that a call to url got no answer. A call whose caller
// gave up says nothing about the address.
func (g *Group) directFailed(ctx context.Context, url string) {
	if ctx.Err() != nil {
		return
	}
	defer g.stir()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.failed[url] = time.Now()
}

func (g *Group) down(url string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.downLocked(url, now)
}

func (g *Group) downLocked(url string, now time.Time) bool {
	at, ok := g.failed[url]
	return ok && now.Sub(at) < directRetry
}

func (g *Group) confirmedLocked(a *remoteAddr, now time.Time) bool {
	return !a.confirmed.IsZero() && now.Sub(a.confirmed) < addrTTL && !g.downLocked(a.url, now)
}

func (g *Group) confirmedDirect(id string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	a := g.addrs[id]
	return a != nil && g.confirmedLocked(a, now)
}
