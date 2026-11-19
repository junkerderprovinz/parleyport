package signin

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// rule is one throttle. A window rule allows max failures per window and
// then waits for the window to end. A backoff rule lets the first max
// failures through and then waits twice as long after each one, up to a
// minute, so strangers cannot lock the owner out by name.
type rule struct {
	window  time.Duration
	max     int
	backoff bool
}

var (
	perAddress = rule{window: 15 * time.Minute, max: 10}
	perName    = rule{window: time.Hour, max: 5, backoff: true}
	perCode    = rule{window: 15 * time.Minute, max: 5}
	perReset   = rule{window: 10 * time.Minute, max: 5}
)

const maxBuckets = 50_000

type bucket struct {
	n     int
	start time.Time
	last  time.Time
}

type limits struct {
	mu sync.Mutex
	m  map[string]*bucket
}

func newLimits() *limits { return &limits{m: map[string]*bucket{}} }

// wait returns how long key has to wait under r, zero when it may try.
func (l *limits) wait(r rule, key string, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.m[key]
	if b == nil || now.Sub(b.start) > r.window {
		return 0
	}
	if !r.backoff {
		if b.n < r.max {
			return 0
		}
		return b.start.Add(r.window).Sub(now)
	}
	if b.n < r.max {
		return 0
	}
	d := min(time.Minute, time.Second<<min(b.n-r.max, 6))
	return max(0, b.last.Add(d).Sub(now))
}

// fail counts one failure of key under r.
func (l *limits) fail(r rule, key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.m[key]
	if b == nil || now.Sub(b.start) > r.window {
		if len(l.m) >= maxBuckets {
			l.prune(now)
		}
		b = &bucket{start: now}
		l.m[key] = b
	}
	b.n++
	b.last = now
}

func (l *limits) clear(key string) {
	l.mu.Lock()
	delete(l.m, key)
	l.mu.Unlock()
}

// prune drops buckets older than the longest window, and when that frees
// nothing, an arbitrary tenth.
func (l *limits) prune(now time.Time) {
	for k, b := range l.m {
		if now.Sub(b.start) > time.Hour {
			delete(l.m, k)
		}
	}
	n := len(l.m) / 10
	for k := range l.m {
		if len(l.m) < maxBuckets || n == 0 {
			return
		}
		delete(l.m, k)
		n--
	}
}

func peer(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return ip.Unmap()
}

func (a *Auth) trusted(ip netip.Addr) bool {
	for _, p := range a.cfg.Proxies {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// client is the address a request comes from: the peer, or behind proxies
// from Config.Proxies the last address in X-Forwarded-For that is not one of
// them. A header from any other peer never counts.
func (a *Auth) client(r *http.Request) netip.Addr {
	ip := peer(r)
	if !ip.IsValid() || !a.trusted(ip) {
		return ip
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return ip
		}
		hop = hop.Unmap()
		if !a.trusted(hop) {
			return hop
		}
		ip = hop
	}
	return ip
}

// addressKey groups IPv6 by /64, the block one connection usually holds.
func addressKey(ip netip.Addr) string {
	if !ip.IsValid() {
		return "addr:none"
	}
	if ip.Is6() {
		p, _ := ip.Prefix(64)
		return "addr:" + p.String()
	}
	return "addr:" + ip.String()
}

// https reports whether the browser reached the app over https.
func (a *Auth) https(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return a.trusted(peer(r)) && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}
