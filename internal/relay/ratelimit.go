package relay

// Backoff for failed handshakes on a publicly operated relay. The group key,
// with 128 bits of entropy, is what keeps strangers out; this limits clients
// that fail the handshake over and over, each attempt costing a TCP
// connection, a TLS negotiation and a goroutine for up to helloTimeout, and
// burying real failures in the journal.
//
// It is keyed on the socket's remote address, never a forwarded-for header.
// The relay is dialled directly, so the peer is the client, and trusting a
// header would let a caller pick its own bucket.

import (
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	// failWindow is how long a failure stays on an address's record: long
	// enough that a script cannot pace itself under the threshold, short
	// enough that a fixed typo stops counting.
	failWindow = 10 * time.Minute

	// failsBeforeBlock is how many failures inside failWindow start a block.
	// A person mistyping a phrase fails once or twice, not ten times.
	failsBeforeBlock = 10

	// baseBlock is the first refusal window. It doubles with each further
	// failure during a block or within failWindow of its end, which is the
	// case a single caller hits, since a blocked address is refused before its
	// handshake can fail again. A persistent caller reaches maxBlock after six
	// blocks.
	//
	// maxBlock is 50 minutes so a record runs out within the 61 minutes the
	// privacy policy states: maxBlock + failWindow, plus sweepEvery.
	baseBlock = 1 * time.Minute
	maxBlock  = 50 * time.Minute

	// maxTrackedAddrs bounds the limiter's own memory. When full, the least
	// recently active record is dropped, so pushing an address out takes
	// enough other addresses failing recently.
	maxTrackedAddrs = 4096
)

type attempts struct {
	fails        int
	last         time.Time
	blockedUntil time.Time
	blockFor     time.Duration
}

// limiter tracks failed handshakes per remote address. now is a field so tests
// can drive the clock instead of sleeping through a backoff.
type limiter struct {
	mu        sync.Mutex
	addrs     map[string]*attempts
	now       func() time.Time
	lastSweep time.Time
}

// sweepEvery is how often the request path may walk the whole map to drop
// expired records, which keeps the walk off the hot path of a flood.
const sweepEvery = time.Minute

func newLimiter() *limiter {
	return &limiter{addrs: map[string]*attempts{}, now: time.Now}
}

// blocked reports whether addr is being refused. It is checked before the
// upgrade, so a refused address costs a rejected HTTP request, not a
// WebSocket.
func (l *limiter) blocked(addr string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.maybeSweepLocked(now)
	a := l.addrs[addr]
	return a != nil && now.Before(a.blockedUntil)
}

// sweep drops every record whose failures have aged out and whose block is
// over. A record runs out failWindow after the address was last active, so no
// later than maxBlock + failWindow (60 minutes) after its last failure, and
// the next sweep deletes it within 61 minutes: the figure the privacy policy
// states and ratelimit_test.go checks. The public relay also calls it on a
// timer, so a relay that goes quiet forgets as well.
func (l *limiter) sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(l.now())
}

func (l *limiter) maybeSweepLocked(now time.Time) {
	if now.Sub(l.lastSweep) < sweepEvery {
		return
	}
	l.sweepLocked(now)
}

func (l *limiter) sweepLocked(now time.Time) {
	l.lastSweep = now
	for k, a := range l.addrs {
		if now.Sub(lastActive(a)) > failWindow {
			delete(l.addrs, k)
		}
	}
}

// tracked is how many addresses have a record.
func (l *limiter) tracked() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.addrs)
}

// fail records one failed handshake and extends the block if the address
// has now earned one.
func (l *limiter) fail(addr string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.maybeSweepLocked(now)

	a := l.addrs[addr]
	if a == nil {
		l.evictIfFullLocked()
		a = &attempts{}
		l.addrs[addr] = a
	}
	// Failures older than the window no longer count. The gap is measured
	// from the end of a block, since a long block outlasts failWindow and
	// measuring from the failure would reset the backoff for any caller that
	// waited the block out.
	if !a.last.IsZero() && now.Sub(lastActive(a)) > failWindow {
		a.fails = 0
		a.blockFor = 0
	}
	a.fails++
	a.last = now

	if a.fails < failsBeforeBlock {
		return
	}
	if a.blockFor == 0 {
		a.blockFor = baseBlock
	} else if a.blockFor < maxBlock {
		a.blockFor *= 2
		if a.blockFor > maxBlock {
			a.blockFor = maxBlock
		}
	}
	a.blockedUntil = now.Add(a.blockFor)
}

// succeed clears an address's record: a working handshake shows a real client,
// and its earlier failures (a half-typed phrase, a reconnect during a key
// change) should not count against it.
func (l *limiter) succeed(addr string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.addrs, addr)
}

// lastActive is when an address last did something the limiter still holds
// against it: its last failure, or the end of its block if that is later.
func lastActive(a *attempts) time.Time {
	if a.blockedUntil.After(a.last) {
		return a.blockedUntil
	}
	return a.last
}

// evictIfFullLocked drops the least recently active record to make room, so an
// address whose block is still running goes last.
func (l *limiter) evictIfFullLocked() {
	if len(l.addrs) < maxTrackedAddrs {
		return
	}
	var oldestKey string
	var oldest time.Time
	for k, a := range l.addrs {
		if t := lastActive(a); oldestKey == "" || t.Before(oldest) {
			oldestKey, oldest = k, t
		}
	}
	delete(l.addrs, oldestKey)
}

// clientAddr is the bucket a request counts against: the peer's IP without its
// port, since every connection gets a fresh source port.
func clientAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// An unparseable address is still limited, as a whole.
		return r.RemoteAddr
	}
	return host
}
