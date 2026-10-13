// Package relay routes messages between KnightLoader or BombVault instances
// that present the same relay key, so two instances behind NAT can reach each
// other by both dialling out to one place.
//
// Possession of the key is the whole authorization model: the relay has no
// account list and no database, it only groups connections that present the
// same string. State lives in memory and rebuilds itself as instances
// reconnect after a restart.
//
// Every connection owns a bounded queue and a writer goroutine, so one
// instance on a bad link cannot delay the others. Since any invented key gets
// in, every limit in this file (queue depth, connection
// counts, in-flight requests, key length) caps what one connection can cost
// the relay or its siblings. They are a floor, not a complete defence.
package relay

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// queueDepth is how many frames may sit unwritten for one connection. Relay
// traffic is request/response, so this only has to absorb a burst of answers
// while one connection briefly stalls.
const queueDepth = 64

// writeTimeout bounds one frame write. It only ever delays its own
// connection, because each connection has its own writer.
const writeTimeout = 5 * time.Second

// helloTimeout bounds how long a connection may stay open without having said
// who it is, so a socket that goes quiet cannot hold a goroutine forever.
const helloTimeout = 10 * time.Second

// challengeSize is how many random bytes the challenge a hello signs has.
const challengeSize = 32

// helloLimit caps what a connection may send before its hello is checked. A
// hello is a key, an instance id, a short sealed identity and at most a proof
// of the id, so a larger first frame only costs the relay memory on behalf of
// nobody.
const helloLimit = 4 << 10

// readLimit caps one inbound frame once the hello has passed. The default 32 KiB is too small for a task
// list from a busy instance; a few megabytes still keeps one client from
// pinning unbounded memory.
const readLimit = 8 << 20

// pendingTTL bounds how long the relay remembers an unanswered request, so a
// target that accepts a request and dies does not grow the table forever. The
// requester has its own timeout.
const pendingTTL = 2 * time.Minute

// minKeyLength is the shortest relay key accepted. It cannot enforce entropy,
// only rule out the laziest keys. The apps derive a key of 64 hex characters
// from their pairing phrase; 32 is the floor for a hand-made key.
const minKeyLength = 32

// maxPendingPerSender caps how many of one connection's proxy-requests may be
// unanswered at once. Without it a sender could fill its target's queue until
// enqueue evicts the target, punishing the side being flooded. A normal
// instance issuing a page's worth of concurrent calls never comes close.
const maxPendingPerSender = 32

// maxClientsPerKey bounds one key's group. A relay connects one person's
// instances, a handful or a few dozen, so this only caps how much state a
// guessed or leaked key can make the relay hold.
const maxClientsPerKey = 64

// maxTotalClients bounds every key combined, so inventing many keys does not
// get around the per-key cap.
const maxTotalClients = 2048

// Conn is the part of *websocket.Conn the registry uses. It is an interface so
// the registry can be tested without real sockets; the dynamic type has to be
// comparable, since connections are map keys.
type Conn interface {
	Write(ctx context.Context, typ websocket.MessageType, p []byte) error
	CloseNow() error
}

// client is one connection plus the queue its writer goroutine drains.
type client struct {
	conn     Conn
	key      string
	announce Announce
	// proven says the hello proved the key announce.InstanceID is made from.
	proven bool
	// only is the one id this connection may see and reach, "" for any (see
	// Server.Confine).
	only string
	send chan []byte
	// quit is closed once, by stop, to end the writer goroutine. send is never
	// closed: frames are pushed into it without the server lock, so closing it
	// would race a live send.
	quit chan struct{}
	once sync.Once
}

// stop ends the writer goroutine, which also closes the socket. A failed
// write, a dropped queue and a Leave can all reach it for the same client.
func (cl *client) stop() { cl.once.Do(func() { close(cl.quit) }) }

// pending is one proxy-request in flight. routeResponse checks an answer's
// sender against target, so a connection that guesses a live request ID
// cannot forge an answer.
type pending struct {
	from    Conn
	target  Conn
	expires time.Time
}

// pendingFailure is a request whose target left before answering, with the
// connection still waiting on it, so the caller can be told at once instead of
// timing out.
type pendingFailure struct {
	requestID string
	from      Conn
}

// Server is the relay: the key-grouped connection registry plus the WebSocket
// endpoint that fills it. pending is grouped by key because a request only
// ever runs between two connections on the same key, so one busy key does not
// make every other key's lookups and sweeps slower.
type Server struct {
	mu      sync.Mutex
	clients map[Conn]*client
	keys    map[string]map[Conn]*client
	pending map[string]map[string]pending // relay key -> request id -> pending

	// Admit decides whether a key may connect at all. nil admits every key,
	// which suits the standalone relay. An instance serving a relay from
	// inside itself sets it so only its own key gets in, rather than becoming
	// a rendezvous for anyone who finds the address. It is a function because
	// the switch and the key can change while the process runs.
	Admit func(key string) bool

	// Confine names, for a key the server admits on behalf of one instance
	// alone, that instance's id: a connection on such a key sees and reaches
	// that instance and nobody else, so whoever holds the key cannot use the
	// relay to meet others who do. "" leaves a key open, and so does a nil
	// Confine. It is read as each connection joins, and connections that
	// joined the key under an answer that no longer holds are dropped then.
	Confine func(key string) string

	// Names gives, for the request a connection arrives with, the host names
	// (RelayHost) this relay goes by, one of which a hello's proof has to name.
	// It gets the request so a relay that knows its names only by rule can
	// judge the Host header. nil takes the Host header as it is, which
	// whoever opens the connection writes, so only a relay that sets Names
	// keeps another relay from passing its challenge on to a member.
	Names func(r *http.Request) []string

	// TrustedProxies lists the reverse proxies whose X-Forwarded-For names
	// the caller for the handshake throttle. nil trusts none. A function for
	// the same reason as Admit.
	TrustedProxies func() []netip.Prefix

	// limiter backs off addresses that keep failing the handshake.
	limiter *limiter
}

// New returns an empty relay that admits every key. Set Admit to narrow it.
func New() *Server {
	return &Server{
		clients: map[Conn]*client{},
		keys:    map[string]map[Conn]*client{},
		pending: map[string]map[string]pending{},
		limiter: newLimiter(),
	}
}

// admits reports whether key may connect. Admit is read without the lock
// because it is set once before the server is mounted, to a closure that
// reads live configuration itself.
func (s *Server) admits(key string) bool {
	return s.Admit == nil || s.Admit(key)
}

// confined is the id connections on key are kept to, "" for none.
func (s *Server) confined(key string) string {
	if s.Confine == nil {
		return ""
	}
	return s.Confine(key)
}

// sees reports whether cl may learn of other and call it: always on an open
// key, and on a confined one only between the instance it is kept to and the
// rest.
func (cl *client) sees(other *client) bool {
	return cl.only == "" || cl.announce.InstanceID == cl.only || other.announce.InstanceID == cl.only
}

// meets reports whether cl and other may learn of and call each other. It
// asks both sides, since a connection that joined before its key was confined
// sees everybody and must still not reach a device kept away from it.
func (cl *client) meets(other *client) bool {
	return cl.sees(other) && other.sees(cl)
}

// names is what a hello's proof on r may name as its relay.
func (s *Server) names(r *http.Request) []string {
	if s.Names == nil {
		return []string{RelayHost(r.Host)}
	}
	return s.Names(r)
}

// Len reports how many connections are registered across every key.
func (s *Server) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.clients)
}

// Join registers a connection under its relay key and introduces it to the
// group both ways: siblings learn about the newcomer, and the newcomer learns
// about every sibling already there.
//
// A connection announcing an instance ID already on this key replaces the old
// one. An instance whose socket died without a close frame reconnects while
// the relay still holds the dead socket, and requests routed there would never
// be answered. Anybody else could announce the same id to take the instance's
// calls, so an id whose holder proved the key behind it (proven, see
// Hello.proves) is taken only by a connection that proves it too. A holder
// that proved nothing, as every BombVault and every KnightLoader before 1.9
// does, is replaced by whoever announces its id, since such a client has
// nothing else to reclaim its place with. The replaced connection gets no
// offline presence, since the announce says the instance is back, but
// requests still waiting on it are failed at once (see failPending).
//
// Connections on the key that joined while Confine answered otherwise for it
// are dropped, so a device that was on a group's key before a reset kept the
// key to one instance cannot reach the devices that join it afterwards.
//
// Join returns why the connection was not admitted, nil when it was; on an
// error the caller closes it.
func (s *Server) Join(key string, c Conn, a Announce, proven bool) error {
	cl := &client{
		conn:     c,
		key:      key,
		announce: a,
		proven:   proven,
		only:     s.confined(key),
		send:     make(chan []byte, queueDepth),
		quit:     make(chan struct{}),
	}

	s.mu.Lock()
	if _, ok := s.clients[c]; ok {
		s.mu.Unlock()
		return errJoinedTwice
	}
	group := s.keys[key]
	var replaced *client
	var stale []Conn
	siblings := make([]*client, 0, len(group))
	for _, other := range group {
		switch {
		case other.announce.InstanceID == a.InstanceID:
			replaced = other
		case other.only != cl.only:
			// It joined while the key was kept otherwise, such as before a
			// reset confined it, and would keep what it could reach then. It
			// reconnects and joins under what holds now.
			stale = append(stale, other.conn)
		case cl.meets(other):
			siblings = append(siblings, other)
		}
	}
	switch {
	case cl.only != "" && a.InstanceID == cl.only && !proven:
		// Whoever announces the id a confined key is kept to sees and reaches
		// everybody on it, so that takes the instance's own key.
		s.mu.Unlock()
		return errConfinedID
	case replaced != nil && replaced.proven && !proven:
		s.mu.Unlock()
		return errIDTaken
	case replaced == nil && (len(s.clients) >= maxTotalClients || len(group) >= maxClientsPerKey):
		s.mu.Unlock()
		return errGroupFull
	}
	var failures []pendingFailure
	if replaced != nil {
		_, failures = s.removeLocked(replaced.conn)
	}
	// Looked up again because removing the only connection on the key drops
	// its group, and a newcomer added to that map would be invisible.
	if group = s.keys[key]; group == nil {
		group = map[Conn]*client{}
		s.keys[key] = group
	}
	s.clients[c] = cl
	group[c] = cl
	s.mu.Unlock()

	if replaced != nil {
		replaced.stop()
	}
	s.failPending(failures, "the instance that would have answered this reconnected before it replied; retry")
	for _, gone := range stale {
		s.Leave(gone)
	}
	go s.writeLoop(cl)

	for _, sib := range siblings {
		s.enqueue(cl, frameOf(TypeAnnounce, sib.announce))
	}
	arrival := frameOf(TypeAnnounce, a)
	for _, sib := range siblings {
		s.enqueue(sib, arrival)
	}
	return nil
}

// The reasons Join turns a connection away, which the close frame carries.
var (
	errJoinedTwice = errors.New("this connection has already joined")
	errGroupFull   = errors.New("too many instances are already connected with this relay key")
	errIDTaken     = errors.New("another connection holds this id; only one that proves the key behind it takes its place")
	errConfinedID  = errors.New("this relay key is kept to one instance, and only a connection that proves its key announces its id")
)

// Leave unregisters a connection, stops its writer (which closes the socket),
// tells its siblings it went offline and fails any request still waiting on
// it. It is safe for a connection that never joined and safe to call twice, so
// callers can defer it.
func (s *Server) Leave(c Conn) {
	s.mu.Lock()
	cl, failures := s.removeLocked(c)
	var siblings []*client
	if cl != nil {
		for _, sib := range s.keys[cl.key] {
			if sib.meets(cl) {
				siblings = append(siblings, sib)
			}
		}
	}
	s.mu.Unlock()
	if cl == nil {
		return
	}
	cl.stop()
	s.failPending(failures, "the instance that would have answered this disconnected before it replied")
	gone := frameOf(TypePresence, Presence{InstanceID: cl.announce.InstanceID})
	for _, sib := range siblings {
		s.enqueue(sib, gone)
	}
}

// Route handles one frame a client sent up its socket. Only the proxy frames
// mean anything inbound; hello is consumed before the read loop starts.
// Anything unparseable or unknown is ignored rather than closing the
// connection, so a newer client using a frame type this build lacks stays
// connected.
func (s *Server) Route(c Conn, frame []byte) {
	env, err := Decode(frame)
	if err != nil {
		return
	}
	switch env.Type {
	case TypeProxyRequest:
		var req ProxyRequest
		if env.intoStrict(&req) != nil || req.RequestID == "" || req.Target == "" {
			return
		}
		s.routeRequest(c, req)
	case TypeProxyResponse:
		var resp ProxyResponse
		if env.Into(&resp) != nil || resp.RequestID == "" {
			return
		}
		s.routeResponse(c, resp.RequestID, frame)
	}
}

// routeRequest forwards a call to the sibling it names, encoded afresh from
// what was decoded with the sender's own id in Sender, so nothing the sender
// put in the frame can stand in for it. An unknown target, or a sender
// already at maxPendingPerSender, gets an immediate error response instead of
// a timeout, and the refused frame never reaches the target's queue.
func (s *Server) routeRequest(c Conn, req ProxyRequest) {
	s.mu.Lock()
	cl := s.clients[c]
	if cl == nil {
		s.mu.Unlock()
		return
	}
	var target *client
	for _, sib := range s.keys[cl.key] {
		if sib.conn != c && sib.announce.InstanceID == req.Target && cl.meets(sib) {
			target = sib
			break
		}
	}
	keyPending := s.pending[cl.key]
	if keyPending == nil {
		keyPending = map[string]pending{}
		s.pending[cl.key] = keyPending
	}
	sweepPendingLocked(keyPending)

	// A refusal carries Error and no sealed blob: the relay holds no part of
	// the frame key, so it cannot author an answer.
	var refusal *ProxyResponse
	switch {
	case target == nil:
		refusal = &ProxyResponse{
			RequestID: req.RequestID,
			Error:     "no instance " + req.Target + " is connected with this relay key",
		}
	case inFlightFromLocked(keyPending, c) >= maxPendingPerSender:
		refusal = &ProxyResponse{
			RequestID: req.RequestID,
			Error:     "too many requests from this instance are still waiting on an answer",
		}
	default:
		keyPending[req.RequestID] = pending{from: c, target: target.conn, expires: time.Now().Add(pendingTTL)}
	}
	s.mu.Unlock()

	if refusal != nil {
		s.enqueue(cl, frameOf(TypeProxyResponse, *refusal))
		return
	}
	req.Sender = cl.announce.InstanceID
	s.enqueue(target, frameOf(TypeProxyRequest, req))
}

// routeResponse sends an answer back to whoever asked, using the relay's own
// record of the request rather than trusting the responder. The frame is
// dropped unless it arrived on the connection the request was routed to, so a
// connection that learns a live request ID, even on another key, cannot forge
// the answer.
func (s *Server) routeResponse(c Conn, requestID string, frame []byte) {
	s.mu.Lock()
	cl := s.clients[c]
	if cl == nil {
		s.mu.Unlock()
		return
	}
	keyPending := s.pending[cl.key]
	p, ok := keyPending[requestID]
	if !ok || p.target != c {
		s.mu.Unlock()
		return
	}
	delete(keyPending, requestID)
	from := s.clients[p.from]
	s.mu.Unlock()
	if from == nil {
		return
	}
	s.enqueue(from, frame)
}

// removeLocked unregisters a connection and returns its client entry, or nil,
// plus the requests its departure orphaned. Requests it sent are forgotten;
// requests it was the target of are returned so the caller can fail them once
// the lock is released. The caller holds mu.
func (s *Server) removeLocked(c Conn) (*client, []pendingFailure) {
	cl := s.clients[c]
	if cl == nil {
		return nil, nil
	}
	delete(s.clients, c)
	group := s.keys[cl.key]
	delete(group, c)
	// Otherwise a long-running relay keeps an empty map for every key it has
	// ever seen.
	if len(group) == 0 {
		delete(s.keys, cl.key)
	}
	keyPending := s.pending[cl.key]
	var failures []pendingFailure
	for id, p := range keyPending {
		switch c {
		case p.from:
			delete(keyPending, id)
		case p.target:
			delete(keyPending, id)
			failures = append(failures, pendingFailure{requestID: id, from: p.from})
		}
	}
	if len(keyPending) == 0 {
		delete(s.pending, cl.key)
	}
	return cl, failures
}

// failPending answers each orphaned request with an error response to the
// connection that asked. It runs after the lock is released, since enqueue
// takes it again.
func (s *Server) failPending(failures []pendingFailure, reason string) {
	for _, f := range failures {
		s.mu.Lock()
		from := s.clients[f.from]
		s.mu.Unlock()
		if from == nil {
			continue
		}
		s.enqueue(from, frameOf(TypeProxyResponse, ProxyResponse{
			RequestID: f.requestID,
			Error:     reason,
		}))
	}
}

// sweepPendingLocked drops one key's requests that were never answered. The
// caller holds mu.
func sweepPendingLocked(keyPending map[string]pending) {
	now := time.Now()
	for id, p := range keyPending {
		if now.After(p.expires) {
			delete(keyPending, id)
		}
	}
}

// inFlightFromLocked counts one key's pending requests sent by from. The
// caller holds mu.
func inFlightFromLocked(keyPending map[string]pending, from Conn) int {
	n := 0
	for _, p := range keyPending {
		if p.from == from {
			n++
		}
	}
	return n
}

// enqueue hands one frame to a connection, or drops the connection if its
// queue is full. A dropped client reconnects and re-announces, whereas a relay
// stalled behind one bad link stops routing for the whole key. Eviction is
// safe because maxPendingPerSender keeps a sender from flooding a healthy
// target's queue; the rest of the traffic is bounded by the group size.
func (s *Server) enqueue(cl *client, frame []byte) {
	select {
	case cl.send <- frame:
	default:
		s.Leave(cl.conn)
	}
}

// writeLoop is the only goroutine that writes to a connection, which keeps a
// slow link off the routing path.
func (s *Server) writeLoop(cl *client) {
	// The writer owns the socket, so a dropped client is torn down without the
	// router waiting on a close handshake.
	defer func() { _ = cl.conn.CloseNow() }()
	for {
		// A stopped client must not keep draining its queue, and the select
		// below would pick a ready send about half the time.
		select {
		case <-cl.quit:
			return
		default:
		}
		select {
		case <-cl.quit:
			return
		case frame := <-cl.send:
			ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
			err := cl.conn.Write(ctx, websocket.MessageText, frame)
			cancel()
			if err != nil {
				s.Leave(cl.conn)
				return
			}
		}
	}
}

// frameOf marshals one outbound frame. Every payload the relay sends is a
// protocol.go struct that encoding/json cannot fail on.
func frameOf(typ string, data any) []byte {
	b, _ := Encode(typ, data)
	return b
}

// ServeHTTP is the relay endpoint: one long-lived WebSocket per instance.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Refused before the upgrade, so a failing address costs one HTTP response
	// rather than a WebSocket and a goroutine. 429 because the caller should
	// slow down, not give up.
	var trusted []netip.Prefix
	if s.TrustedProxies != nil {
		trusted = s.TrustedProxies()
	}
	addr := clientAddr(r, trusted)
	if s.limiter.blocked(addr) {
		http.Error(w, "too many failed handshakes from this address", http.StatusTooManyRequests)
		return
	}

	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// No origin check, unlike internal/api's socket: there is no session or
		// cookie to ride, the key in the first frame is the only credential,
		// and every legitimate client is cross-origin.
		OriginPatterns: []string{"*"},
	})
	if err != nil {
		return
	}
	c.SetReadLimit(helloLimit)

	// Sent before the hello is read and never waited on, so a client that
	// writes its hello at once and skips frame types it does not know, as
	// every BombVault does, connects without ever looking at it.
	challenge := make([]byte, challengeSize)
	if _, err := rand.Read(challenge); err != nil {
		c.Close(websocket.StatusInternalError, "the relay has no randomness for a challenge")
		return
	}
	writeCtx, cancel := context.WithTimeout(r.Context(), writeTimeout)
	err = c.Write(writeCtx, websocket.MessageText, frameOf(TypeChallenge, Challenge{Nonce: challenge}))
	cancel()
	if err != nil {
		_ = c.CloseNow()
		return
	}

	hello, err := readHello(r.Context(), c)
	if err != nil {
		s.limiter.fail(addr)
		c.Close(websocket.StatusPolicyViolation, "the first frame must be a hello with a relay key of at least 32 characters and an instance id")
		return
	}
	// Checked before Join, so an unserved key never enters the registry. The
	// close reason tells an instance whose key stopped matching what happened.
	if !s.admits(hello.Key) {
		s.limiter.fail(addr)
		c.Close(websocket.StatusPolicyViolation, "this relay does not serve that relay key")
		return
	}
	s.limiter.succeed(addr)
	if err := s.Join(hello.Key, c, hello.Announce, hello.proves(challenge, s.names(r))); err != nil {
		c.Close(websocket.StatusPolicyViolation, err.Error())
		return
	}
	c.SetReadLimit(readLimit)
	// Leave stops the writer, which closes the socket, so this is the whole
	// teardown.
	defer s.Leave(c)
	for {
		_, frame, err := c.Read(r.Context())
		if err != nil {
			return
		}
		s.Route(c, frame)
	}
}

// readHello consumes the frame that authenticates a connection, on its own
// deadline, so an unauthenticated socket costs one goroutine for helloTimeout
// at most.
func readHello(ctx context.Context, c *websocket.Conn) (Hello, error) {
	ctx, cancel := context.WithTimeout(ctx, helloTimeout)
	defer cancel()
	_, frame, err := c.Read(ctx)
	if err != nil {
		return Hello{}, err
	}
	env, err := Decode(frame)
	if err != nil {
		return Hello{}, err
	}
	if env.Type != TypeHello {
		return Hello{}, errors.New("first frame is not a hello")
	}
	var h Hello
	if err := env.Into(&h); err != nil {
		return Hello{}, err
	}
	if len(h.Key) < minKeyLength || h.Announce.InstanceID == "" {
		return Hello{}, errors.New("hello carries no relay key, a key shorter than the minimum, or no instance id")
	}
	return h, nil
}
