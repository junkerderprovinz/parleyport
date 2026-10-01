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
	"errors"
	"net/http"
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

// helloLimit caps what a connection may send before its hello is checked. A
// hello is a key, an instance id and a short sealed identity, so a larger
// first frame only costs the relay memory on behalf of nobody.
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
	send     chan []byte
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
// be answered. The replaced connection gets no offline presence, since the
// announce says the instance is back, but requests still waiting on it are
// failed at once (see failPending).
//
// Join reports whether the connection was admitted; on false the caller closes
// it. That happens when the connection limits are reached and this is not a
// reconnect, or when the same connection joins twice.
func (s *Server) Join(key string, c Conn, a Announce) bool {
	cl := &client{
		conn:     c,
		key:      key,
		announce: a,
		send:     make(chan []byte, queueDepth),
		quit:     make(chan struct{}),
	}

	s.mu.Lock()
	if _, ok := s.clients[c]; ok {
		s.mu.Unlock()
		return false
	}
	group := s.keys[key]
	if group == nil {
		group = map[Conn]*client{}
		s.keys[key] = group
	}
	var replaced *client
	siblings := make([]*client, 0, len(group))
	for _, other := range group {
		if other.announce.InstanceID == a.InstanceID {
			replaced = other
			continue
		}
		siblings = append(siblings, other)
	}
	if replaced == nil {
		if len(s.clients) >= maxTotalClients || len(group) >= maxClientsPerKey {
			s.mu.Unlock()
			return false
		}
	}
	var failures []pendingFailure
	if replaced != nil {
		_, failures = s.removeLocked(replaced.conn)
	}
	s.clients[c] = cl
	group[c] = cl
	s.mu.Unlock()

	if replaced != nil {
		replaced.stop()
	}
	s.failPending(failures, "the instance that would have answered this reconnected before it replied; retry")
	go s.writeLoop(cl)

	for _, sib := range siblings {
		s.enqueue(cl, frameOf(TypeAnnounce, sib.announce))
	}
	arrival := frameOf(TypeAnnounce, a)
	for _, sib := range siblings {
		s.enqueue(sib, arrival)
	}
	return true
}

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
			siblings = append(siblings, sib)
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
		if env.Into(&req) != nil || req.RequestID == "" || req.Target == "" {
			return
		}
		s.routeRequest(c, req, frame)
	case TypeProxyResponse:
		var resp ProxyResponse
		if env.Into(&resp) != nil || resp.RequestID == "" {
			return
		}
		s.routeResponse(c, resp.RequestID, frame)
	}
}

// routeRequest forwards a call verbatim to the sibling it names; the frame is
// never re-marshalled, so a body the relay does not understand arrives intact.
// An unknown target, or a sender already at maxPendingPerSender, gets an
// immediate error response instead of a timeout, and the refused frame never
// reaches the target's queue.
func (s *Server) routeRequest(c Conn, req ProxyRequest, frame []byte) {
	s.mu.Lock()
	cl := s.clients[c]
	if cl == nil {
		s.mu.Unlock()
		return
	}
	var target *client
	for _, sib := range s.keys[cl.key] {
		if sib.conn != c && sib.announce.InstanceID == req.Target {
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
	s.enqueue(target, frame)
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
	addr := clientAddr(r)
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
	if !s.Join(hello.Key, c, hello.Announce) {
		c.Close(websocket.StatusPolicyViolation, "too many instances are already connected with this relay key")
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
