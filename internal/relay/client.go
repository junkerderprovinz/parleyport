package relay

// The instance side of the relay: one outbound WebSocket an instance keeps
// open to a relay, so two instances behind NAT reach each other without
// either accepting an inbound connection.
//
// The client depends on protocol.go and the standard library only, because
// the desktop build, which has no listener and can only be paired this way,
// uses it as well as the container build. Unlike Server it has no queue or
// writer goroutine: it has one peer, so a slow write only delays its own
// caller, and coder/websocket serializes concurrent writes itself.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// connectPath is appended to an address that does not name the socket itself,
// so the bare "https://relay.example.com" given to a reverse proxy works, and
// so does "https://example.com/kl" for an instance a proxy serves under /kl.
const connectPath = "/relay/connect"

// proxyTimeout bounds one call to a sibling over the relay. It matches
// federation's peerTimeout, so a call has the same patience over either
// transport.
const proxyTimeout = 15 * time.Second

// dialTimeout bounds one connection attempt, for a relay that accepts TCP and
// never finishes the upgrade.
const dialTimeout = 15 * time.Second

// minBackoff and maxBackoff bound the reconnect loop. It retries forever, but
// a minute apart once nobody is answering.
const (
	minBackoff = time.Second
	maxBackoff = time.Minute
)

// stableSession is how long a connection has to last before the backoff
// resets. Resetting on every successful dial would redial once a second a
// relay that accepts the socket and then hangs up, such as one rejecting the
// key.
const stableSession = 30 * time.Second

// pingInterval keeps the connection alive through reverse proxies that close
// an idle upstream after a minute or so; this socket is idle between calls.
const pingInterval = 30 * time.Second

// pingTimeout is how long a pong may take before the connection counts as
// dead, which turns a silently broken link into a reconnect.
const pingTimeout = 10 * time.Second

// ProxyHandler answers one call a sibling made to this instance's REST API,
// returning the status and body to send back. It receives the opened
// ProxyCall rather than the wire frame, so it cannot trust a routing field the
// relay was free to write.
type ProxyHandler func(ctx context.Context, call ProxyCall) (status int, body []byte)

// ClientOptions configures a Client. URL, Key, FrameKey and Self.InstanceID
// are required.
type ClientOptions struct {
	// URL is the relay's address, with or without the connect path, with an
	// http(s) or ws(s) scheme.
	URL string
	// Key is the relay key, the only credential the protocol has.
	Key string
	// FrameKey is the 32-byte key every proxy frame is sealed under. It must
	// be the same on every instance in the group and must not be derivable
	// from Key, which the relay receives (see DeriveFrameKey).
	FrameKey []byte
	// Self is what siblings see on their Instances page.
	Self Announce
	// Serve answers calls siblings make to this instance. With a nil Serve
	// every inbound call gets 501 instead of timing out.
	Serve ProxyHandler
	// Replay admits the calls Serve gets. nil gives the client a guard of its
	// own; an instance that also takes direct calls passes the guard those go
	// through.
	Replay *ReplayGuard
	// OnChange fires when a sibling arrives or leaves and when the connection
	// comes up or goes down. It runs on the client's goroutine and must not
	// block.
	OnChange func()
}

// Client is one instance's connection to a relay: it announces itself, tracks
// the visible siblings, answers their calls and makes calls to them.
//
// Every method works whether or not the relay is reachable. A disconnected
// Client reports no siblings and fails proxy calls at once; it never blocks a
// caller waiting for the relay.
type Client struct {
	url string
	key string
	// frameKey seals and opens every proxy frame. Unlike key it never leaves
	// the process.
	frameKey []byte
	self     Announce
	serve    ProxyHandler
	replay   *ReplayGuard
	onChange func()

	// minBackoff and maxBackoff default to the package constants; tests
	// shorten them.
	minBackoff time.Duration
	maxBackoff time.Duration

	mu       sync.Mutex
	conn     *websocket.Conn
	siblings map[string]Announce
	pending  map[string]chan ProxyResponse
	started  bool

	startOnce sync.Once
	closeOnce sync.Once
	stop      chan struct{}
	done      chan struct{}
}

// NewClient validates the configuration and returns a Client that is not yet
// connected. A bad address, key, instance id or frame key is an error here,
// since each is a permanent misconfiguration that would otherwise show up as
// a connection that never works or calls that all fail.
func NewClient(opts ClientOptions) (*Client, error) {
	connect, err := connectURL(opts.URL)
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(opts.Key)) < minKeyLength {
		return nil, errors.New("relay: no relay key configured, or it is shorter than the minimum the relay itself will accept")
	}
	if opts.Self.InstanceID == "" {
		return nil, errors.New("relay: no instance id to announce")
	}
	if len(opts.FrameKey) != 32 {
		return nil, fmt.Errorf("relay: frame key is %d bytes, want 32", len(opts.FrameKey))
	}
	replay := opts.Replay
	if replay == nil {
		replay = NewReplayGuard()
	}
	return &Client{
		url:        connect,
		key:        opts.Key,
		frameKey:   opts.FrameKey,
		self:       opts.Self,
		serve:      opts.Serve,
		replay:     replay,
		onChange:   opts.OnChange,
		minBackoff: minBackoff,
		maxBackoff: maxBackoff,
		siblings:   map[string]Announce{},
		pending:    map[string]chan ProxyResponse{},
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
	}, nil
}

// Start connects in the background and keeps reconnecting until Close. It
// returns at once and never reports a dial failure, since the loop already
// retries. A second call does nothing, and so does a call after Close, so a
// boot that fails between NewClient and Start can still run a deferred Close.
func (c *Client) Start() {
	c.startOnce.Do(func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		select {
		case <-c.stop:
			return
		default:
		}
		c.started = true
		go c.run()
	})
}

// Close ends the connection and the reconnect loop and waits for the loop to
// finish, so the caller can tear down whatever Serve talks to.
func (c *Client) Close() error {
	c.closeOnce.Do(func() { close(c.stop) })
	c.mu.Lock()
	conn, started := c.conn, c.started
	c.mu.Unlock()
	if conn != nil {
		_ = conn.CloseNow()
	}
	if started {
		<-c.done
	}
	return nil
}

// Connected reports whether the relay connection is up. An empty sibling list
// cannot tell "the relay is down" from "no other instance is connected".
func (c *Client) Connected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil
}

// Siblings returns the instances visible through the relay, sorted by instance
// ID, which unlike the name is unique on a key. It is empty while the relay is
// unreachable.
func (c *Client) Siblings() []Announce {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Announce, 0, len(c.siblings))
	for _, a := range c.siblings {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].InstanceID < out[j].InstanceID })
	return out
}

// Proxy calls one sibling's REST API through the relay and waits for its
// answer, in the shape federation.Manager.Proxy uses over direct HTTP.
//
// An error means no answer came from the sibling: the relay or the sibling is
// not connected, or nobody replied in time. A reply the sibling produced is
// returned with its status however bad, so a caller can tell "your other
// instance said no" from "your other instance is gone".
func (c *Client) Proxy(ctx context.Context, target, method, path string, body []byte, authorization string) ([]byte, int, error) {
	id, err := requestID()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	c.mu.Lock()
	conn := c.conn
	answer := make(chan ProxyResponse, 1)
	if conn != nil {
		c.pending[id] = answer
	}
	c.mu.Unlock()
	if conn == nil {
		return nil, http.StatusBadGateway, errors.New("relay: not connected")
	}
	defer func() {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(ctx, proxyTimeout)
	defer cancel()
	sealed, err := SealCall(c.frameKey, id, target, ProxyCall{
		Method: method, Path: path, Body: body, Authorization: authorization,
	})
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	frame := frameOf(TypeProxyRequest, ProxyRequest{RequestID: id, Target: target, Sealed: sealed})
	if err := writeFrameTo(ctx, conn, frame); err != nil {
		return nil, http.StatusBadGateway, fmt.Errorf("relay: %w", err)
	}

	select {
	case <-ctx.Done():
		return nil, http.StatusGatewayTimeout, fmt.Errorf("relay: %s did not answer: %w", target, ctx.Err())
	case resp := <-answer:
		// Error is the one field a hostile relay can write, so it is checked
		// before Sealed and an unsealed response is never taken as a result.
		// That limits a relay to denial of service.
		if resp.Error != "" {
			return nil, http.StatusBadGateway, errors.New("relay: " + resp.Error)
		}
		result, err := OpenResult(c.frameKey, id, resp.Sealed)
		if err != nil {
			// The peer holds a different secret, or the frame was rewritten
			// in flight. Neither is a reply.
			return nil, http.StatusBadGateway, fmt.Errorf("relay: %s answered unreadably: %w", target, err)
		}
		return result.Body, result.Status, nil
	}
}

// run is the reconnect loop: one session at a time until Close.
func (c *Client) run() {
	defer close(c.done)
	wait := c.minBackoff
	for {
		select {
		case <-c.stop:
			return
		default:
		}
		began := time.Now()
		c.session()
		if time.Since(began) >= stableSession {
			wait = c.minBackoff
		}
		if !c.sleep(wait) {
			return
		}
		if wait *= 2; wait > c.maxBackoff {
			wait = c.maxBackoff
		}
	}
}

// sleep waits out one backoff and reports false if Close came first.
func (c *Client) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-c.stop:
		return false
	case <-t.C:
		return true
	}
}

// session runs one connection from dial to death. Whatever ends it (a failed
// dial, a rejected key, a dead link or Close), the loop tries again later.
func (c *Client) session() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Read only unblocks on its context, so Close has to cancel it.
	go func() {
		select {
		case <-c.stop:
			cancel()
		case <-ctx.Done():
		}
	}()

	dialCtx, dialCancel := context.WithTimeout(ctx, dialTimeout)
	conn, _, err := websocket.Dial(dialCtx, c.url, nil)
	dialCancel()
	if err != nil {
		return
	}
	conn.SetReadLimit(readLimit)
	defer func() { _ = conn.CloseNow() }()

	// The hello goes out before the connection is published, so nothing
	// proxies over a socket that has not introduced itself. The relay does not
	// answer it: a refused key shows only as the relay closing the socket right
	// after. This is the only place an announce leaves the process, and it is
	// always sealed: NewClient has
	// already checked the frame key, so a failure here is the cipher itself and
	// never a reason to fall back to plaintext.
	self, err := sealAnnounce(c.frameKey, c.self)
	if err != nil {
		log.Printf("relay: this instance's announce could not be sealed, not connecting: %v", err)
		return
	}
	helloCtx, helloCancel := context.WithTimeout(ctx, writeTimeout)
	err = writeFrameTo(helloCtx, conn, frameOf(TypeHello, Hello{Key: c.key, Announce: self}))
	helloCancel()
	if err != nil {
		return
	}

	c.connected(conn)
	defer c.disconnected()
	go c.keepalive(ctx, conn)

	for {
		_, frame, err := conn.Read(ctx)
		if err != nil {
			return
		}
		c.handle(ctx, conn, frame)
	}
}

// keepalive pings the relay and closes the socket when a ping fails, which
// ends the read loop and the session. Ping needs the reader in session to
// receive the pong.
func (c *Client) keepalive(ctx context.Context, conn *websocket.Conn) {
	t := time.NewTicker(pingInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pingCtx, cancel := context.WithTimeout(ctx, pingTimeout)
			err := conn.Ping(pingCtx)
			cancel()
			if err != nil {
				_ = conn.CloseNow()
				return
			}
		}
	}
}

// handle dispatches one frame the relay sent. Unparseable or unknown frames are
// ignored, as in Server.Route, so a newer relay does not cost this instance
// its peers.
func (c *Client) handle(ctx context.Context, conn *websocket.Conn, frame []byte) {
	env, err := Decode(frame)
	if err != nil {
		return
	}
	switch env.Type {
	case TypeAnnounce:
		var a Announce
		if env.Into(&a) != nil || a.InstanceID == "" {
			return
		}
		c.mu.Lock()
		c.siblings[a.InstanceID] = openAnnounce(c.frameKey, a)
		c.mu.Unlock()
		c.changed()
	case TypePresence:
		var p Presence
		// Arrivals come as an Announce with the sibling's name, so only an
		// offline report is acted on.
		if env.Into(&p) != nil || p.InstanceID == "" || p.Online {
			return
		}
		c.mu.Lock()
		delete(c.siblings, p.InstanceID)
		c.mu.Unlock()
		c.changed()
	case TypeProxyResponse:
		var resp ProxyResponse
		if env.Into(&resp) != nil || resp.RequestID == "" {
			return
		}
		c.deliver(resp)
	case TypeProxyRequest:
		var req ProxyRequest
		if env.Into(&req) != nil || req.RequestID == "" {
			return
		}
		// Answering runs a real API call, and the read loop has to stay free
		// for the next frame, possibly the answer to a call of our own.
		go c.answer(ctx, conn, req)
	}
}

// answer runs one inbound call and sends the result back. A frame that does
// not open is dropped without a reply: its sender is on this relay key without
// this group's secret, or the frame was rewritten, and an error reply would
// only confirm that the key was accepted. Nor does one that is old or ran
// before get a reply, which is a relay sending a captured frame again.
func (c *Client) answer(ctx context.Context, conn *websocket.Conn, req ProxyRequest) {
	call, err := OpenCall(c.frameKey, req.RequestID, c.self.InstanceID, req.Sealed)
	if err != nil || !c.replay.Admit(call) {
		return
	}
	result := ProxyResult{Status: http.StatusNotImplemented}
	if c.serve != nil {
		serveCtx, cancel := context.WithTimeout(ctx, proxyTimeout)
		result.Status, result.Body = c.serve(serveCtx, call)
		cancel()
	}
	sealed, err := SealResult(c.frameKey, req.RequestID, result)
	if err != nil {
		return
	}
	writeCtx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	_ = writeFrameTo(writeCtx, conn, frameOf(TypeProxyResponse, ProxyResponse{
		RequestID: req.RequestID, Sealed: sealed,
	}))
}

// deliver hands a response to the Proxy call waiting on it. A response nobody
// waits for is dropped.
func (c *Client) deliver(resp ProxyResponse) {
	c.mu.Lock()
	answer := c.pending[resp.RequestID]
	delete(c.pending, resp.RequestID)
	c.mu.Unlock()
	if answer != nil {
		answer <- resp
	}
}

// connected publishes a live socket so Proxy can use it.
func (c *Client) connected(conn *websocket.Conn) {
	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()
	c.changed()
}

// disconnected clears the sibling list, since a relay peer exists only while
// the relay says so, and fails every call in flight at once instead of letting
// it time out.
func (c *Client) disconnected() {
	c.mu.Lock()
	c.conn = nil
	c.siblings = map[string]Announce{}
	waiting := make([]chan ProxyResponse, 0, len(c.pending))
	for id, answer := range c.pending {
		waiting = append(waiting, answer)
		delete(c.pending, id)
	}
	c.mu.Unlock()
	for _, answer := range waiting {
		answer <- ProxyResponse{
			Error: "the relay connection dropped before the answer arrived",
		}
	}
	c.changed()
}

// changed calls OnChange. It runs without the lock held, since the callback
// may call back into Siblings.
func (c *Client) changed() {
	if c.onChange != nil {
		c.onChange()
	}
}

// writeFrameTo writes one frame under the caller's deadline, capped by
// writeTimeout.
func writeFrameTo(ctx context.Context, conn *websocket.Conn, frame []byte) error {
	ctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	return conn.Write(ctx, websocket.MessageText, frame)
}

// requestID is the token a response is matched back by. It is random rather
// than a counter, which would restart on reconnect and deliver a late answer
// to whoever inherited the number.
func requestID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// connectURL turns a configured address into the WebSocket URL to dial. It
// accepts both the https:// address given to a reverse proxy and a wss:// URL.
func connectURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("relay: %q is not a relay address", raw)
	}
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	case "ws", "wss":
	default:
		return "", fmt.Errorf("relay: %q must be an http(s) or ws(s) address", raw)
	}
	// A path ending in /connect names the socket and stays, since a relay
	// behind a reverse proxy can be mounted anywhere. Any other path is where
	// a proxy serves an instance, whose relay sits below it.
	p := strings.TrimRight(u.Path, "/")
	if !strings.HasSuffix(p, "/connect") {
		p += connectPath
	}
	u.Path, u.RawPath = p, ""
	return u.String(), nil
}
