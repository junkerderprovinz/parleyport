package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/junkerderprovinz/parleyport/kit/keys"
	"github.com/junkerderprovinz/parleyport/kit/member"
)

// proxyTimeout is how long a call to a sibling over the relay waits with
// nothing coming in, and how long the sibling may take to serve it.
const proxyTimeout = 15 * time.Second

// dialTimeout bounds one connection attempt, for a relay that accepts TCP and
// never finishes the upgrade.
const dialTimeout = 15 * time.Second

// The reconnect loop retries forever, a minute apart once nobody answers.
const (
	minBackoff = time.Second
	maxBackoff = time.Minute
)

// stableSession is how long a connection has to last before the backoff
// resets, so a relay that accepts the socket and hangs up at once, such as one
// refusing the key, is not redialled every second.
const stableSession = 30 * time.Second

// pingInterval keeps the socket alive through reverse proxies that close an
// idle upstream after a minute or so.
const pingInterval = 30 * time.Second

// pingTimeout is how long a pong may take before the connection counts as
// dead and is redialled.
const pingTimeout = 10 * time.Second

// Dial opens every Client's socket. An app's tests can replace it so that none
// of them reaches the project relay.
var Dial = websocket.Dial

// ProxyHandler answers one call a sibling made, returning the status and body
// to send back, or StatusDrop to send nothing. It gets the opened call, never
// the wire frame, so it cannot trust a field the relay was free to write.
// Whether the call is new is the handler's to decide (see ReplayGuard), since
// only it knows whose key it pinned.
type ProxyHandler func(ctx context.Context, call ProxyCall) (status int, body []byte)

// ClientOptions configures a Client. URL, Key and FrameKey are required, and
// Self.InstanceID unless Identity gives it.
type ClientOptions struct {
	// URL is the relay's address, with or without the connect path, with an
	// http(s) or ws(s) scheme.
	URL string
	// Key is the group key, the one credential the relay asks for.
	Key string
	// FrameKey is the 32-byte key every frame is sealed under, the same on
	// every member and not derivable from Key.
	FrameKey []byte
	// Signing names the labels calls and answers are signed under. It is
	// required with an Identity.
	Signing keys.Signing
	// Self is what siblings see of this instance.
	Self Announce
	// Identity is this instance's member key. Every call it makes and every
	// answer it gives is signed with it, and its hello proves its id. nil
	// leaves all three unsigned.
	Identity *member.Identity
	// Trusts reports whether an answer signed by key may count as target's,
	// beyond the key making target's id, which Proxy checks itself. nil
	// trusts every such answer.
	Trusts func(target string, key ed25519.PublicKey) bool
	// Serve answers calls siblings make. With a nil Serve every call gets 501
	// instead of timing out.
	Serve ProxyHandler
	// OnChange fires when a sibling arrives or leaves and when the connection
	// comes up or goes down. It runs on the client's goroutine and must not
	// block.
	OnChange func()
}

// Client is one instance's connection to a relay: it announces itself, keeps
// the list of visible siblings, answers their calls and calls them.
//
// Every method works whether or not the relay is reachable. A disconnected
// Client lists no siblings and fails calls at once; it never blocks a caller
// waiting for the relay.
type Client struct {
	url       string
	relayHost string
	key       string
	frameKey  []byte
	signing   keys.Signing
	id        string
	identity  *member.Identity
	trusts    func(target string, key ed25519.PublicKey) bool
	serve     ProxyHandler
	onChange  func()

	minBackoff time.Duration
	maxBackoff time.Duration

	mu       sync.Mutex
	self     Announce
	conn     *websocket.Conn
	siblings map[string]Announce
	pending  map[string]*waiting
	started  bool

	// inbound is the read loop's state, moved when bytes last came in.
	inbound atomic.Int32
	moved   atomic.Int64

	startOnce sync.Once
	closeOnce sync.Once
	stop      chan struct{}
	done      chan struct{}
}

// NewClient checks the configuration and returns a Client that is not yet
// connected. A bad address, key, id or frame key is an error here, since each
// would otherwise show only as a connection that never works.
func NewClient(opts ClientOptions) (*Client, error) {
	connect, err := connectURL(opts.URL)
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(opts.Key)) < minKeyLength {
		return nil, errors.New("relay: no group key configured, or it is shorter than the relay accepts")
	}
	if len(opts.FrameKey) != 32 {
		return nil, fmt.Errorf("relay: frame key is %d bytes, want 32", len(opts.FrameKey))
	}
	self := opts.Self
	if opts.Identity != nil {
		if opts.Signing.Call == "" || opts.Signing.Result == "" {
			return nil, errors.New("relay: an identity needs the labels to sign under")
		}
		if self.InstanceID == "" {
			self.InstanceID = opts.Identity.ID()
		}
		if self.InstanceID != opts.Identity.ID() {
			return nil, errors.New("relay: the instance id is not the one the identity makes")
		}
	}
	if self.InstanceID == "" {
		return nil, errors.New("relay: no instance id to announce")
	}
	return &Client{
		url:        connect,
		relayHost:  RelayHost(connect),
		key:        opts.Key,
		frameKey:   opts.FrameKey,
		signing:    opts.Signing,
		id:         self.InstanceID,
		self:       self,
		identity:   opts.Identity,
		trusts:     opts.Trusts,
		serve:      opts.Serve,
		onChange:   opts.OnChange,
		minBackoff: minBackoff,
		maxBackoff: maxBackoff,
		siblings:   map[string]Announce{},
		pending:    map[string]*waiting{},
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
	}, nil
}

// Start connects in the background and keeps reconnecting until Close. It
// returns at once. A second call does nothing, and neither does one after
// Close.
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

// SetSelf changes what siblings see of this instance, all but its id. The
// relay takes an announce only with the hello, so the client says hello again
// on a new connection, and siblings see it leave and come back.
func (c *Client) SetSelf(self Announce) {
	c.mu.Lock()
	self.InstanceID = c.id
	c.self = self
	conn := c.conn
	c.mu.Unlock()
	if conn != nil {
		_ = conn.CloseNow()
	}
}

// Connected reports whether the relay connection is up, which an empty
// sibling list cannot tell.
func (c *Client) Connected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil
}

// Siblings returns the instances visible through the relay, sorted by id. It
// is empty while the relay is unreachable.
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

// Proxy calls target through the relay and waits for its answer.
//
// An error means no answer came: the relay or the target is not connected, or
// nobody replied in time. An answer the target gave is returned with its
// status however bad, so a caller can tell "your other instance said no" from
// "your other instance is gone". An answer counts only once the key target's
// id is made from signed it and Trusts takes that key.
func (c *Client) Proxy(ctx context.Context, target, method, path string, body []byte) ([]byte, int, error) {
	id, err := requestID()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	c.mu.Lock()
	conn := c.conn
	w := newWaiting()
	if conn != nil {
		c.pending[id] = w
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

	sealed, err := SealSignedCall(c.frameKey, c.signing, c.identity, id, target, ProxyCall{Method: method, Path: path, Body: body})
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	frame := frameOf(TypeProxyRequest, ProxyRequest{RequestID: id, Target: target, Sealed: sealed, Framing: framingParts})
	if err := sendFrame(ctx, conn, frame, writeTimeout); err != nil {
		return nil, http.StatusBadGateway, fmt.Errorf("relay: %w", err)
	}

	resp, err := c.await(ctx, w, proxyTimeout, writeTimeout)
	if err != nil {
		return nil, http.StatusGatewayTimeout, fmt.Errorf("relay: %s did not answer: %w", target, err)
	}
	// Error is the one field a hostile relay can write, so an unsealed
	// response is never taken as a result.
	if resp.Error != "" {
		return nil, http.StatusBadGateway, errors.New("relay: " + resp.Error)
	}
	result, err := OpenResult(c.frameKey, id, resp.Sealed)
	if err != nil {
		return nil, http.StatusBadGateway, fmt.Errorf("relay: %s answered unreadably: %w", target, err)
	}
	if !VerifyResult(c.signing, id, target, sealed, result) {
		return nil, http.StatusBadGateway, fmt.Errorf("relay: %s's answer is not signed by its key", target)
	}
	if c.trusts != nil && !c.trusts(target, result.Key) {
		return nil, http.StatusBadGateway, &UntrustedAnswer{Target: target, Status: result.Status, Body: result.Body}
	}
	return result.Body, result.Status, nil
}

// UntrustedAnswer is the error for an answer target signed with the key its id
// is made from but that Trusts does not take. It carries the answer, which the
// caller may read only for what cannot hurt it, such as that target has this
// instance waiting for approval.
type UntrustedAnswer struct {
	Target string
	Status int
	Body   []byte
}

func (e *UntrustedAnswer) Error() string {
	return "relay: " + e.Target + " is not approved on this instance"
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

// session runs one connection from dial to death.
func (c *Client) session() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Read only returns on its context, so Close has to cancel it.
	go func() {
		select {
		case <-c.stop:
			cancel()
		case <-ctx.Done():
		}
	}()

	dialCtx, dialCancel := context.WithTimeout(ctx, dialTimeout)
	conn, _, err := Dial(dialCtx, c.url, nil)
	dialCancel()
	if err != nil {
		return
	}
	conn.SetReadLimit(readLimit)
	defer func() { _ = conn.CloseNow() }()

	// The announce is always sealed. NewClient checked the frame key, so a
	// failure here is the cipher itself and never a reason to send plaintext.
	c.mu.Lock()
	announce := c.self
	c.mu.Unlock()
	self, err := sealAnnounce(c.frameKey, announce)
	if err != nil {
		log.Printf("relay: this instance's announce could not be sealed, not connecting: %v", err)
		return
	}
	challenge, err := readChallenge(ctx, conn)
	if err != nil {
		return
	}
	// The hello goes out before the connection is published, so nothing is
	// called over a socket that has not introduced itself. A refused key
	// shows only as the relay closing the socket right after.
	hello := Hello{Key: c.key, Announce: self}
	if c.identity != nil {
		hello.Proof = c.identity.ProveHello(c.key, c.relayHost, challenge)
	}
	if err := sendFrame(ctx, conn, frameOf(TypeHello, hello), writeTimeout); err != nil {
		return
	}

	c.connected(conn)
	defer c.disconnected()
	go c.keepalive(ctx, conn)

	for {
		_, r, err := conn.Reader(ctx)
		if err != nil {
			return
		}
		c.moved.Store(time.Now().UnixNano())
		c.inbound.Store(reading)
		frame, err := io.ReadAll(moving{r: r, moved: &c.moved})
		if err != nil {
			c.inbound.Store(idle)
			return
		}
		c.inbound.Store(handling)
		c.handle(ctx, conn, frame)
		c.inbound.Store(idle)
	}
}

// readChallenge reads the first frame a relay sends, the challenge the hello
// signs.
func readChallenge(ctx context.Context, conn *websocket.Conn) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, helloTimeout)
	defer cancel()
	_, frame, err := conn.Read(ctx)
	if err != nil {
		return nil, err
	}
	var ch Challenge
	env, err := Decode(frame)
	if err != nil || env.Type != TypeChallenge || env.Into(&ch) != nil || len(ch.Nonce) != challengeSize {
		return nil, errors.New("relay: the first frame is not a challenge")
	}
	return ch.Nonce, nil
}

// keepalive pings the relay and closes the socket when a ping fails, which
// ends the session. The pong arrives through the read loop in session.
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

// handle dispatches one frame the relay sent. Unparseable and unknown frames
// are ignored, so a newer relay does not cost this instance its siblings.
func (c *Client) handle(ctx context.Context, conn *websocket.Conn, frame []byte) {
	env, err := Decode(frame)
	if err != nil {
		return
	}
	switch env.Type {
	case TypeAnnounce:
		var a Announce
		if env.Into(&a) != nil {
			return
		}
		a = openAnnounce(c.frameKey, a)
		if !listable(a) {
			return
		}
		// An honest relay never introduces more siblings than it admits on
		// one key, so the cap only binds a relay inventing them.
		c.mu.Lock()
		_, known := c.siblings[a.InstanceID]
		if !known && len(c.siblings) >= maxClientsPerKey {
			c.mu.Unlock()
			return
		}
		c.siblings[a.InstanceID] = a
		c.mu.Unlock()
		c.changed()
	case TypePresence:
		var p Presence
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
		if env.intoStrict(&req) != nil || req.RequestID == "" {
			return
		}
		// The read loop has to stay free for the next frame, possibly the
		// answer to a call of our own.
		go c.answer(ctx, conn, req)
	}
}

// answer runs one call and sends the result back. A frame that does not open
// gets no reply, since its sender holds the key but not the phrase, or the
// frame was rewritten, and a reply would only confirm the key. Neither does a
// call Serve drops. A call that opens with a broken signature is answered with
// the reason, since only a member can seal one.
func (c *Client) answer(ctx context.Context, conn *websocket.Conn, req ProxyRequest) {
	call, err := OpenCall(c.frameKey, c.signing, req.RequestID, c.id, req.Sealed)
	result := ProxyResult{Status: http.StatusNotImplemented}
	switch {
	case errors.Is(err, ErrSignature):
		result = ProxyResult{Status: http.StatusForbidden, Body: SignatureRefused}
	case err != nil:
		return
	case c.serve != nil:
		serveCtx, cancel := context.WithTimeout(ctx, proxyTimeout)
		if req.Sender != "" {
			serveCtx = WithSource(serveCtx, "relay\x00"+req.Sender)
		}
		result.Status, result.Body = c.serve(serveCtx, call)
		cancel()
		if result.Status == StatusDrop {
			return
		}
	}
	result = SignResult(c.signing, c.identity, req.RequestID, req.Sealed, result)
	sealed, err := SealResult(c.frameKey, req.RequestID, result)
	if err != nil {
		return
	}
	for _, part := range split(ProxyResponse{RequestID: req.RequestID, Sealed: sealed}, req.Framing) {
		if sendFrame(ctx, conn, frameOf(TypeProxyResponse, part), writeTimeout) != nil {
			return
		}
	}
}

// deliver hands a response, or a part of one, to the Proxy call waiting on
// it, or drops it. A broken answer in parts fails the call at once.
func (c *Client) deliver(resp ProxyResponse) {
	c.mu.Lock()
	w := c.pending[resp.RequestID]
	if w == nil {
		c.mu.Unlock()
		return
	}
	whole, done, err := w.take(resp)
	if done || err != nil {
		delete(c.pending, resp.RequestID)
	}
	c.mu.Unlock()
	switch {
	case err != nil:
		w.answer <- ProxyResponse{RequestID: resp.RequestID, Error: err.Error()}
	case done:
		w.answer <- whole
	default:
		select {
		case w.moved <- struct{}{}:
		default:
		}
	}
}

// connected publishes a live socket so Proxy can use it.
func (c *Client) connected(conn *websocket.Conn) {
	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()
	c.changed()
}

// disconnected clears the siblings, which exist only while the relay says so,
// and fails every call in flight at once instead of letting it time out.
func (c *Client) disconnected() {
	c.mu.Lock()
	c.conn = nil
	c.siblings = map[string]Announce{}
	calls := make([]*waiting, 0, len(c.pending))
	for id, w := range c.pending {
		calls = append(calls, w)
		delete(c.pending, id)
	}
	c.mu.Unlock()
	for _, w := range calls {
		w.answer <- ProxyResponse{
			Error: "the relay connection dropped before the answer arrived",
		}
	}
	c.changed()
}

// changed calls OnChange without the lock held, since the callback may call
// Siblings.
func (c *Client) changed() {
	if c.onChange != nil {
		c.onChange()
	}
}

// requestID is the token an answer is matched by. It is random rather than
// counted, since a counter would restart on reconnect and hand a late answer
// to whoever inherited the number.
func requestID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
