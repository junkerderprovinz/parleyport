package group

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/keys"
	"github.com/junkerderprovinz/parleyport/kit/lan"
	"github.com/junkerderprovinz/parleyport/kit/member"
	"github.com/junkerderprovinz/parleyport/kit/relay"
	"golang.org/x/net/netutil"
)

// The direct route: members on one network call each other over HTTP at the
// address they announce. The call inside is the one the relay would carry,
// sealed and signed, and the request around it is tagged with the peer-auth
// key, its headers apart as well, so a stranger who reaches the route is
// turned away before the body is even read. A call without that head tag,
// from an older release, is still taken, but read in a small pool of its own.

const (
	// maxDirectRequest caps a direct call as it arrives: MaxCallBytes with
	// the seal and two rounds of base64 around it.
	maxDirectRequest = 2 << 20
	// directSource starts the source of a call that came directly, as
	// relay.SourceOf tells it.
	directSource = "direct\x00"
	// maxDirectCalls is how many direct calls are served at once.
	maxDirectCalls = 16
	// maxProbeBacks is how many probes back to a prober run at once.
	maxProbeBacks = 4
	// maxSenderBytes bounds the sender header before anything is checked.
	maxSenderBytes = 128
	// callTimeout bounds one call to a member.
	callTimeout = 15 * time.Second
	// directDialTimeout bounds connecting to a member's direct address, and
	// apart from that the TLS handshake. A LAN connects in milliseconds, and
	// five seconds still covers one lost SYN and a slow name lookup.
	directDialTimeout = 5 * time.Second
	// directReadTimeout bounds how long a call's body may take to arrive, so
	// a stranger sending slowly holds a connection no longer than that.
	directReadTimeout = 10 * time.Second
	// maxUntaggedCalls and maxUntaggedFromSource bound the calls without a
	// head tag that are read at once, in all and from one address.
	maxUntaggedCalls      = 4
	maxUntaggedFromSource = 2
	// directHeaderTimeout and maxDirectHeaderBytes bound the headers of a
	// request at a port ServeDirect answers on. An upload's call travels in
	// them.
	directHeaderTimeout  = 3 * time.Second
	maxDirectHeaderBytes = 64 << 10
	// maxHeadsKept bounds the head tags kept to tell a played back one.
	maxHeadsKept = 4096
)

// directIdle is how long ServeDirect keeps a connection open with no request
// on it, maxDirectConns how many it holds at once and maxConnsFromSource how
// many of them from one address.
var (
	directIdle         = time.Minute
	maxDirectConns     = 64
	maxConnsFromSource = 4
)

// probeTarget stands in for a member id on a call whose sender does not know
// who, if anyone, answers at an address: the sweep dials hosts with nothing
// but the phrase to go on. A probe only ever reaches the hello.
const probeTarget = "*"

// headers are the names of the request headers of a direct call, made from
// the domain so each app keeps the ones its instances already send.
type headers struct {
	peer, target, time, signature string
	// call carries the call of an upload, whose body is the upload.
	call    string
	head    string
	request string
}

func headersFor(d keys.Domain) headers {
	name := func(s string) string { return http.CanonicalHeaderKey("X-" + string(d) + "-" + s) }
	return headers{peer: name("Peer"), target: name("Target"), time: name("Time"), signature: name("Signature"), call: name("Call"), head: name("Head"), request: name("Request")}
}

// announceTag signs everything an announce claims, its time included, so a
// device on the network can neither point members at an address of its
// choosing nor keep a departed member listed by playing its announces back.
func announceTag(peerAuth []byte, p lan.Peer) string {
	mac := hmac.New(sha256.New, peerAuth)
	mac.Write([]byte("announce\x00" + p.ID + "\x00" + p.URL + "\x00" + p.Name + "\x00" + p.Deployment + "\x00" + p.Address + "\x00" + strconv.FormatInt(p.Sent, 10)))
	return hex.EncodeToString(mac.Sum(nil))
}

// directSignature binds a direct call's sender, time and exact body to the
// peer-auth key.
func directSignature(peerAuth []byte, sender, unix string, body []byte) string {
	sum := sha256.Sum256(body)
	mac := hmac.New(sha256.New, peerAuth)
	mac.Write([]byte("direct\x00" + sender + "\x00" + unix + "\x00" + hex.EncodeToString(sum[:])))
	return hex.EncodeToString(mac.Sum(nil))
}

// headSignature binds what a direct call's headers say, its request and
// length included, to the peer-auth key, so the call can be told from a
// stranger's before its body arrives.
func headSignature(peerAuth []byte, sender, target, unix, request string, length int64) string {
	mac := hmac.New(sha256.New, peerAuth)
	mac.Write([]byte("direct-head\x00" + sender + "\x00" + target + "\x00" + unix + "\x00" + request + "\x00" + strconv.FormatInt(length, 10)))
	return hex.EncodeToString(mac.Sum(nil))
}

func recent(unix int64) bool {
	d := time.Since(time.Unix(unix, 0))
	return d <= relay.ClockSkew && d >= -relay.ClockSkew
}

// acceptAnnounce takes an announce tagged under the group's key, and looks
// around at once when it comes from a member the network did not show for a
// while. It runs under the lock of the lan.Service, which g.mu always nests in.
func (g *Group) acceptAnnounce(p lan.Peer) bool {
	if !recent(p.Sent) || !hmac.Equal([]byte(p.Tag), []byte(announceTag(g.peerAuth, p))) {
		return false
	}
	now := time.Now()
	g.mu.Lock()
	last, known := g.arrived[p.ID]
	arrives := !known || now.Sub(last) >= addrTTL
	if known || len(g.arrived) < maxArrivals {
		g.arrived[p.ID] = now
	} else {
		arrives = false
	}
	g.mu.Unlock()
	if arrives {
		g.poke()
	}
	return true
}

// announce tells the network what this instance goes by now.
func (g *Group) announce() {
	if g.lan == nil {
		return
	}
	info := g.selfInfo()
	g.lan.SetSelf(lan.Peer{ID: g.self, Name: info.Name, URL: g.directURL(), Deployment: info.Deployment, Address: info.Address},
		func(p lan.Peer) string { return announceTag(g.peerAuth, p) })
}

// directURL is where this instance takes direct calls: the address learned
// from a browser, else the one the app gave.
func (g *Group) directURL() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.st.Address != "" {
		return g.st.Address
	}
	return g.info.DirectURL
}

// NoteAddress learns this instance's direct address from a request a
// signed-in user made, since from inside a container nothing else tells the
// address the host is reached at. The address goes out on the network at
// once and is kept. An app whose owner set the address by hand does not call
// it.
func (g *Group) NoteAddress(r *http.Request) {
	addr := relay.FitAddress(lan.AddressOf(r))
	if addr == "" {
		return
	}
	g.mu.Lock()
	if g.st.Address == addr {
		g.mu.Unlock()
		return
	}
	g.st.Address = addr
	if g.saveLocked() != nil {
		g.dirty = true
	}
	g.mu.Unlock()
	g.announce()
}

// DirectHandler answers members' direct calls at DirectPath. A call that is
// unsigned, stale, addressed to another instance or does not open is refused
// without saying which, since the reason would only help a guesser.
func (g *Group) DirectHandler() http.Handler {
	return http.HandlerFunc(g.serveDirect)
}

func forbid(w http.ResponseWriter) {
	http.Error(w, "forbidden", http.StatusForbidden)
}

// envelope is what a direct request says about itself in its headers.
type envelope struct {
	sender, target, unix, signature string
	// upload means the call travels in a header and the body is the upload.
	upload  bool
	call    string
	head    string
	request string
}

// envelopeOf reads the headers of a direct request to this instance, and
// reports false where they cannot be a member's. The route is open, so
// whatever a stranger can send without the key is checked before the body is
// read.
func (g *Group) envelopeOf(r *http.Request) (envelope, bool) {
	h := g.headers
	e := envelope{
		sender: r.Header.Get(h.peer), target: r.Header.Get(h.target), unix: r.Header.Get(h.time),
		signature: r.Header.Get(h.signature), upload: r.Header.Get("Content-Type") == uploadType, call: r.Header.Get(h.call),
		head: r.Header.Get(h.head), request: r.Header.Get(h.request),
	}
	sent, err := strconv.ParseInt(e.unix, 10, 64)
	ok := err == nil && e.sender != "" && len(e.sender) <= maxSenderBytes && (e.target == g.self || e.target == probeTarget) &&
		(e.upload || r.ContentLength <= maxDirectRequest) && recent(sent)
	return e, ok
}

// signed reads what the signature of e covers: the call of an upload, else
// the body, which the request gives up to.
func (e envelope) signed(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	if e.upload {
		// The body of an upload is read by the app, once it wants it.
		return base64.StdEncoding.DecodeString(e.call)
	}
	return io.ReadAll(http.MaxBytesReader(w, r.Body, maxDirectRequest))
}

// tags reports whether body is signed under peerAuth as e says.
func (e envelope) tags(peerAuth, body []byte) bool {
	return hmac.Equal([]byte(e.signature), []byte(directSignature(peerAuth, e.sender, e.unix, body)))
}

// sent is the time the call e describes says it was sent at.
func (e envelope) sent() time.Time {
	unix, _ := strconv.ParseInt(e.unix, 10, 64)
	return time.Unix(unix, 0)
}

// tagged reports whether the headers of the call e describes, length long,
// are tagged under peerAuth: an upload's call, which travels in them, or the
// head tag of any other.
func (e envelope) tagged(peerAuth []byte, length int64) bool {
	if e.upload {
		call, err := base64.StdEncoding.DecodeString(e.call)
		return err == nil && e.tags(peerAuth, call)
	}
	return e.head != "" && length >= 0 &&
		e.request != "" && hmac.Equal([]byte(e.head), []byte(headSignature(peerAuth, e.sender, e.target, e.unix, e.request, length)))
}

// untagged bounds the calls without a head tag that are read at once, in
// all and from each address.
type untagged struct {
	mu   sync.Mutex
	all  int
	from map[string]int
}

func (u *untagged) enter(source string) (leave func(), ok bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.all >= maxUntaggedCalls || u.from[source] >= maxUntaggedFromSource {
		return nil, false
	}
	if u.from == nil {
		u.from = map[string]int{}
	}
	u.all++
	u.from[source]++
	return func() {
		u.mu.Lock()
		defer u.mu.Unlock()
		u.all--
		if u.from[source]--; u.from[source] == 0 {
			delete(u.from, source)
		}
	}, true
}

// heads keeps the head tags taken lately, so a tag played back holds no slot
// while its body never comes. A tag is good until relay.ClockSkew after the
// time it carries, and a full cache makes room by dropping the one that runs
// out first, so filling it shuts nobody out.
type heads struct {
	mu    sync.Mutex
	until map[string]time.Time
}

// first records key, the sender and request of a head tag sent at sent, and
// reports whether it was not taken before.
func (h *heads) first(key string, sent, now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.until[key]; ok {
		return false
	}
	if h.until == nil {
		h.until = map[string]time.Time{}
	}
	soonest := ""
	for k, until := range h.until {
		if now.After(until) {
			delete(h.until, k)
		} else if soonest == "" || until.Before(h.until[soonest]) {
			soonest = k
		}
	}
	if len(h.until) >= maxHeadsKept {
		delete(h.until, soonest)
	}
	h.until[key] = sent.Add(relay.ClockSkew)
	return true
}

// fromSource holds at most maxConnsFromSource connections from one address,
// so one host cannot keep the members out with half sent requests.
type fromSource struct {
	net.Listener
	mu sync.Mutex
	n  map[string]int
}

func (l *fromSource) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		host := c.RemoteAddr().String()
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		l.mu.Lock()
		if l.n[host] >= maxConnsFromSource {
			l.mu.Unlock()
			_ = c.Close()
			continue
		}
		l.n[host]++
		l.mu.Unlock()
		return &sourceConn{Conn: c, leave: func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			if l.n[host]--; l.n[host] == 0 {
				delete(l.n, host)
			}
		}}, nil
	}
}

type sourceConn struct {
	net.Conn
	once  sync.Once
	leave func()
}

func (c *sourceConn) Close() error {
	c.once.Do(c.leave)
	return c.Conn.Close()
}

// sourceOf is the address a direct call came from.
func sourceOf(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func busy(w http.ResponseWriter) {
	http.Error(w, "busy", http.StatusServiceUnavailable)
}

// Direct answers at DirectPath the direct calls of several groups this
// instance is in, such as an app's group on its old phrase and the one it
// moves to, which go by the same domain and so send the same headers. Each
// call goes to the group whose key it is tagged with; one tagged with none is
// refused as a single group would refuse it.
func Direct(groups ...*Group) http.Handler {
	var gs []*Group
	for _, g := range groups {
		if g != nil {
			gs = append(gs, g)
		}
	}
	switch len(gs) {
	case 0:
		return http.NotFoundHandler()
	case 1:
		return gs[0].DirectHandler()
	}
	var pool untagged
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		type fit struct {
			g *Group
			e envelope
		}
		var fits []fit
		for _, g := range gs {
			if e, ok := g.envelopeOf(r); ok && r.Method == http.MethodPost {
				fits = append(fits, fit{g, e})
			}
		}
		switch len(fits) {
		case 0:
			gs[0].serveDirect(w, r)
			return
		case 1:
			fits[0].g.serveDirect(w, r)
			return
		}
		// Only the tags tell the groups apart: those over the headers before
		// anything is read, else the one over the body, which is read once
		// here and handed on.
		if e := fits[0].e; e.upload || e.head != "" {
			for _, f := range fits {
				if f.e.tagged(f.g.peerAuth, r.ContentLength) {
					f.g.serveDirect(w, r)
					return
				}
			}
			forbid(w)
			return
		}
		leave, ok := pool.enter(sourceOf(r))
		if !ok {
			busy(w)
			return
		}
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(directReadTimeout))
		body, err := fits[0].e.signed(w, r)
		leave()
		if err != nil {
			forbid(w)
			return
		}
		for _, f := range fits {
			if f.e.tags(f.g.peerAuth, body) {
				r.Body = io.NopCloser(bytes.NewReader(body))
				f.g.serveDirect(w, r)
				return
			}
		}
		forbid(w)
	})
}

// receive reads the call e describes and holds one of the group's slots for
// it, which the caller gives back. A call with tagged headers takes its slot
// before anything is read. Any other is read in the small pool first and
// takes a slot once its tag holds, so a stranger that sends slowly keeps no
// member waiting. It answers the call itself when it returns false.
func (g *Group) receive(w http.ResponseWriter, r *http.Request, e envelope) ([]byte, bool) {
	tagged := e.tagged(g.peerAuth, r.ContentLength)
	if !tagged && (e.upload || e.head != "") {
		forbid(w)
		return nil, false
	}
	leave := func() {}
	if tagged && !e.upload && !g.heads.first(e.sender+"\x00"+e.request, e.sent(), time.Now()) {
		forbid(w)
		return nil, false
	}
	if tagged {
		if !g.take() {
			busy(w)
			return nil, false
		}
	} else {
		var ok bool
		if leave, ok = g.untagged.enter(sourceOf(r)); !ok {
			busy(w)
			return nil, false
		}
	}
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(directReadTimeout))
	body, err := e.signed(w, r)
	leave()
	switch {
	case err != nil || !e.tags(g.peerAuth, body):
		if tagged {
			<-g.slots
		}
		forbid(w)
		return nil, false
	case !tagged && !g.take():
		busy(w)
		return nil, false
	}
	return body, true
}

func (g *Group) take() bool {
	select {
	case g.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

// ServeDirect answers the direct calls h takes, Direct's or a group's
// DirectHandler, at ln and nothing else, for a member with a port of its own
// for them, such as a plugin. It holds a bounded number of connections, lets
// go of slow and idle ones, and logs nothing, since its errors name the
// caller's address. Closing the server stops it.
func ServeDirect(ln net.Listener, h http.Handler) *http.Server {
	mux := http.NewServeMux()
	mux.Handle(DirectPath, h)
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: directHeaderTimeout,
		ReadTimeout:       directHeaderTimeout + directReadTimeout,
		IdleTimeout:       directIdle,
		MaxHeaderBytes:    maxDirectHeaderBytes,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	go func() {
		_ = srv.Serve(netutil.LimitListener(&fromSource{Listener: ln, n: map[string]int{}}, maxDirectConns))
	}()
	return srv
}

func (g *Group) serveDirect(w http.ResponseWriter, r *http.Request) {
	if !g.enter() {
		http.NotFound(w, r)
		return
	}
	defer g.wg.Done()
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	e, ok := g.envelopeOf(r)
	if !ok {
		forbid(w)
		return
	}
	body, ok := g.receive(w, r, e)
	if !ok {
		return
	}
	defer func() { <-g.slots }()
	target, upload := e.target, e.upload
	var req relay.ProxyRequest
	if json.Unmarshal(body, &req) != nil || req.RequestID == "" || req.Target != target || e.head != "" && req.RequestID != e.request {
		forbid(w)
		return
	}
	call, err := relay.OpenCall(g.frameKey, g.signing, req.RequestID, target, req.Sealed)
	var status int
	var out []byte
	switch {
	case errors.Is(err, relay.ErrSignature):
		status, out = http.StatusForbidden, relay.SignatureRefused
	case err != nil:
		forbid(w)
		return
	case target == probeTarget:
		if call.Path != helloPath || !relay.Recent(call, time.Now()) {
			forbid(w)
			return
		}
		g.probeBack(call)
		status, out = http.StatusOK, g.hello()
	default:
		ctx := relay.WithSource(r.Context(), directSource+sourceOf(r))
		if upload {
			if !strings.HasPrefix(call.Path, uploadPrefix) {
				forbid(w)
				return
			}
			g.serveUpload(ctx, w, r, req, call)
			return
		}
		if strings.HasPrefix(call.Path, streamPrefix) {
			g.serveStream(ctx, w, req, call)
			return
		}
		status, out = g.handle(ctx, call)
		if status == relay.StatusDrop {
			forbid(w)
			return
		}
	}
	g.answer(w, req, status, out)
}

// answer sends status and body as this instance's signed answer to req.
func (g *Group) answer(w http.ResponseWriter, req relay.ProxyRequest, status int, body []byte) {
	resp, err := g.response(req, status, body)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// response is status and body sealed and signed as the answer to req.
func (g *Group) response(req relay.ProxyRequest, status int, body []byte) (relay.ProxyResponse, error) {
	result := relay.SignResult(g.signing, &g.identity, req.RequestID, req.Sealed, relay.ProxyResult{Status: status, Body: body})
	sealed, err := relay.SealResult(g.frameKey, req.RequestID, result)
	return relay.ProxyResponse{RequestID: req.RequestID, Sealed: sealed}, err
}

func requestID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// newDirectRequest seals and signs call for target and wraps it in the request
// to its direct address base.
func (g *Group) newDirectRequest(ctx context.Context, base, target string, call relay.ProxyCall) (*http.Request, []byte, string, error) {
	id, err := requestID()
	if err != nil {
		return nil, nil, "", err
	}
	sealed, err := relay.SealSignedCall(g.frameKey, g.signing, &g.identity, id, target, call)
	if err != nil {
		return nil, nil, "", err
	}
	payload, err := json.Marshal(relay.ProxyRequest{RequestID: id, Target: target, Sealed: sealed})
	if err != nil {
		return nil, nil, "", err
	}
	endpoint, err := directEndpoint(base)
	if err != nil {
		return nil, nil, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, nil, "", err
	}
	now := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(g.headers.peer, g.self)
	req.Header.Set(g.headers.target, target)
	req.Header.Set(g.headers.time, now)
	req.Header.Set(g.headers.signature, directSignature(g.peerAuth, g.self, now, payload))
	req.Header.Set(g.headers.request, id)
	req.Header.Set(g.headers.head, headSignature(g.peerAuth, g.self, target, now, id, int64(len(payload))))
	return req, sealed, id, nil
}

// directEndpoint is where the member at base takes direct calls. A query or
// fragment in an address a phrase holder announces would swallow DirectPath
// and send the call wherever the address points, so only the path counts.
func directEndpoint(base string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimRight(u.Path, "/") + DirectPath
	u.RawPath, u.RawQuery, u.Fragment, u.ForceQuery = "", "", "", false
	return u.String(), nil
}

// directRefusal is the error for a direct call that base answered with status
// instead of 200. A group refuses whatever is not tagged with its key with 403,
// and a closed one, like an address without a group, with 404.
func directRefusal(base string, status int) error {
	switch status {
	case http.StatusServiceUnavailable:
		return fmt.Errorf("%w directly at %s: it is busy", ErrUnreachable, base)
	case http.StatusForbidden, http.StatusNotFound:
		return fmt.Errorf("%w: %s refused the direct call with HTTP %d", ErrStranger, base, status)
	}
	return &StatusError{Address: base, Status: status}
}

// exchange makes one direct call and opens the answer, without asking yet
// whose key signed it.
func (g *Group) exchange(ctx context.Context, base, target string, call relay.ProxyCall) (relay.ProxyResult, []byte, string, error) {
	req, sealed, id, err := g.newDirectRequest(ctx, base, target, call)
	if err != nil {
		return relay.ProxyResult{}, nil, "", err
	}
	resp, err := g.hc.Do(req)
	if err != nil {
		return relay.ProxyResult{}, nil, "", fmt.Errorf("%w directly at %s: %w", ErrUnreachable, base, err)
	}
	defer resp.Body.Close() //nolint:errcheck // nothing to do about a failed close of a read body
	// The answer comes sealed, with two rounds of base64 around it, which
	// make it 16/9 as large.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, int64(2*g.maxAnswer+64<<10)))
	switch {
	case err != nil:
		return relay.ProxyResult{}, nil, "", fmt.Errorf("%w directly at %s: %w", ErrUnreachable, base, err)
	case resp.StatusCode != http.StatusOK:
		return relay.ProxyResult{}, nil, "", directRefusal(base, resp.StatusCode)
	}
	res, err := g.openResponse(raw, id, base)
	if err != nil {
		return relay.ProxyResult{}, nil, "", err
	}
	return res, sealed, id, nil
}

// openResponse opens raw as the answer to request id from base, without
// asking yet whose key signed it.
func (g *Group) openResponse(raw []byte, id, base string) (relay.ProxyResult, error) {
	var out relay.ProxyResponse
	if err := json.Unmarshal(raw, &out); err != nil || out.RequestID != id {
		return relay.ProxyResult{}, fmt.Errorf("%w: %s answered unreadably", ErrStranger, base)
	}
	res, err := relay.OpenResult(g.frameKey, id, out.Sealed)
	if err != nil {
		return relay.ProxyResult{}, fmt.Errorf("%w: %s answered unreadably: %w", ErrStranger, base, err)
	}
	return res, nil
}

// callDirect calls target at base and returns its answer once the key target's
// id is made from signed it.
func (g *Group) callDirect(ctx context.Context, base, target string, call relay.ProxyCall) (relay.ProxyResult, error) {
	res, sealed, id, err := g.exchange(ctx, base, target, call)
	if err != nil {
		return res, err
	}
	if !relay.VerifyResult(g.signing, id, target, sealed, res) {
		return relay.ProxyResult{}, fmt.Errorf("group: %s's answer is not signed by its key", target)
	}
	return res, nil
}

// probeIntro is what a probe tells the member it reaches: where the prober
// takes direct calls, so the two know each other after one probe.
type probeIntro struct {
	URL string `json:"url,omitempty"`
}

// probe asks whoever answers at base who it is. A member of the group that
// answers under its own key is pinned by that answer and recorded as
// reachable there.
func (g *Group) probe(ctx context.Context, base string) (hello, error) {
	intro, err := json.Marshal(probeIntro{URL: g.directURL()})
	if err != nil {
		return hello{}, err
	}
	res, sealed, id, err := g.exchange(ctx, base, probeTarget, relay.ProxyCall{Method: http.MethodGet, Path: helloPath, Body: intro})
	if err != nil {
		return hello{}, err
	}
	var h hello
	if res.Status != http.StatusOK || json.Unmarshal(res.Body, &h) != nil || !relay.ValidInstanceID(h.ID) ||
		!relay.VerifyResult(g.signing, id, h.ID, sealed, res) {
		return hello{}, fmt.Errorf("%w: %s answered a probe unreadably", ErrStranger, base)
	}
	if h.ID == g.self {
		return hello{}, fmt.Errorf("group: %s is this instance's own address", base)
	}
	vouched := g.vouched(h.ID, member.KindInstance, res.Key)
	if g.asks(h.ID, vouched) && !g.mayJoin(ctx, h.ID) {
		return hello{}, fmt.Errorf("%w: %s is not taken in", ErrStranger, base)
	}
	g.mu.Lock()
	if _, pinned := g.st.Members[h.ID]; !pinned {
		g.pinAnswerLocked(h.ID, res.Key, vouched)
	}
	g.mu.Unlock()
	g.confirm(h.ID, base, h.Name, h.Deployment, time.Now())
	return h, nil
}

// probeBack probes a prober at the address it named, if that address is
// nearby. Only a member not yet reachable is probed back, so two instances
// stop after one round instead of probing each other for ever.
func (g *Group) probeBack(call relay.ProxyCall) {
	var in probeIntro
	if call.Kind != member.KindInstance || !claimFits(call.From, call.Kind, call.Key) || json.Unmarshal(call.Body, &in) != nil {
		return
	}
	base, ok := g.nearby(in.URL)
	if !ok || g.confirmedDirect(call.From, time.Now()) {
		return
	}
	g.noteAddress(call.From, base)
	if !g.enter() {
		return
	}
	select {
	case g.probing <- struct{}{}:
	default:
		g.wg.Done()
		return
	}
	go func() {
		defer g.wg.Done()
		defer func() { <-g.probing }()
		ctx, cancel := context.WithTimeout(g.ctx, 2*sweepTimeout)
		defer cancel()
		_, _ = g.probe(ctx, base)
	}()
}
