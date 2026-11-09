package group

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/keys"
	"github.com/junkerderprovinz/parleyport/kit/lan"
	"github.com/junkerderprovinz/parleyport/kit/member"
	"github.com/junkerderprovinz/parleyport/kit/relay"
)

// The direct route: members on one network call each other over HTTP at the
// address they announce. The call inside is the one the relay would carry,
// sealed and signed, and the request around it is tagged with the peer-auth
// key, so a stranger who reaches the route is turned away before the body is
// even read.

const (
	// maxDirectRequest caps a direct call as it arrives: MaxCallBytes with
	// the seal and two rounds of base64 around it.
	maxDirectRequest = 2 << 20
	// maxDirectAnswer caps the answer read back, which is maxAnswerBytes
	// wrapped the same way.
	maxDirectAnswer = 8 << 20
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
)

// probeTarget stands in for a member id on a call whose sender does not know
// who, if anyone, answers at an address: the sweep dials hosts with nothing
// but the phrase to go on. A probe only ever reaches the hello.
const probeTarget = "*"

// headers are the names of the request headers of a direct call, made from
// the domain so each app keeps the ones its instances already send.
type headers struct {
	peer, target, time, signature string
}

func headersFor(d keys.Domain) headers {
	name := func(s string) string { return http.CanonicalHeaderKey("X-" + string(d) + "-" + s) }
	return headers{peer: name("Peer"), target: name("Target"), time: name("Time"), signature: name("Signature")}
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

func recent(unix int64) bool {
	d := time.Since(time.Unix(unix, 0))
	return d <= relay.ClockSkew && d >= -relay.ClockSkew
}

func (g *Group) acceptAnnounce(p lan.Peer) bool {
	return recent(p.Sent) && hmac.Equal([]byte(p.Tag), []byte(announceTag(g.peerAuth, p)))
}

// announce tells the network what this instance goes by now.
func (g *Group) announce() {
	if g.lan == nil {
		return
	}
	g.lan.SetSelf(lan.Peer{ID: g.self, Name: g.info.Name, URL: g.directURL(), Deployment: g.info.Deployment, Address: g.info.Address},
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
	// The route is open, so whatever a stranger can send without the key is
	// checked before the body is read.
	h := g.headers
	sender, target, unix := r.Header.Get(h.peer), r.Header.Get(h.target), r.Header.Get(h.time)
	sent, err := strconv.ParseInt(unix, 10, 64)
	if err != nil || sender == "" || len(sender) > maxSenderBytes || (target != g.self && target != probeTarget) ||
		r.ContentLength > maxDirectRequest || !recent(sent) {
		forbid(w)
		return
	}
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	default:
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(directReadTimeout))
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxDirectRequest))
	if err != nil || !hmac.Equal([]byte(r.Header.Get(h.signature)), []byte(directSignature(g.peerAuth, sender, unix, body))) {
		forbid(w)
		return
	}
	var req relay.ProxyRequest
	if json.Unmarshal(body, &req) != nil || req.RequestID == "" || req.Target != target {
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
		source := r.RemoteAddr
		if host, _, err := net.SplitHostPort(source); err == nil {
			source = host
		}
		status, out = g.handle(relay.WithSource(r.Context(), "direct\x00"+source), call)
		if status == relay.StatusDrop {
			forbid(w)
			return
		}
	}
	result := relay.SignResult(g.signing, &g.identity, req.RequestID, req.Sealed, relay.ProxyResult{Status: status, Body: out})
	sealed, err := relay.SealResult(g.frameKey, req.RequestID, result)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(relay.ProxyResponse{RequestID: req.RequestID, Sealed: sealed})
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+DirectPath, bytes.NewReader(payload))
	if err != nil {
		return nil, nil, "", err
	}
	now := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(g.headers.peer, g.self)
	req.Header.Set(g.headers.target, target)
	req.Header.Set(g.headers.time, now)
	req.Header.Set(g.headers.signature, directSignature(g.peerAuth, g.self, now, payload))
	return req, sealed, id, nil
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
		return relay.ProxyResult{}, nil, "", fmt.Errorf("group: %s is not reachable directly: %w", target, err)
	}
	defer resp.Body.Close() //nolint:errcheck // nothing to do about a failed close of a read body
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxDirectAnswer))
	if err != nil {
		return relay.ProxyResult{}, nil, "", err
	}
	if resp.StatusCode != http.StatusOK {
		return relay.ProxyResult{}, nil, "", fmt.Errorf("group: %s refused the direct call with HTTP %d", target, resp.StatusCode)
	}
	var out relay.ProxyResponse
	if err := json.Unmarshal(raw, &out); err != nil || out.RequestID != id {
		return relay.ProxyResult{}, nil, "", fmt.Errorf("group: %s answered unreadably", target)
	}
	res, err := relay.OpenResult(g.frameKey, id, out.Sealed)
	if err != nil {
		return relay.ProxyResult{}, nil, "", fmt.Errorf("group: %s answered unreadably: %w", target, err)
	}
	return res, sealed, id, nil
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

// probe asks whoever answers at base who it is, and records it as reachable
// there when a member of the group answered under its own key.
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
	if res.Status != http.StatusOK || json.Unmarshal(res.Body, &h) != nil || !relay.ValidInstanceID(h.ID) || h.ID == g.self ||
		!relay.VerifyResult(g.signing, id, h.ID, sealed, res) {
		return hello{}, fmt.Errorf("group: %s answered a probe unreadably", base)
	}
	g.confirm(h.ID, base, h.Name, h.Deployment, time.Now())
	return h, nil
}

// probeBack probes a prober at the address it named. Only a member not yet
// reachable is probed back, so two instances stop after one round instead of
// probing each other for ever.
func (g *Group) probeBack(call relay.ProxyCall) {
	var in probeIntro
	if call.Kind != member.KindInstance || !claimFits(call.From, call.Kind, call.Key) || json.Unmarshal(call.Body, &in) != nil {
		return
	}
	u, err := url.Parse(strings.TrimSpace(in.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || g.confirmedDirect(call.From, time.Now()) {
		return
	}
	g.noteAddress(call.From, u.String())
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
		_, _ = g.probe(ctx, u.String())
	}()
}
