package fortress

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/junkerderprovinz/parleyport/kit/group"
)

// A live stream of an opened page, a websocket or an event stream, does not
// fit into one call. The opened app runs it in this process and keeps what it
// sends. The opening member asks for what came on all streams of one sign-in
// with one call at a time and asks again as soon as the answer came, so that
// a page with many sockets does not use up the calls a member may have under
// way. Messages from the browser go over as calls of their own.
const (
	uiStreamPath = prefix + "ui/stream"

	// pollFor is how long an ask for more waits for something to arrive,
	// well inside the relay's silence limit.
	pollFor = 10 * time.Second
	// streamIdle ends a stream nobody asked about for that long.
	streamIdle = 30 * time.Second
	// A stream holds what fits into half an answer for the opening member,
	// at least minStreamBytes and at most maxStreamBytes, and so does one
	// message; a stream that falls further behind ends and the browser
	// connects anew.
	minStreamBytes = 256 << 10
	maxStreamBytes = 4 << 20
	// maxStreamsPerCaller and maxStreams bound the streams the opened app
	// runs for one member and in all, maxTabStreams those of one tab. Some
	// pages open a socket for every part of the screen.
	maxStreamsPerCaller = 64
	maxStreams          = 128
	maxTabStreams       = 32
	// maxSends bounds the messages from browsers on their way to members at
	// once, so that a page opening many sockets does not run into the calls
	// a member takes from one caller.
	maxSends = 4
	// tabCheck is how often a stream looks whether its tab still stands.
	tabCheck = time.Second
	// maxBacklog is how many answers a stream may fall behind its browser.
	maxBacklog = 32
	// startFor is how long the opened app may take to answer a new stream.
	startFor = 10 * time.Second
)

type streamOp struct {
	Op     string `json:"op"`
	Stream string `json:"stream,omitempty"`
	Socket bool   `json:"socket,omitempty"`
	Ask    *uiAsk `json:"ask,omitempty"`
	Binary bool   `json:"binary,omitempty"`
	Jar    string `json:"jar,omitempty"`
}

type streamMsg struct {
	Binary bool   `json:"binary,omitempty"`
	Data   []byte `json:"data"`
}

type streamAnswer struct {
	Stream string      `json:"stream,omitempty"`
	Status int         `json:"status,omitempty"`
	Header http.Header `json:"header,omitempty"`
	Done   bool        `json:"done,omitempty"`
	// Batch is what came on each stream of a sign-in, by stream.
	Batch map[string]streamBatch `json:"batch,omitempty"`
}

type streamBatch struct {
	Messages []streamMsg `json:"messages,omitempty"`
	Done     bool        `json:"done,omitempty"`
}

// stream is one live stream the opened app runs for a member.
type stream struct {
	caller string
	jar    string
	limit  int
	owner  *streams
	cancel context.CancelFunc
	send   func(ctx context.Context, binary bool, data []byte) error

	mu     sync.Mutex
	queue  []streamMsg
	queued int
	done   bool
	used   time.Time
}

func (s *stream) push(m streamMsg) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return
	}
	if s.queued+len(m.Data) > s.limit {
		s.done = true
		s.cancel()
	} else {
		s.queue = append(s.queue, m)
		s.queued += len(m.Data)
	}
	s.wake()
}

func (s *stream) end() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.done = true
	s.wake()
}

func (s *stream) wake() { s.owner.signal(s.caller) }

func (s *stream) touch() {
	s.mu.Lock()
	s.used = time.Now()
	s.mu.Unlock()
}

// drain takes what came, budget bytes at most but at least one message, and
// whether the stream ended with it.
func (s *stream) drain(budget int) ([]streamMsg, bool, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.used = time.Now()
	n, size := 0, 0
	for n < len(s.queue) && (n == 0 || size+len(s.queue[n].Data) <= budget) {
		size += len(s.queue[n].Data)
		n++
	}
	out := s.queue[:n:n]
	s.queue, s.queued = s.queue[n:], s.queued-size
	return out, s.done && len(s.queue) == 0, size
}

type streams struct {
	mu   sync.Mutex
	byID map[string]*stream
	// sig is closed and replaced when a stream of a caller has news.
	sigMu sync.Mutex
	sig   map[string]chan struct{}
}

func (ss *streams) signal(caller string) {
	ss.sigMu.Lock()
	defer ss.sigMu.Unlock()
	if ch, ok := ss.sig[caller]; ok {
		close(ch)
		delete(ss.sig, caller)
	}
}

func (ss *streams) news(caller string) <-chan struct{} {
	ss.sigMu.Lock()
	defer ss.sigMu.Unlock()
	if ss.sig == nil {
		ss.sig = map[string]chan struct{}{}
	}
	ch, ok := ss.sig[caller]
	if !ok {
		ch = make(chan struct{})
		ss.sig[caller] = ch
	}
	return ch
}

// ofJar lists the streams of caller under one sign-in, by id.
func (ss *streams) ofJar(caller, jar string) map[string]*stream {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	out := map[string]*stream{}
	for id, s := range ss.byID {
		if s.caller == caller && s.jar == jar {
			out[id] = s
		}
	}
	return out
}

func (ss *streams) add(s *stream) (string, bool) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", false
	}
	id := hex.EncodeToString(raw)
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.sweepLocked(time.Now())
	n := 0
	for _, o := range ss.byID {
		if o.caller == s.caller {
			n++
		}
	}
	if n >= maxStreamsPerCaller || len(ss.byID) >= maxStreams {
		return "", false
	}
	if ss.byID == nil {
		ss.byID = map[string]*stream{}
	}
	ss.byID[id] = s
	return id, true
}

func (ss *streams) sweepLocked(now time.Time) {
	for id, s := range ss.byID {
		s.mu.Lock()
		gone := s.done && len(s.queue) == 0 || now.Sub(s.used) > streamIdle
		s.mu.Unlock()
		if gone {
			s.cancel()
			delete(ss.byID, id)
		}
	}
}

func (ss *streams) get(id, caller string) *stream {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.sweepLocked(time.Now())
	s := ss.byID[id]
	if s == nil || s.caller != caller {
		return nil
	}
	return s
}

func (ss *streams) end(id string) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if s := ss.byID[id]; s != nil {
		s.cancel()
		delete(ss.byID, id)
	}
}

// drop ends every stream of caller.
func (ss *streams) drop(caller string) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	for id, s := range ss.byID {
		if s.caller == caller {
			s.cancel()
			s.end()
			delete(ss.byID, id)
		}
	}
}

func (ss *streams) closeAll() {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	for id, s := range ss.byID {
		s.cancel()
		delete(ss.byID, id)
	}
}

func (ss *streams) count(caller string) int {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	n := 0
	for _, s := range ss.byID {
		if s.caller == caller {
			n++
		}
	}
	return n
}

// serveStream answers one step of a live stream of a page member caller
// opened: starting it, asking for what came, sending to it or ending it.
func (f *Fortress) serveStream(w http.ResponseWriter, r *http.Request, caller string) {
	if f.ui == nil {
		writeError(w, http.StatusNotFound, "no_such_action")
		return
	}
	from, ok := f.allowed(w, r, caller, OpenAction)
	if !ok {
		f.dropCaller(caller)
		return
	}
	if !f.ui.SignIn() {
		f.dropCaller(caller)
		writeError(w, http.StatusForbidden, "ui_no_login")
		return
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	var op streamOp
	data, err := unframe(raw, &op)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	switch op.Op {
	case "open":
		f.startStream(w, op, from)
		return
	case "poll":
		writeJSON(w, streamAnswer{Batch: f.pollStreams(r.Context(), caller, op.Jar)})
		return
	}
	s := f.streams.get(op.Stream, caller)
	if s == nil {
		writeJSON(w, streamAnswer{Done: true})
		return
	}
	switch op.Op {
	case "send":
		if s.send == nil || s.send(r.Context(), op.Binary, data) != nil {
			f.streams.end(op.Stream)
			writeJSON(w, streamAnswer{Done: true})
			return
		}
		writeJSON(w, streamAnswer{})
	case "close":
		f.streams.end(op.Stream)
		writeJSON(w, streamAnswer{Done: true})
	default:
		writeError(w, http.StatusBadRequest, "bad_request")
	}
}

// pollStreams waits until a stream of caller under jar has news, at most
// pollFor, and hands over what came on each, half an answer in all.
func (f *Fortress) pollStreams(ctx context.Context, caller, jar string) map[string]streamBatch {
	t := time.NewTimer(pollFor)
	defer t.Stop()
	for {
		news := f.streams.news(caller)
		out := map[string]streamBatch{}
		budget := f.streamLimit()
		for id, s := range f.streams.ofJar(caller, jar) {
			if budget <= 0 {
				s.touch()
				continue
			}
			msgs, done, size := s.drain(budget)
			if len(msgs) > 0 || done {
				out[id] = streamBatch{Messages: msgs, Done: done}
				budget -= size
			}
		}
		if len(out) > 0 {
			return out
		}
		select {
		case <-news:
		case <-t.C:
			return out
		case <-ctx.Done():
			return out
		}
	}
}

// streamLimit is what one stream holds and one answer about streams carries.
func (f *Fortress) streamLimit() int {
	return min(max(f.uiLimit/2, minStreamBytes), maxStreamBytes)
}

func (f *Fortress) dropCaller(caller string) {
	f.jars.drop(caller)
	f.streams.drop(caller)
}

// startStream runs the request op asks for as a live stream at the app's own
// handler and answers its first word: the status, and the stream to ask for
// more.
func (f *Fortress) startStream(w http.ResponseWriter, op streamOp, from Caller) {
	q := op.Ask
	if q == nil || q.Method != http.MethodGet || !jarPattern.MatchString(q.Jar) || !prefixPattern.MatchString(q.Prefix) {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	u, good := target(q.Target)
	if !good {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	j, fresh, ok := f.jars.take(from.ID, q.Jar, time.Now())
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "jars_full")
		return
	}
	if fresh {
		f.ui.Opened(from)
	}
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), openedKey{}, from))
	s := &stream{caller: from.ID, jar: q.Jar, limit: f.streamLimit(), owner: &f.streams, cancel: cancel, used: time.Now()}
	id, ok := f.streams.add(s)
	if !ok {
		cancel()
		writeError(w, http.StatusServiceUnavailable, "busy")
		return
	}
	header := only(q.Header, headersIn)
	header.Del("Accept-Encoding")
	header.Set("X-Forwarded-Prefix", q.Prefix)
	cookies := f.jars.cookies(j)
	var status int
	var answer http.Header
	if op.Socket {
		status, answer = f.startSocket(ctx, s, u.RequestURI(), header, cookies)
	} else {
		status, answer = f.startEvents(ctx, s, u, q.Target, header, cookies)
	}
	if status != http.StatusOK && status != http.StatusSwitchingProtocols {
		f.streams.end(id)
		id = ""
	}
	writeJSON(w, streamAnswer{Stream: id, Status: status, Header: only(answer, headersOut)})
}

// startEvents runs an event stream at the app's handler and waits for its
// head.
func (f *Fortress) startEvents(ctx context.Context, s *stream, u *url.URL, target string, header http.Header, cookies []*http.Cookie) (int, http.Header) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, http.NoBody)
	if err != nil {
		return http.StatusBadRequest, nil
	}
	req.URL, req.RequestURI, req.RemoteAddr, req.Host, req.Header = u, target, farAway, "", header
	for _, c := range cookies {
		req.AddCookie(c)
	}
	sw := &streamWriter{header: http.Header{}, s: s, head: make(chan int, 1)}
	go func() {
		defer s.end()
		f.ui.Handler.ServeHTTP(sw, req)
		sw.WriteHeader(http.StatusOK)
	}()
	select {
	case status := <-sw.head:
		if status != http.StatusOK || !strings.HasPrefix(sw.header.Get("Content-Type"), "text/event-stream") {
			s.cancel()
			return notStreamed(status), sw.header
		}
		return status, sw.header
	case <-time.After(startFor):
		s.cancel()
		return http.StatusGatewayTimeout, nil
	}
}

// notStreamed is the status a stream the app answered without streaming
// fails with: its own, or 406 for a plain page.
func notStreamed(status int) int {
	if status == http.StatusOK {
		return http.StatusNotAcceptable
	}
	return status
}

// streamWriter hands what an event stream writes to its stream.
type streamWriter struct {
	header http.Header
	s      *stream
	once   sync.Once
	head   chan int
	status int
}

func (sw *streamWriter) Header() http.Header { return sw.header }

func (sw *streamWriter) WriteHeader(status int) {
	sw.once.Do(func() {
		sw.status = status
		sw.head <- status
	})
}

func (sw *streamWriter) Write(b []byte) (int, error) {
	sw.WriteHeader(http.StatusOK)
	if sw.status != http.StatusOK {
		return len(b), nil
	}
	sw.s.push(streamMsg{Data: append([]byte(nil), b...)})
	sw.s.mu.Lock()
	done := sw.s.done
	sw.s.mu.Unlock()
	if done {
		return 0, errors.New("fortress: the stream ended")
	}
	return len(b), nil
}

func (sw *streamWriter) Flush() {}

// startSocket opens a websocket at the app's handler, which runs on one end of
// a pipe in this process, and waits for its handshake.
func (f *Fortress) startSocket(ctx context.Context, s *stream, target string, header http.Header, cookies []*http.Cookie) (int, http.Header) {
	server, client := net.Pipe()
	handler := f.ui.Handler
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.RemoteAddr, r.Host = farAway, ""
			r.Header.Del("Host")
			handler.ServeHTTP(w, r.WithContext(ctx))
		}),
		ReadHeaderTimeout: startFor,
	}
	go func() { _ = srv.Serve(&oneConn{conn: server, done: make(chan struct{})}) }()
	context.AfterFunc(ctx, func() { _ = srv.Close(); _ = client.Close() })
	for _, c := range cookies {
		header.Add("Cookie", c.String())
	}
	dial, cancel := context.WithTimeout(ctx, startFor)
	defer cancel()
	// target starts with a slash, which the fixed prefix already ends with,
	// so nothing a member asks for can change the host.
	c, res, err := websocket.Dial(dial, "ws://fortress/"+strings.TrimPrefix(target, "/"), &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: &http.Transport{
			DialContext: func(context.Context, string, string) (net.Conn, error) { return client, nil },
		}},
		HTTPHeader: header,
	})
	if err != nil {
		s.cancel()
		if res != nil {
			return res.StatusCode, res.Header
		}
		return http.StatusBadGateway, nil
	}
	c.SetReadLimit(int64(s.limit))
	s.send = func(ctx context.Context, binary bool, data []byte) error {
		typ := websocket.MessageText
		if binary {
			typ = websocket.MessageBinary
		}
		return c.Write(ctx, typ, data)
	}
	go func() {
		defer s.end()
		defer func() { _ = c.CloseNow() }()
		for {
			typ, data, err := c.Read(ctx)
			if err != nil {
				return
			}
			s.push(streamMsg{Binary: typ == websocket.MessageBinary, Data: data})
		}
	}()
	return http.StatusSwitchingProtocols, res.Header
}

// oneConn is a listener that hands out one connection and then waits until it
// is closed.
type oneConn struct {
	conn net.Conn
	once sync.Once
	done chan struct{}
	used bool
	mu   sync.Mutex
}

func (l *oneConn) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.used {
		l.used = true
		l.mu.Unlock()
		return l.conn, nil
	}
	l.mu.Unlock()
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneConn) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *oneConn) Addr() net.Addr { return l.conn.LocalAddr() }

// streamCall is one step of a live stream at member.
func (f *Fortress) streamCall(ctx context.Context, member string, op streamOp, data []byte) (streamAnswer, error) {
	framed, err := frame(op, data)
	if err != nil {
		return streamAnswer{}, err
	}
	status, out, err := f.group.Call(ctx, member, http.MethodPost, uiStreamPath, framed)
	if err != nil {
		return streamAnswer{}, err
	}
	if status != http.StatusOK {
		return streamAnswer{}, refusal(status, out)
	}
	var a streamAnswer
	err = json.Unmarshal(out, &a)
	return a, err
}

// tunnelStream carries a websocket or an event stream of an opened page.
func (f *Fortress) tunnelStream(w http.ResponseWriter, r *http.Request, t *ticket, target string, socket bool, words func(*http.Request, string) string) {
	if !t.stream() {
		f.refuse(w, r, http.StatusServiceUnavailable, "busy", words)
		return
	}
	defer t.unstream()
	header := only(r.Header, headersIn)
	ask := &uiAsk{Method: http.MethodGet, Target: target, Header: header, Jar: t.jar, Prefix: tabPath(r, t) + "/"}
	first, err := f.streamCall(r.Context(), t.member, streamOp{Op: "open", Socket: socket, Ask: ask}, nil)
	if err != nil || first.Stream == "" {
		code, status := "unreachable", http.StatusBadGateway
		if err == nil {
			code, status = "refused", notStreamed(first.Status)
		} else if errors.Is(err, ErrPermissionOff) {
			code, status = "permission_off", http.StatusForbidden
		}
		f.refuse(w, r, status, code, words)
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	defer func() {
		end, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_, _ = f.streamCall(end, t.member, streamOp{Op: "close", Stream: first.Stream}, nil)
	}()
	came := f.listen(t.member, t.jar, first.Stream)
	defer f.unlisten(t.jar, first.Stream)
	poll := func(deliver func(streamMsg) error) {
		check := time.NewTicker(tabCheck)
		defer check.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-check.C:
				if f.tickets.get(t.id, time.Now()) == nil || !t.valid() {
					return
				}
			case b, ok := <-came:
				if !ok {
					return
				}
				for _, m := range b.Messages {
					if deliver(m) != nil {
						return
					}
				}
				if b.Done {
					return
				}
				f.tickets.use(t, time.Now())
			}
		}
	}
	if !socket {
		guard(w, r)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		poll(func(m streamMsg) error {
			if _, err := w.Write(m.Data); err != nil {
				return err
			}
			if flusher != nil {
				flusher.Flush()
			}
			return nil
		})
		return
	}
	guard(w, r)
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	defer func() { _ = c.CloseNow() }()
	c.SetReadLimit(group.MaxCallBytes - maxAskHead)
	go func() {
		defer cancel()
		for {
			typ, data, err := c.Read(ctx)
			if err != nil {
				return
			}
			select {
			case f.sending <- struct{}{}:
			case <-ctx.Done():
				return
			}
			a, err := f.streamCall(ctx, t.member, streamOp{Op: "send", Stream: first.Stream, Binary: typ == websocket.MessageBinary}, data)
			<-f.sending
			if err != nil || a.Done {
				return
			}
		}
	}()
	poll(func(m streamMsg) error {
		typ := websocket.MessageText
		if m.Binary {
			typ = websocket.MessageBinary
		}
		return c.Write(ctx, typ, m.Data)
	})
	_ = c.Close(websocket.StatusGoingAway, "")
}

// pump asks a member for what came on the streams of one sign-in and hands
// each stream its part.
type pump struct {
	member string
	subs   map[string]chan streamBatch
}

// listen hands what comes on stream id of member under jar to the channel it
// returns, which closes when the stream ends or falls behind.
func (f *Fortress) listen(member, jar, id string) <-chan streamBatch {
	ch := make(chan streamBatch, maxBacklog)
	f.pumpMu.Lock()
	defer f.pumpMu.Unlock()
	if f.pumps == nil {
		f.pumps = map[string]*pump{}
	}
	p, running := f.pumps[jar]
	if !running {
		p = &pump{member: member, subs: map[string]chan streamBatch{}}
		f.pumps[jar] = p
	}
	p.subs[id] = ch
	if !running && f.enter() {
		go f.runPump(jar, p)
	}
	return ch
}

func (f *Fortress) unlisten(jar, id string) {
	f.pumpMu.Lock()
	defer f.pumpMu.Unlock()
	if p := f.pumps[jar]; p != nil {
		if ch, ok := p.subs[id]; ok {
			delete(p.subs, id)
			close(ch)
		}
	}
}

// runPump asks for what came until no stream of jar listens any more. A
// member that does not answer ends them all, and their browsers connect anew.
func (f *Fortress) runPump(jar string, p *pump) {
	defer f.wg.Done()
	for {
		f.pumpMu.Lock()
		if len(p.subs) == 0 {
			delete(f.pumps, jar)
			f.pumpMu.Unlock()
			return
		}
		f.pumpMu.Unlock()
		a, err := f.streamCall(f.ctx, p.member, streamOp{Op: "poll", Jar: jar}, nil)
		f.pumpMu.Lock()
		for id, ch := range p.subs {
			b, ok := a.Batch[id]
			if err != nil {
				b, ok = streamBatch{Done: true}, true
			}
			if !ok {
				continue
			}
			select {
			case ch <- b:
				if !b.Done {
					continue
				}
			default:
			}
			delete(p.subs, id)
			close(ch)
		}
		f.pumpMu.Unlock()
	}
}
