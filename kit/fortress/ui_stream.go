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
)

// A live stream of an opened page, a websocket or an event stream, does not
// fit into one call. The opened app runs it in this process, keeps what it
// sends and hands it over when the opening member asks again, which it does
// as soon as an answer came. Messages from the browser go over as calls of
// their own.
const (
	uiStreamPath = prefix + "ui/stream"

	// pollFor is how long an ask for more waits for something to arrive,
	// well inside the relay's silence limit.
	pollFor = 10 * time.Second
	// streamIdle ends a stream nobody asked about for that long.
	streamIdle = 30 * time.Second
	// maxStreamQueue is what a stream holds for the opening member at most;
	// a stream that falls further behind ends and the browser connects anew.
	maxStreamQueue = 256 << 10
	// maxStreamsPerCaller and maxStreams bound the streams the opened app
	// runs for one member and in all, maxTabStreams those of one tab.
	maxStreamsPerCaller = 4
	maxStreams          = 16
	maxTabStreams       = 2
	// startFor is how long the opened app may take to answer a new stream.
	startFor = 10 * time.Second
)

type streamOp struct {
	Op     string `json:"op"`
	Stream string `json:"stream,omitempty"`
	Socket bool   `json:"socket,omitempty"`
	Ask    *uiAsk `json:"ask,omitempty"`
	Binary bool   `json:"binary,omitempty"`
}

type streamMsg struct {
	Binary bool   `json:"binary,omitempty"`
	Data   []byte `json:"data"`
}

type streamAnswer struct {
	Stream   string      `json:"stream,omitempty"`
	Status   int         `json:"status,omitempty"`
	Header   http.Header `json:"header,omitempty"`
	Messages []streamMsg `json:"messages,omitempty"`
	Done     bool        `json:"done,omitempty"`
}

// stream is one live stream the opened app runs for a member.
type stream struct {
	caller string
	cancel context.CancelFunc
	send   func(ctx context.Context, binary bool, data []byte) error

	mu     sync.Mutex
	queue  []streamMsg
	queued int
	done   bool
	used   time.Time
	ready  chan struct{}
}

func (s *stream) push(m streamMsg) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return
	}
	if s.queued+len(m.Data) > maxStreamQueue {
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

func (s *stream) wake() {
	select {
	case s.ready <- struct{}{}:
	default:
	}
}

// take waits until something is there or the stream ended, at most pollFor.
func (s *stream) take(ctx context.Context) ([]streamMsg, bool) {
	t := time.NewTimer(pollFor)
	defer t.Stop()
	for {
		s.mu.Lock()
		s.used = time.Now()
		if len(s.queue) > 0 || s.done {
			out, done := s.queue, s.done
			s.queue, s.queued = nil, 0
			s.mu.Unlock()
			return out, done
		}
		s.mu.Unlock()
		select {
		case <-s.ready:
		case <-t.C:
			return nil, false
		case <-ctx.Done():
			return nil, false
		}
	}
}

type streams struct {
	mu   sync.Mutex
	byID map[string]*stream
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
	if op.Op == "open" {
		f.startStream(w, op, from)
		return
	}
	s := f.streams.get(op.Stream, caller)
	if s == nil {
		writeJSON(w, streamAnswer{Done: true})
		return
	}
	switch op.Op {
	case "poll":
		msgs, done := s.take(r.Context())
		writeJSON(w, streamAnswer{Messages: msgs, Done: done})
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
	s := &stream{caller: from.ID, cancel: cancel, used: time.Now(), ready: make(chan struct{}, 1)}
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
	c, res, err := websocket.Dial(dial, "ws://fortress"+target, &websocket.DialOptions{
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
	c.SetReadLimit(maxStreamQueue)
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
	status, out, err := f.group.Call(ctx, member, http.MethodPost, uiStreamPath, frame(op, data))
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
	poll := func(deliver func(streamMsg) error) {
		for ctx.Err() == nil && f.tickets.get(t.id, time.Now()) != nil && t.valid() {
			a, err := f.streamCall(ctx, t.member, streamOp{Op: "poll", Stream: first.Stream}, nil)
			if err != nil {
				return
			}
			for _, m := range a.Messages {
				if deliver(m) != nil {
					return
				}
			}
			if a.Done {
				return
			}
			f.tickets.use(t, time.Now())
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
	c.SetReadLimit(maxStreamQueue)
	go func() {
		defer cancel()
		for {
			typ, data, err := c.Read(ctx)
			if err != nil {
				return
			}
			a, err := f.streamCall(ctx, t.member, streamOp{Op: "send", Stream: first.Stream, Binary: typ == websocket.MessageBinary}, data)
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
