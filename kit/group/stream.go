package group

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/relay"
)

// A stream is an answer too large to hold, such as a backup, and goes only on
// the direct route. The call is an ordinary sealed and signed one. The answer
// is a head, sealed and signed like any answer, that gives the length and a
// fresh key; the body follows in pieces sealed under that key, and an end the
// member signs over the length and the SHA-256 of the whole. A refusal comes
// back as an ordinary answer.

const (
	streamPrefix = internalPrefix + "stream"
	streamType   = "application/x-kit-stream"
	// pieceBytes is how much of a stream one sealed piece carries.
	pieceBytes = 64 << 10
	// maxHeadBytes bounds the head of a stream and a refusal, which are as
	// small as any call.
	maxHeadBytes = 256 << 10
	// maxRefusalBytes bounds what the app may refuse a stream with.
	maxRefusalBytes = 64 << 10
	// maxStreams is how many streams an instance sends at once, and how many
	// uploads it takes.
	maxStreams = 2
	// streamWriteTimeout bounds how long one piece may wait for a reader that
	// stopped reading.
	streamWriteTimeout = 30 * time.Second
)

const (
	pieceHead byte = 'h'
	pieceData byte = 'd'
	pieceEnd  byte = 'e'
)

// Errors of Stream.
var (
	ErrNotDirect    = errors.New("group: a stream goes only directly on the local network, and the member is reachable through the relay alone")
	ErrStreamBroken = errors.New("group: the stream broke off or arrived damaged")
)

type streamHead struct {
	Length int64  `json:"length"`
	Key    []byte `json:"key"`
}

type streamEnd struct {
	Length int64  `json:"length"`
	SHA256 string `json:"sha256"`
	Sig    []byte `json:"sig"`
}

// endBody is what the member signs at the end of a stream.
func endBody(length int64, sum []byte) []byte {
	return fmt.Appendf(nil, `{"length":%d,"sha256":"%x"}`, length, sum)
}

func pieceNonce(n uint64) []byte {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], n)
	return nonce
}

func streamAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Stream asks member id for path as a stream, on the direct route only, and
// returns the status and body the app gave. The body of a 200 is the stream:
// a read fails with ErrStreamBroken once it breaks off, runs past its length
// or does not match what the member signed, at the latest where it would end.
// The body of any other status is the member's refusal. A member reachable
// through the relay alone gets ErrNotDirect. The caller closes the body.
func (g *Group) Stream(ctx context.Context, id, path string) (int, io.ReadCloser, error) {
	urls, relayed := g.routesTo(id)
	call := relay.ProxyCall{Method: http.MethodGet, Path: streamPrefix + path}
	err := ErrUnreachable
	if relayed {
		err = ErrNotDirect
	}
	for _, u := range urls {
		if relayed && g.down(u, time.Now()) {
			continue
		}
		status, body, serr := g.streamFrom(ctx, u, id, call)
		var untrusted *relay.UntrustedAnswer
		switch {
		case serr == nil:
			g.confirm(id, u, "", "", time.Now())
			return status, body, nil
		case errors.As(serr, &untrusted):
			return 0, nil, serr
		}
		g.directFailed(ctx, u)
		err = serr
		if relayed {
			err = fmt.Errorf("%w: %w", ErrNotDirect, serr)
		}
	}
	return 0, nil, err
}

// streamFrom makes one stream call to target at base and reads as far as the
// head.
func (g *Group) streamFrom(ctx context.Context, base, target string, call relay.ProxyCall) (int, io.ReadCloser, error) {
	ctx, cancel := context.WithCancel(ctx)
	// The head comes as soon as an ordinary answer would; the body takes as
	// long as it takes.
	timer := time.AfterFunc(callTimeout, cancel)
	req, sealed, id, err := g.newDirectRequest(ctx, base, target, call)
	if err != nil {
		cancel()
		return 0, nil, err
	}
	resp, err := g.streamer.Do(req)
	if err != nil {
		cancel()
		return 0, nil, fmt.Errorf("%w directly at %s: %w", ErrUnreachable, base, err)
	}
	fail := func(err error) (int, io.ReadCloser, error) {
		_ = resp.Body.Close()
		cancel()
		return 0, nil, err
	}
	switch {
	case resp.StatusCode == http.StatusServiceUnavailable:
		return fail(fmt.Errorf("%w directly at %s: it is busy", ErrUnreachable, base))
	case resp.StatusCode != http.StatusOK:
		return fail(fmt.Errorf("%w: %s refused the direct call with HTTP %d", ErrStranger, base, resp.StatusCode))
	}
	br := bufio.NewReaderSize(resp.Body, pieceBytes+1024)
	streamed := resp.Header.Get("Content-Type") == streamType
	var raw []byte
	if streamed {
		raw, err = readPiece(br, pieceHead, maxHeadBytes)
	} else {
		raw, err = io.ReadAll(io.LimitReader(br, maxHeadBytes))
	}
	if err != nil {
		return fail(fmt.Errorf("%w directly at %s: %w", ErrUnreachable, base, err))
	}
	res, err := g.openResponse(raw, id, base)
	if err != nil {
		return fail(err)
	}
	if !relay.VerifyResult(g.signing, id, target, sealed, res) {
		return fail(fmt.Errorf("group: %s's answer is not signed by its key", target))
	}
	g.noteAnswer(target, res.Status, res.Body, time.Now())
	if !g.trustsAnswer(target, res.Key) {
		return fail(&relay.UntrustedAnswer{Target: target, Status: res.Status, Body: res.Body})
	}
	if !streamed {
		_ = resp.Body.Close()
		cancel()
		return res.Status, io.NopCloser(bytes.NewReader(res.Body)), nil
	}
	var head streamHead
	if res.Status != http.StatusOK || json.Unmarshal(res.Body, &head) != nil || head.Length < 0 {
		return fail(fmt.Errorf("%w: %s began it unreadably", ErrStreamBroken, base))
	}
	aead, err := streamAEAD(head.Key)
	if err != nil {
		return fail(fmt.Errorf("%w: %s began it unreadably", ErrStreamBroken, base))
	}
	if !timer.Stop() {
		return fail(fmt.Errorf("%w directly at %s: %w", ErrUnreachable, base, context.DeadlineExceeded))
	}
	return http.StatusOK, &streamReader{
		body: resp.Body, br: br, cancel: cancel, aead: aead, length: head.Length, sum: sha256.New(),
		verify: func(end []byte, sig []byte) bool {
			return relay.VerifyResult(g.signing, id, target, sealed,
				relay.ProxyResult{Status: http.StatusOK, Body: end, Key: res.Key, Sig: sig})
		},
	}, nil
}

// readPiece reads one piece of kind, of at most limit bytes.
func readPiece(r io.Reader, kind byte, limit int) ([]byte, error) {
	got, b, err := readAnyPiece(r, limit)
	if err != nil {
		return nil, err
	}
	if got != kind {
		return nil, fmt.Errorf("a piece of kind %q came where %q belongs", got, kind)
	}
	return b, nil
}

func readAnyPiece(r io.Reader, limit int) (byte, []byte, error) {
	var head [5]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(head[1:])
	if n > uint32(limit) { //nolint:gosec // G115: limit is a small positive constant
		return 0, nil, fmt.Errorf("a piece of %d bytes is too large", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, nil, err
	}
	return head[0], b, nil
}

// streamReader opens the pieces of a stream as they come.
type streamReader struct {
	body   io.ReadCloser
	br     *bufio.Reader
	cancel context.CancelFunc
	aead   cipher.AEAD
	count  uint64
	length int64
	got    int64
	sum    hash.Hash
	verify func(end, sig []byte) bool
	// wait, if set, gives the connection time for the next piece.
	wait  func()
	plain []byte
	err   error
}

func (r *streamReader) Read(p []byte) (int, error) {
	for len(r.plain) == 0 && r.err == nil {
		r.err = r.next()
	}
	if len(r.plain) > 0 {
		n := copy(p, r.plain)
		r.plain = r.plain[n:]
		return n, nil
	}
	return 0, r.err
}

func (r *streamReader) next() error {
	if r.wait != nil {
		r.wait()
	}
	kind, sealed, err := readAnyPiece(r.br, pieceBytes+r.aead.Overhead())
	if err != nil {
		return fmt.Errorf("%w: it ended after %d of %d bytes", ErrStreamBroken, r.got, r.length)
	}
	plain, err := r.aead.Open(nil, pieceNonce(r.count), sealed, []byte{kind})
	r.count++
	if err != nil {
		return fmt.Errorf("%w: a piece after %d bytes does not open", ErrStreamBroken, r.got)
	}
	switch kind {
	case pieceData:
		if r.got+int64(len(plain)) > r.length {
			return fmt.Errorf("%w: it runs past its %d bytes", ErrStreamBroken, r.length)
		}
		r.got += int64(len(plain))
		r.sum.Write(plain)
		r.plain = plain
		return nil
	case pieceEnd:
		var end streamEnd
		sum := r.sum.Sum(nil)
		switch {
		case json.Unmarshal(plain, &end) != nil:
			return fmt.Errorf("%w: its end is unreadable", ErrStreamBroken)
		case r.got != r.length || end.Length != r.length:
			return fmt.Errorf("%w: it ended after %d of %d bytes", ErrStreamBroken, r.got, r.length)
		case end.SHA256 != hex.EncodeToString(sum):
			return fmt.Errorf("%w: its SHA-256 does not match what arrived", ErrStreamBroken)
		case !r.verify(endBody(r.length, sum), end.Sig):
			return fmt.Errorf("%w: its end is not signed by the member", ErrStreamBroken)
		}
		return io.EOF
	}
	return fmt.Errorf("%w: a piece of unknown kind %q", ErrStreamBroken, kind)
}

func (r *streamReader) Close() error {
	r.cancel()
	return r.body.Close()
}

// serveStream answers a stream call that came directly.
func (g *Group) serveStream(ctx context.Context, w http.ResponseWriter, req relay.ProxyRequest, call relay.ProxyCall) {
	caller, refused := g.admit(call, relay.SourceOf(ctx), g.vouched(call.From, call.Kind, call.Key), time.Now())
	if refused != nil {
		if refused.status == relay.StatusDrop {
			forbid(w)
			return
		}
		g.answer(w, req, refused.status, refused.body)
		return
	}
	release, ok := g.limits.acquire(call.Key)
	if !ok {
		g.answer(w, req, http.StatusTooManyRequests, relay.RefusalBody("memberBusy", "this device already has as many calls waiting on this instance as it may"))
		return
	}
	defer release()
	path := strings.TrimPrefix(call.Path, streamPrefix)
	if g.stream == nil {
		g.answer(w, req, http.StatusNotFound, relay.RefusalBody("noStreams", "this instance sends no streams"))
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer context.AfterFunc(g.ctx, cancel)()
	hreq, err := http.NewRequestWithContext(context.WithValue(ctx, callerKey{}, caller), call.Method, path, http.NoBody)
	if err != nil || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		g.answer(w, req, http.StatusBadRequest, nil)
		return
	}
	hreq.RequestURI = path
	select {
	case g.streams <- struct{}{}:
		defer func() { <-g.streams }()
	default:
		g.answer(w, req, http.StatusServiceUnavailable, relay.RefusalBody("streamBusy", "this instance is sending as many streams as it may; try again in a moment"))
		return
	}
	rc := http.NewResponseController(w)
	// The call is read, so its deadline would only cut the stream short.
	_ = rc.SetReadDeadline(time.Time{})
	s := &streamWriter{g: g, ctx: ctx, w: w, rc: rc, req: req, header: http.Header{}}
	if !s.serve(hreq) {
		return
	}
	s.finish(call.Path)
}

// streamWriter is the ResponseWriter the app streams into.
type streamWriter struct {
	g       *Group
	ctx     context.Context
	w       http.ResponseWriter
	rc      *http.ResponseController
	req     relay.ProxyRequest
	header  http.Header
	status  int
	refusal bytes.Buffer
	length  int64
	sent    int64
	sum     hash.Hash
	aead    cipher.AEAD
	count   uint64
	piece   []byte
	started bool
	// unmeasured is a 200 without a Content-Length, failed a stream that
	// cannot end well any more.
	unmeasured bool
	failed     bool
}

var errStreamFailed = errors.New("group: the stream cannot end well any more")

// serve runs the app's handler and reports whether it returned rather than
// panicked. A panic ends the stream without its end, or comes back as a
// refusal if the stream had not begun.
func (s *streamWriter) serve(r *http.Request) (ok bool) {
	defer func() {
		if p := recover(); p != nil {
			slog.Error("group: a stream handler panicked", "path", r.URL.Path, "panic", fmt.Sprint(p))
			if !s.started {
				s.g.answer(s.w, s.req, http.StatusInternalServerError, nil)
			}
			ok = false
		}
	}()
	s.g.stream.ServeHTTP(s, r)
	return true
}

func (s *streamWriter) Header() http.Header { return s.header }

func (s *streamWriter) WriteHeader(status int) {
	if s.status == 0 {
		s.status = status
	}
}

func (s *streamWriter) Write(p []byte) (int, error) {
	s.WriteHeader(http.StatusOK)
	if s.status != http.StatusOK {
		if s.failed || s.refusal.Len()+len(p) > maxRefusalBytes {
			s.failed = true
			return 0, errAnswerTooLarge
		}
		return s.refusal.Write(p)
	}
	if !s.started && !s.failed {
		s.start()
	}
	switch {
	case s.failed:
		return 0, errStreamFailed
	case s.ctx.Err() != nil:
		s.failed = true
		return 0, s.ctx.Err()
	case s.sent+int64(len(p)) > s.length:
		s.failed = true
		return 0, fmt.Errorf("group: the stream runs past the %d bytes it announced", s.length)
	}
	s.sum.Write(p)
	s.sent += int64(len(p))
	written := 0
	for len(p) > 0 {
		n := min(len(p), pieceBytes-len(s.piece))
		s.piece = append(s.piece, p[:n]...)
		p, written = p[n:], written+n
		if len(s.piece) == pieceBytes {
			if err := s.flush(); err != nil {
				s.failed = true
				return written, err
			}
		}
	}
	return written, nil
}

// start sends the head once the app said how long the stream is.
func (s *streamWriter) start() {
	length, err := strconv.ParseInt(s.header.Get("Content-Length"), 10, 64)
	if err != nil || length < 0 {
		s.unmeasured, s.failed = true, true
		return
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	aead, err := streamAEAD(key)
	if err != nil {
		s.failed = true
		return
	}
	head, _ := json.Marshal(streamHead{Length: length, Key: key})
	resp, err := s.g.response(s.req, http.StatusOK, head)
	if err != nil {
		s.failed = true
		return
	}
	raw, _ := json.Marshal(resp)
	s.length, s.aead, s.sum, s.started = length, aead, sha256.New(), true
	s.w.Header().Set("Content-Type", streamType)
	s.w.WriteHeader(http.StatusOK)
	if err := s.send(pieceHead, raw); err != nil {
		s.failed = true
	}
}

func (s *streamWriter) send(kind byte, b []byte) error {
	_ = s.rc.SetWriteDeadline(time.Now().Add(streamWriteTimeout))
	return writePiece(s.w, kind, b)
}

func writePiece(w io.Writer, kind byte, b []byte) error {
	var head [5]byte
	head[0] = kind
	binary.BigEndian.PutUint32(head[1:], uint32(len(b))) //nolint:gosec // G115: a piece is at most a few hundred KiB
	if _, err := w.Write(head[:]); err != nil {
		return err
	}
	_, err := w.Write(b) //nolint:gosec // G705: sealed bytes, under a type no browser renders
	return err
}

func (s *streamWriter) seal(kind byte, plain []byte) error {
	sealed := s.aead.Seal(nil, pieceNonce(s.count), plain, []byte{kind})
	s.count++
	return s.send(kind, sealed)
}

func (s *streamWriter) flush() error {
	if len(s.piece) == 0 {
		return nil
	}
	err := s.seal(pieceData, s.piece)
	s.piece = s.piece[:0]
	return err
}

// finish ends the stream once the app's handler returned: with the end the
// member signs, if the app sent what it announced, and without, so that the
// caller sees it broke off, if not.
func (s *streamWriter) finish(path string) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	if s.status != http.StatusOK {
		if s.failed {
			s.g.answer(s.w, s.req, http.StatusInternalServerError, relay.RefusalBody("answerTooLarge", "the answer is larger than a member may send"))
			return
		}
		s.g.answer(s.w, s.req, s.status, s.refusal.Bytes())
		return
	}
	if !s.started && !s.failed {
		s.start()
	}
	if s.unmeasured {
		s.g.answer(s.w, s.req, http.StatusInternalServerError, relay.RefusalBody("streamLength", "the app began a stream without saying how long it is"))
		return
	}
	if !s.started {
		s.g.answer(s.w, s.req, http.StatusInternalServerError, nil)
		return
	}
	if s.failed || s.sent != s.length || s.flush() != nil {
		slog.Warn("group: a stream ended before it was whole", "path", path, "sent", s.sent, "length", s.length)
		return
	}
	sum := s.sum.Sum(nil)
	signed := relay.SignResult(s.g.signing, &s.g.identity, s.req.RequestID, s.req.Sealed,
		relay.ProxyResult{Status: http.StatusOK, Body: endBody(s.length, sum)})
	end, _ := json.Marshal(streamEnd{Length: s.length, SHA256: hex.EncodeToString(sum), Sig: signed.Sig})
	_ = s.seal(pieceEnd, end)
}
