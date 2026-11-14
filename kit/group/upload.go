package group

import (
	"bufio"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/member"
	"github.com/junkerderprovinz/parleyport/kit/relay"
)

// An upload is a stream the other way round, such as a backup handed back to
// the app that made it. The call is an ordinary sealed and signed one and
// travels in a header, its body giving the length and a fresh key. The
// request asks for 100-continue, so the body only goes out once the app
// starts to read it and a refusal comes back as one. The body is the upload
// in pieces sealed under that key and an end the caller signs over the length
// and the SHA-256 of the whole.

const (
	uploadPrefix = internalPrefix + "upload"
	uploadType   = "application/x-kit-upload"
)

var errUploadLength = errors.New("group: the upload does not have the length it announced")

// Upload sends body, n bytes long, to member id as a call to path, on the
// direct route only, and returns the status and body the app answered. The
// body goes out once the member's app starts to read it, so a refusal before
// that comes back as one. The app reads ErrStreamBroken where the upload
// would end if it arrived damaged or other than n bytes long, and so does not
// keep it. A member reachable through the relay alone gets ErrNotDirect.
func (g *Group) Upload(ctx context.Context, id, path string, body io.Reader, n int64) (int, []byte, error) {
	if n < 0 {
		return 0, nil, errUploadLength
	}
	urls, relayed := g.routesTo(id)
	err := ErrUnreachable
	if relayed {
		err = ErrNotDirect
	}
	src := &measured{r: body}
	for _, u := range urls {
		if relayed && g.down(u, time.Now()) {
			continue
		}
		status, out, uerr := g.uploadTo(ctx, u, id, path, src, n)
		var untrusted *relay.UntrustedAnswer
		switch {
		case uerr == nil:
			g.confirm(id, u, "", "", time.Now())
			return status, out, nil
		case errors.As(uerr, &untrusted), src.read > 0:
			// Once body was read, it cannot be sent again.
			return 0, nil, uerr
		}
		g.directFailed(ctx, u)
		err = uerr
		if relayed {
			err = fmt.Errorf("%w: %w", ErrNotDirect, uerr)
		}
	}
	return 0, nil, err
}

// measured is a reader that counts what was read of it.
type measured struct {
	r    io.Reader
	read int64
}

func (m *measured) Read(p []byte) (int, error) {
	n, err := m.r.Read(p)
	m.read += int64(n)
	return n, err
}

// uploadTo makes one upload call to target at base.
func (g *Group) uploadTo(ctx context.Context, base, target, path string, body io.Reader, n int64) (int, []byte, error) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	aead, err := streamAEAD(key)
	if err != nil {
		return 0, nil, err
	}
	head, _ := json.Marshal(streamHead{Length: n, Key: key})
	id, err := requestID()
	if err != nil {
		return 0, nil, err
	}
	sealed, err := relay.SealSignedCall(g.frameKey, g.signing, &g.identity, id, target, relay.ProxyCall{Method: http.MethodPost, Path: uploadPrefix + path, Body: head})
	if err != nil {
		return 0, nil, err
	}
	payload, err := json.Marshal(relay.ProxyRequest{RequestID: id, Target: target, Sealed: sealed})
	if err != nil {
		return 0, nil, err
	}

	pr, pw := io.Pipe()
	var sent error
	done := make(chan struct{})
	go func() {
		defer close(done)
		sent = g.sendUpload(pw, aead, body, n, id, sealed)
		_ = pw.CloseWithError(sent)
	}()
	settle := func() error {
		_ = pr.Close()
		<-done
		if sent != nil && !errors.Is(sent, io.ErrClosedPipe) {
			return sent
		}
		return nil
	}

	endpoint, err := directEndpoint(base)
	if err != nil {
		_ = settle()
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, pr)
	if err != nil {
		_ = settle()
		return 0, nil, err
	}
	now := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set("Content-Type", uploadType)
	req.Header.Set("Expect", "100-continue")
	req.Header.Set(g.headers.peer, g.self)
	req.Header.Set(g.headers.target, target)
	req.Header.Set(g.headers.time, now)
	req.Header.Set(g.headers.call, base64.StdEncoding.EncodeToString(payload))
	req.Header.Set(g.headers.signature, directSignature(g.peerAuth, g.self, now, payload))
	resp, err := g.uploader.Do(req)
	if serr := settle(); serr != nil {
		if err == nil {
			_ = resp.Body.Close()
		}
		return 0, nil, serr
	}
	if err != nil {
		return 0, nil, fmt.Errorf("%w directly at %s: %w", ErrUnreachable, base, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 0, nil, directRefusal(base, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, int64(2*g.maxAnswer+64<<10)))
	if err != nil {
		return 0, nil, fmt.Errorf("%w directly at %s: %w", ErrUnreachable, base, err)
	}
	res, err := g.openResponse(raw, id, base)
	if err != nil {
		return 0, nil, err
	}
	if !relay.VerifyResult(g.signing, id, target, sealed, res) {
		return 0, nil, fmt.Errorf("group: %s's answer is not signed by its key", target)
	}
	g.noteAnswer(target, res.Status, res.Body, time.Now())
	if !g.trustsAnswer(target, res.Key) {
		return 0, nil, &relay.UntrustedAnswer{Target: target, Status: res.Status, Body: res.Body}
	}
	return res.Status, res.Body, nil
}

// sendUpload writes body to w as the pieces of an upload, n bytes long, and
// the end this instance signs for the call requestID.
func (g *Group) sendUpload(w io.Writer, aead cipher.AEAD, body io.Reader, n int64, requestID string, sealed []byte) error {
	sum := sha256.New()
	buf := make([]byte, pieceBytes)
	var count uint64
	for left := n; left > 0; {
		k, err := io.ReadFull(body, buf[:min(left, pieceBytes)])
		if err != nil {
			return fmt.Errorf("%w: it ended after %d of %d bytes: %w", errUploadLength, n-left+int64(k), n, err)
		}
		sum.Write(buf[:k])
		left -= int64(k)
		if err := writePiece(w, pieceData, aead.Seal(nil, pieceNonce(count), buf[:k], []byte{pieceData})); err != nil {
			return err
		}
		count++
	}
	var one [1]byte
	switch _, err := io.ReadFull(body, one[:]); {
	case err == nil:
		return fmt.Errorf("%w: it runs past its %d bytes", errUploadLength, n)
	case !errors.Is(err, io.EOF):
		return err
	}
	digest := sum.Sum(nil)
	signed := relay.SignResult(g.signing, &g.identity, requestID, sealed, relay.ProxyResult{Status: http.StatusOK, Body: endBody(n, digest)})
	end, _ := json.Marshal(streamEnd{Length: n, SHA256: hex.EncodeToString(digest), Sig: signed.Sig})
	return writePiece(w, pieceEnd, aead.Seal(nil, pieceNonce(count), end, []byte{pieceEnd}))
}

// serveUpload hands an upload that came directly to the app.
func (g *Group) serveUpload(ctx context.Context, w http.ResponseWriter, r *http.Request, req relay.ProxyRequest, call relay.ProxyCall) {
	caller, refused := g.admitCall(ctx, call)
	switch {
	case refused != nil && refused.status == relay.StatusDrop:
		forbid(w)
		return
	case refused != nil:
		g.answer(w, req, refused.status, refused.body)
		return
	case caller.Kind != member.KindInstance:
		g.answer(w, req, http.StatusForbidden, relay.RefusalBody("uploadFromInstance", "only an instance sends uploads"))
		return
	}
	release, ok := g.limits.acquire(call.Key)
	if !ok {
		g.answer(w, req, http.StatusTooManyRequests, relay.RefusalBody("memberBusy", "this device already has as many calls waiting on this instance as it may"))
		return
	}
	defer release()
	if g.upload == nil {
		g.answer(w, req, http.StatusNotFound, relay.RefusalBody("noUploads", "this instance takes no uploads"))
		return
	}
	var head streamHead
	if json.Unmarshal(call.Body, &head) != nil || head.Length < 0 {
		g.answer(w, req, http.StatusBadRequest, nil)
		return
	}
	aead, err := streamAEAD(head.Key)
	path := strings.TrimPrefix(call.Path, uploadPrefix)
	if err != nil || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		g.answer(w, req, http.StatusBadRequest, nil)
		return
	}
	select {
	case g.uploads <- struct{}{}:
		defer func() { <-g.uploads }()
	default:
		g.answer(w, req, http.StatusServiceUnavailable, relay.RefusalBody("uploadBusy", "this instance is taking as many uploads as it may; try again in a moment"))
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer context.AfterFunc(g.ctx, cancel)()
	rc := http.NewResponseController(w)
	upload := &streamReader{
		body: r.Body, br: bufio.NewReaderSize(r.Body, pieceBytes+1024), cancel: cancel,
		aead: aead, length: head.Length, sum: sha256.New(),
		wait: func() { _ = rc.SetReadDeadline(time.Now().Add(streamWriteTimeout)) },
		verify: func(end, sig []byte) bool {
			return relay.VerifyResult(g.signing, req.RequestID, caller.ID, req.Sealed,
				relay.ProxyResult{Status: http.StatusOK, Body: end, Key: caller.Key, Sig: sig})
		},
	}
	hreq, err := http.NewRequestWithContext(context.WithValue(ctx, callerKey{}, caller), http.MethodPost, path, upload)
	if err != nil {
		g.answer(w, req, http.StatusBadRequest, nil)
		return
	}
	hreq.RequestURI = path
	hreq.ContentLength = head.Length
	status, out := g.serveUploadApp(&recorder{header: http.Header{}, limit: g.maxAnswer}, hreq)
	g.answer(w, req, status, out)
}

// serveUploadApp runs the app's upload handler into rw and returns its
// answer. A panic is answered as an internal error.
func (g *Group) serveUploadApp(rw *recorder, r *http.Request) (status int, body []byte) {
	defer func() {
		if p := recover(); p != nil {
			slog.Error("group: an upload handler panicked", "path", r.URL.Path, "panic", fmt.Sprint(p))
			status, body = http.StatusInternalServerError, nil
		}
	}()
	g.upload.ServeHTTP(rw, r)
	if rw.tooLarge {
		return http.StatusInternalServerError, relay.RefusalBody("answerTooLarge", "the answer is larger than a member may send")
	}
	if rw.status == 0 {
		rw.status = http.StatusOK
	}
	return rw.status, rw.body.Bytes()
}
