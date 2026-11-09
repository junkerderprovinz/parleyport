package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// failure is a failed attempt with what the dispatcher needs to decide on the
// next one.
type failure struct {
	code   string
	status int
	retry  bool
	wait   time.Duration
	msg    string
}

func (f *failure) Error() string { return f.msg }

// maxSaid is how much of a refusal's body goes into the error, which is where
// a service says why.
const maxSaid = 512

// do sends req and turns anything but a 2xx into a *failure. out, when not
// nil, receives the decoded JSON of a success.
func (d *Dispatcher) do(req *http.Request, out any) error {
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck // nothing to do about a failed close
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if out != nil {
			return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return nil
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	msg := resp.Status
	if said := strings.TrimSpace(string(raw[:min(len(raw), maxSaid)])); said != "" {
		msg += ": " + said
	}
	return &failure{
		code:   statusCode(resp.StatusCode),
		status: resp.StatusCode,
		retry:  resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500,
		wait:   waitAsked(resp.StatusCode, resp.Header, raw),
		msg:    msg,
	}
}

func (d *Dispatcher) postJSON(ctx context.Context, endpoint string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return d.do(req, nil)
}

func statusCode(status int) string {
	switch {
	case status >= 300 && status < 400:
		return CodeRedirect
	case status == http.StatusUnauthorized, status == http.StatusForbidden:
		return CodeAuth
	case status == http.StatusNotFound:
		return CodeNotFound
	case status == http.StatusRequestTimeout:
		return CodeTimeout
	case status == http.StatusTooManyRequests:
		return CodeRateLimited
	case status >= 500:
		return CodeServer
	default:
		return CodeRejected
	}
}

// waitAsked reads how long a 429 asks the sender to hold off. Discord states
// it in its body with a fraction, finer than the whole seconds of Retry-After.
func waitAsked(status int, h http.Header, body []byte) time.Duration {
	if status != http.StatusTooManyRequests {
		return 0
	}
	var doc struct {
		RetryAfter float64 `json:"retry_after"`
	}
	if json.Unmarshal(body, &doc) == nil && doc.RetryAfter > 0 {
		return time.Duration(doc.RetryAfter * float64(time.Second))
	}
	secs, err := strconv.ParseFloat(strings.TrimSpace(h.Get("Retry-After")), 64)
	if err != nil || secs <= 0 {
		return 0
	}
	return time.Duration(secs * float64(time.Second))
}

// sameHostRedirect follows a redirect that stays on the host and does not
// leave https. Anything else comes back as the 3xx, because the request's
// headers may hold a token the next host must not see.
func sameHostRedirect(req *http.Request, via []*http.Request) error {
	first := via[0].URL
	if len(via) >= 5 || req.URL.Host != first.Host || (first.Scheme == "https" && req.URL.Scheme != "https") {
		return http.ErrUseLastResponse
	}
	return nil
}

// classify turns any error of an attempt into a *failure. ctx is the send's
// own context, which tells a cancelled send from an attempt that timed out.
func classify(ctx context.Context, err error) *failure {
	if f, ok := errors.AsType[*failure](err); ok {
		return f
	}
	f := &failure{code: CodeNetwork, retry: true, msg: err.Error()}
	var dns *net.DNSError
	var netErr net.Error
	var certErr *tls.CertificateVerificationError
	var authorityErr x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var recordErr tls.RecordHeaderError
	switch {
	case ctx.Err() != nil:
		f.code, f.retry = CodeCanceled, false
	case errors.As(err, &dns):
		f.code = CodeDNS
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		f.code = CodeTimeout
	case errors.As(err, &certErr), errors.As(err, &authorityErr), errors.As(err, &hostErr), errors.As(err, &recordErr):
		f.code, f.retry = CodeTLS, false
	case refused(err):
		f.code = CodeRefused
	}
	return f
}

// wsaeconnrefused is Winsock's "connection refused", which Go does not map to
// syscall.ECONNREFUSED on Windows.
const wsaeconnrefused = syscall.Errno(10061)

func refused(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	errno, ok := errors.AsType[syscall.Errno](err)
	return ok && errno == wsaeconnrefused
}

func failf(code string, format string, args ...any) *failure {
	return &failure{code: code, msg: fmt.Sprintf(format, args...)}
}
