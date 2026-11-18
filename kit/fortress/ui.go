package fortress

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// OpenAction is what an app runs at another member when its user opens that
// member's web interface through the fortress. A member offers it with
// Config.UI, an app that opens others lists it in Config.Uses.
const OpenAction = "ui.open"

// UI is an app's web interface as the members open it through the fortress.
// Every request reaches Handler as one from far away: RemoteAddr 192.0.2.1,
// an empty Host, none of the browser's cookies, credentials, origin or
// forwarding headers, and X-Forwarded-Prefix set to where the browser sees
// the interface. The cookies Handler sets stay with this instance, one jar
// per opening member and sign-in there, and never reach the browser.
type UI struct {
	// Handler serves the interface as a browser reaches it, with the app's
	// own sign-in in front. Opened tells its requests apart, so that it can
	// keep doors such as a password reset closed to them.
	Handler http.Handler
	// SignIn reports whether the app asks for its own sign-in now. While it
	// does not, the fortress opens nothing, since every phrase holder could
	// then use the app.
	SignIn func() bool
	// Opened runs when a member starts a new session here, for the app's
	// activity log, so that every opening shows up afterwards.
	Opened func(from Caller)
}

func (u *UI) complete() bool {
	return u.Handler != nil && u.SignIn != nil && u.Opened != nil
}

const (
	uiPath      = prefix + "ui"
	uiCheckPath = prefix + "ui/check"

	// farAway is where every opened request comes from, an address no app
	// trusts as its own machine or its network.
	farAway = "192.0.2.1:0"
	// uiTimeout bounds one request at the opened app.
	uiTimeout = 30 * time.Second
	// maxUICalls bounds the requests the opened app serves at a time for all
	// members together, maxUICallsPerCaller for one; the rest is turned away
	// at once.
	maxUICalls          = 8
	maxUICallsPerCaller = 4
	// The jars an opened app keeps: per opening member, in all, cookies per
	// jar and bytes per cookie, and how long a jar lives unused and at most.
	maxJarsPerCaller = 8
	maxJars          = 64
	maxJarCookies    = 32
	maxCookieBytes   = 4 << 10
	jarIdle          = 30 * time.Minute
	jarLife          = 12 * time.Hour
	// maxUIAnswer is what an opened request answers at most unless
	// Config.MaxAnswerBytes says otherwise; the relay may carry less.
	maxUIAnswer = 4 << 20
	// packFrom is the size from which text is packed before it travels.
	packFrom = 1 << 10
	// maxFrameHead and maxFrameBody lie far above anything a call carries.
	// They keep a frame's length within its four bytes and its size within
	// an int on 32-bit platforms as well.
	maxFrameHead = 4 << 20
	maxFrameBody = 1 << 30
)

var errFrameTooLarge = errors.New("fortress: a frame too large to send")

var (
	jarPattern    = regexp.MustCompile(`^[0-9a-f]{32}$`)
	prefixPattern = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{0,254}/$`)
)

// headersIn are the request headers that reach the opened app.
var headersIn = []string{
	"Accept", "Accept-Encoding", "Accept-Language", "Cache-Control", "Content-Type",
	"If-Match", "If-None-Match", "If-Modified-Since", "If-Unmodified-Since",
	"Pragma", "Range", "X-Requested-With", "X-Csrf-Token",
}

// headersOut are the answer headers that reach the browser.
var headersOut = []string{
	"Content-Type", "Content-Encoding", "Content-Language", "Content-Disposition",
	"Content-Range", "Accept-Ranges", "Cache-Control", "Etag", "Last-Modified",
	"Expires", "Vary", "Location", "Content-Security-Policy",
}

var uiMethods = map[string]bool{
	http.MethodGet: true, http.MethodHead: true, http.MethodPost: true,
	http.MethodPut: true, http.MethodPatch: true, http.MethodDelete: true,
}

func only(h http.Header, names []string) http.Header {
	out := http.Header{}
	for _, name := range names {
		if v := h.Values(name); len(v) > 0 {
			out[name] = append([]string(nil), v...)
		}
	}
	return out
}

// uiAsk is one request of an opened page as it travels: a length, the head as
// JSON and the body.
type uiAsk struct {
	Method string      `json:"method"`
	Target string      `json:"target"`
	Header http.Header `json:"header,omitempty"`
	Jar    string      `json:"jar"`
	Prefix string      `json:"prefix"`
}

type uiAnswer struct {
	Status int         `json:"status"`
	Header http.Header `json:"header,omitempty"`
}

func frame(head any, body []byte) ([]byte, error) {
	h, err := json.Marshal(head)
	if err != nil {
		return nil, err
	}
	if len(h) > maxFrameHead || len(body) > maxFrameBody {
		return nil, errFrameTooLarge
	}
	out := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(h)+len(body)), uint32(len(h)))
	return append(append(out, h...), body...), nil
}

func unframe(raw []byte, head any) ([]byte, error) {
	if len(raw) < 4 {
		return nil, errors.New("fortress: a frame without its length")
	}
	n := int(binary.BigEndian.Uint32(raw))
	if n > len(raw)-4 {
		return nil, errors.New("fortress: a frame shorter than it says")
	}
	if err := json.Unmarshal(raw[4:4+n], head); err != nil {
		return nil, err
	}
	return raw[4+n:], nil
}

func (q uiAsk) encode(body []byte) ([]byte, error) { return frame(q, body) }

func decodeAsk(raw []byte) (uiAsk, []byte, error) {
	var q uiAsk
	body, err := unframe(raw, &q)
	return q, body, err
}

func decodeAnswer(raw []byte) (uiAnswer, []byte, error) {
	var a uiAnswer
	body, err := unframe(raw, &a)
	return a, body, err
}

// target checks the path and query an opened request asks for: one leading
// slash, no scheme, host or backslash, nothing a handler could read as
// another place.
func target(t string) (*url.URL, bool) {
	if !strings.HasPrefix(t, "/") || strings.HasPrefix(t, "//") || strings.ContainsAny(t, "\\") {
		return nil, false
	}
	for i := 0; i < len(t); i++ {
		if t[i] < 0x20 || t[i] == 0x7f {
			return nil, false
		}
	}
	u, err := url.ParseRequestURI(t)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
		return nil, false
	}
	return u, true
}

type openedKey struct{}

// Opened reports whether r came through the fortress and from whom.
func Opened(r *http.Request) (Caller, bool) {
	c, ok := r.Context().Value(openedKey{}).(Caller)
	return c, ok
}

// checkUI tells an opening member whether it may open this instance now.
func (f *Fortress) checkUI(w http.ResponseWriter, r *http.Request, caller string) {
	if f.ui == nil {
		writeError(w, http.StatusNotFound, "no_such_action")
		return
	}
	if _, ok := f.allowed(w, r, caller, OpenAction); !ok {
		f.dropCaller(caller)
		return
	}
	if !f.ui.SignIn() {
		writeError(w, http.StatusForbidden, "ui_no_login")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// serveUI runs one request of a page member caller opened through the app's
// own handler and answers what it wrote.
func (f *Fortress) serveUI(w http.ResponseWriter, r *http.Request, caller string) {
	if f.ui == nil {
		writeError(w, http.StatusNotFound, "no_such_action")
		return
	}
	if !f.jars.enter(caller) {
		writeError(w, http.StatusServiceUnavailable, "busy")
		return
	}
	defer f.jars.leave(caller)
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
	q, body, err := decodeAsk(raw)
	u, good := target(q.Target)
	if err != nil || !good || !uiMethods[q.Method] || !jarPattern.MatchString(q.Jar) || !prefixPattern.MatchString(q.Prefix) {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	j, fresh, ok := f.jars.take(caller, q.Jar, time.Now())
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "jars_full")
		return
	}
	if fresh {
		f.ui.Opened(from)
	}
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), openedKey{}, from), uiTimeout)
	defer cancel()
	stop := context.AfterFunc(r.Context(), cancel)
	defer stop()
	req, err := http.NewRequestWithContext(ctx, q.Method, q.Target, bytes.NewReader(body))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	req.URL, req.RequestURI, req.RemoteAddr, req.Host = u, q.Target, farAway, ""
	req.Header = only(q.Header, headersIn)
	req.Header.Set("X-Forwarded-Prefix", q.Prefix)
	for _, c := range f.jars.cookies(j) {
		req.AddCookie(c)
	}
	rec := &uiRecorder{header: http.Header{}, limit: f.uiLimit}
	f.ui.Handler.ServeHTTP(rec, req)
	if rec.over {
		writeError(w, http.StatusRequestEntityTooLarge, "too_large")
		return
	}
	f.jars.keep(j, rec.header, time.Now())
	header, out := pack(q.Header, only(rec.header, headersOut), rec.code(), rec.body.Bytes())
	if strings.HasPrefix(strings.ToLower(header.Get("Content-Type")), "multipart/x-mixed-replace") {
		writeError(w, http.StatusBadGateway, "bad_answer")
		return
	}
	framed, err := frame(uiAnswer{Status: rec.code(), Header: header}, out)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "too_large")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(framed)
}

// pack compresses text the handler left as it was, when the browser takes
// gzip, so that less of it crosses the relay.
func pack(asked, header http.Header, status int, body []byte) (http.Header, []byte) {
	if status != http.StatusOK || len(body) < packFrom || header.Get("Content-Encoding") != "" ||
		!strings.Contains(asked.Get("Accept-Encoding"), "gzip") || !compressible(header.Get("Content-Type")) {
		return header, body
	}
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	if _, err := z.Write(body); err != nil || z.Close() != nil {
		return header, body
	}
	header.Set("Content-Encoding", "gzip")
	header.Add("Vary", "Accept-Encoding")
	return header, b.Bytes()
}

func compressible(contentType string) bool {
	t, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return strings.HasPrefix(t, "text/") || strings.HasSuffix(t, "json") || strings.HasSuffix(t, "javascript") ||
		strings.HasSuffix(t, "+xml") || t == "application/xml"
}

// uiRecorder keeps what the opened app's handler writes, up to limit.
type uiRecorder struct {
	header http.Header
	status int
	body   bytes.Buffer
	limit  int
	over   bool
}

func (u *uiRecorder) Header() http.Header { return u.header }

func (u *uiRecorder) WriteHeader(status int) {
	if u.status == 0 {
		u.status = status
	}
}

func (u *uiRecorder) Write(b []byte) (int, error) {
	u.WriteHeader(http.StatusOK)
	if u.body.Len()+len(b) > u.limit {
		u.over = true
		return 0, errors.New("fortress: the answer is too large to open through the fortress")
	}
	return u.body.Write(b)
}

func (u *uiRecorder) Flush() {}

func (u *uiRecorder) code() int {
	if u.status == 0 {
		return http.StatusOK
	}
	return u.status
}

// jars are the cookies the opened app set for the members that opened it,
// one jar per member and sign-in there. They never leave this instance.
type jars struct {
	mu   sync.Mutex
	of   map[string]map[string]*jar
	all  int
	busy map[string]int
	sem  chan struct{}
}

type jar struct {
	cookies    map[string]string
	made, used time.Time
}

func newJars() jars {
	return jars{of: map[string]map[string]*jar{}, busy: map[string]int{}, sem: make(chan struct{}, maxUICalls)}
}

// enter lets one more request of caller run, unless too many run.
func (js *jars) enter(caller string) bool {
	select {
	case js.sem <- struct{}{}:
	default:
		return false
	}
	js.mu.Lock()
	defer js.mu.Unlock()
	if js.busy[caller] >= maxUICallsPerCaller {
		<-js.sem
		return false
	}
	js.busy[caller]++
	return true
}

func (js *jars) leave(caller string) {
	js.mu.Lock()
	if js.busy[caller]--; js.busy[caller] <= 0 {
		delete(js.busy, caller)
	}
	js.mu.Unlock()
	<-js.sem
}

// take returns caller's jar id and whether it is new. A new one is refused
// while caller or everybody holds as many as they may.
func (js *jars) take(caller, id string, now time.Time) (*jar, bool, bool) {
	js.mu.Lock()
	defer js.mu.Unlock()
	for c, of := range js.of {
		for k, j := range of {
			if now.Sub(j.used) > jarIdle || now.Sub(j.made) > jarLife {
				delete(of, k)
				js.all--
			}
		}
		if len(of) == 0 {
			delete(js.of, c)
		}
	}
	if j, ok := js.of[caller][id]; ok {
		j.used = now
		return j, false, true
	}
	if len(js.of[caller]) >= maxJarsPerCaller || js.all >= maxJars {
		return nil, false, false
	}
	if js.of[caller] == nil {
		js.of[caller] = map[string]*jar{}
	}
	j := &jar{cookies: map[string]string{}, made: now, used: now}
	js.of[caller][id] = j
	js.all++
	return j, true, true
}

func (js *jars) cookies(j *jar) []*http.Cookie {
	js.mu.Lock()
	defer js.mu.Unlock()
	out := make([]*http.Cookie, 0, len(j.cookies))
	for name, value := range j.cookies {
		out = append(out, &http.Cookie{Name: name, Value: value})
	}
	return out
}

// keep takes the cookies an answer sets into j and drops those it ends.
func (js *jars) keep(j *jar, header http.Header, now time.Time) {
	set := (&http.Response{Header: header}).Cookies()
	if len(set) == 0 {
		return
	}
	js.mu.Lock()
	defer js.mu.Unlock()
	for _, c := range set {
		_, held := j.cookies[c.Name]
		switch {
		case c.MaxAge < 0 || !c.Expires.IsZero() && c.Expires.Before(now):
			delete(j.cookies, c.Name)
		case len(c.Name)+len(c.Value) > maxCookieBytes:
		case held || len(j.cookies) < maxJarCookies:
			j.cookies[c.Name] = c.Value
		}
	}
}

// drop forgets every jar of caller, for a member taken out or refused.
func (js *jars) drop(caller string) {
	js.mu.Lock()
	defer js.mu.Unlock()
	js.all -= len(js.of[caller])
	delete(js.of, caller)
}

func (js *jars) count(caller string) int {
	js.mu.Lock()
	defer js.mu.Unlock()
	return len(js.of[caller])
}
