package fortress

import (
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"html/template"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/group"
	"github.com/junkerderprovinz/parleyport/kit/member"
)

// OpenPath is where an app mounts OpenHandler.
const OpenPath = "/fortress/open/"

const (
	// ticketIdle and ticketLife are how long an opened tab lives unused and
	// at most; maxTickets bounds the tabs open at a time, the oldest going
	// first.
	ticketIdle = 30 * time.Minute
	ticketLife = 12 * time.Hour
	maxTickets = 32
	// maxTabCalls bounds the requests of one tab on their way, maxOpenCalls
	// those of all tabs; the rest wait.
	maxTabCalls  = 4
	maxOpenCalls = 8
	// maxAskHead is room for the head of a request beside its body in one
	// call.
	maxAskHead = 16 << 10
	// sandbox is what an opened page may do. Without allow-same-origin it
	// runs in an origin of its own and reaches nothing of the app that opened
	// it; without allow-top-navigation it cannot replace the bar above it.
	sandbox = "allow-scripts allow-forms allow-popups allow-downloads"
	// maxAge caps how long the browser keeps an opened file.
	maxAge = 24 * time.Hour
)

// Visit is a signed-in user of this app opening member's web interface.
type Visit struct {
	// Member is the member's ID.
	Member string
	// Session names the user's sign-in here, which only a password session
	// may give: the opened app keeps that sign-in's session apart from any
	// other. It never leaves this instance.
	Session string
	// Valid reports whether that sign-in still stands; the tab closes once
	// it does not.
	Valid func() bool
	// Back is the page of this app the bar's close button leads to.
	Back string
}

type ticket struct {
	id, member, session, jar, back string
	valid                          func() bool
	made, used                     time.Time
	calls                          chan struct{}
	mu                             sync.Mutex
	streams                        int
}

// stream lets one more live stream of the tab run, unless too many do.
func (t *ticket) stream() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.streams >= maxTabStreams {
		return false
	}
	t.streams++
	return true
}

func (t *ticket) unstream() {
	t.mu.Lock()
	t.streams--
	t.mu.Unlock()
}

type tickets struct {
	mu   sync.Mutex
	byID map[string]*ticket
}

// get returns ticket id while it lives.
func (ts *tickets) get(id string, now time.Time) *ticket {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	t := ts.byID[id]
	if t == nil {
		return nil
	}
	if now.Sub(t.used) > ticketIdle || now.Sub(t.made) > ticketLife {
		delete(ts.byID, id)
		return nil
	}
	return t
}

func (ts *tickets) use(t *ticket, now time.Time) {
	ts.mu.Lock()
	t.used = now
	ts.mu.Unlock()
}

func (ts *tickets) add(t *ticket) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.byID == nil {
		ts.byID = map[string]*ticket{}
	}
	for len(ts.byID) >= maxTickets {
		var oldest *ticket
		for _, o := range ts.byID {
			if oldest == nil || o.used.Before(oldest.used) {
				oldest = o
			}
		}
		delete(ts.byID, oldest.id)
	}
	ts.byID[t.id] = t
}

func (ts *tickets) end(id string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	delete(ts.byID, id)
}

// dropMember ends every tab open on member.
func (ts *tickets) dropMember(member string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	for id, t := range ts.byID {
		if t.member == member {
			delete(ts.byID, id)
		}
	}
}

// Open asks member v.Member whether its interface opens for this app now and
// returns the path of a new tab on it, under OpenPath. It fails with
// group.ErrNoSuchMember, group.ErrUnreachable, ErrNoSuchAction for a member
// without an interface, ErrPermissionOff (ErrNotUsed when Config.Uses lacks
// OpenAction) or a *Refusal, such as "ui_no_login" for a member that asks
// for no sign-in of its own.
func (f *Fortress) Open(ctx context.Context, v Visit) (string, error) {
	if v.Member == "" || v.Session == "" || v.Valid == nil {
		return "", errors.New("fortress: a visit needs a member, a session and Valid")
	}
	m, ok := f.member(v.Member)
	switch {
	case !ok:
		return "", group.ErrNoSuchMember
	case m.Kind != member.KindInstance || !slices.Contains(m.Actions, OpenAction):
		return "", ErrNoSuchAction
	case !slices.Contains(f.about.Uses, OpenAction):
		return "", ErrNotUsed
	case !m.Online():
		return "", group.ErrUnreachable
	}
	status, body, err := f.group.Call(ctx, v.Member, http.MethodPost, uiCheckPath, nil)
	if err != nil {
		return "", err
	}
	if status != http.StatusNoContent {
		return "", f.refused(v.Member, status, body)
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, f.jarKey)
	mac.Write([]byte(v.Session + "\x00" + v.Member))
	now := time.Now()
	t := &ticket{
		id: hex.EncodeToString(raw), member: v.Member, session: v.Session, back: v.Back, valid: v.Valid,
		jar:  hex.EncodeToString(mac.Sum(nil)[:16]),
		made: now, used: now, calls: make(chan struct{}, maxTabCalls),
	}
	f.tickets.add(t)
	return OpenPath + t.id, nil
}

func (f *Fortress) member(id string) (Member, bool) {
	for _, m := range f.Members() {
		if m.ID == id {
			return m, true
		}
	}
	return Member{}, false
}

// OpenHandler serves the tabs Open made: at the path Open returned a bar
// naming the member above a sandboxed frame, below it the member's
// interface, each request taken there through the fortress. The app mounts
// it at OpenPath without its own sign-in in front: session names the
// password session a request carries, which the bar needs and the requests
// of the sandboxed page cannot carry. words says why a page did not open, in
// the language r asks for; nil takes Words.
func (f *Fortress) OpenHandler(session func(r *http.Request) (string, bool), words func(r *http.Request, code string) string) http.Handler {
	if words == nil {
		words = Words
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest, ok := strings.CutPrefix(r.URL.EscapedPath(), OpenPath)
		if !ok {
			http.NotFound(w, r)
			return
		}
		id, sub, inside := strings.Cut(rest, "/")
		t := f.tickets.get(id, time.Now())
		if t != nil && !t.valid() {
			f.tickets.end(id)
			t = nil
		}
		if !inside {
			f.serveShell(w, r, t, session)
			return
		}
		if t == nil {
			f.refuse(w, r, http.StatusGone, "closed", words)
			return
		}
		f.tunnel(w, r, t, "/"+sub, words)
	})
}

var shellPage = template.Must(template.New("shell").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.App}} · {{.Device}}</title>
<style>
:root{color-scheme:light dark;--bar:#f3f1ec;--ink:#1d1b18;--muted:#6b665e;--line:#d9d4ca}
@media (prefers-color-scheme:dark){:root{--bar:#1c1b19;--ink:#f0ede6;--muted:#a39d92;--line:#34312c}}
html,body{margin:0;height:100%;background:var(--bar);color:var(--ink);font:14px/1.3 system-ui,sans-serif}
body{display:flex;flex-direction:column}
header{display:flex;align-items:center;gap:10px;padding:6px 12px;border-bottom:1px solid var(--line);min-height:32px}
header img{width:24px;height:24px}
header b{font-weight:600}
header span{color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
header code{color:var(--muted);font-size:12px}
header a{margin-left:auto;color:var(--ink);text-decoration:none;font-size:20px;line-height:1;padding:2px 8px;border-radius:6px}
header a:hover{background:var(--line)}
iframe{flex:1;border:0;width:100%;background:#fff}
</style></head>
<body><header>{{if .Icon}}<img src="{{.Icon}}" alt="">{{end}}<b>{{.App}}</b><span>{{.Device}}</span><code title="{{.ID}}">{{.Print}}</code><a href="{{.Back}}" aria-label="×">×</a></header>
<iframe src="{{.Frame}}" title="{{.App}}" sandbox="` + sandbox + `" referrerpolicy="no-referrer"></iframe>
</body></html>`))

// serveShell answers the tab itself: the bar that says whose interface this
// is, which the member's page below cannot replace. It needs the sign-in the
// tab was opened with.
func (f *Fortress) serveShell(w http.ResponseWriter, r *http.Request, t *ticket, session func(*http.Request) (string, bool)) {
	if t == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s, ok := session(r)
	if !ok || subtle.ConstantTimeCompare([]byte(s), []byte(t.session)) != 1 {
		http.Redirect(w, r, cmp.Or(t.back, "/"), http.StatusSeeOther)
		return
	}
	f.tickets.use(t, time.Now())
	m, _ := f.member(t.member)
	a := f.aboutOf(t.member)
	short := t.member
	if len(short) > 8 {
		short = short[len(short)-8:]
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	_ = shellPage.Execute(w, map[string]any{
		"App": cmp.Or(a.App.Name, a.App.ID), "Device": m.Device, "ID": t.member, "Print": short,
		"Icon": template.URL(a.App.Icon), "Back": cmp.Or(t.back, "/"), "Frame": t.id + "/",
	})
}

// guard sets what every answer of an opened page carries: a sandbox of its
// own, framed only by the bar, and nothing that leaks the tab's path.
func guard(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Add("Content-Security-Policy", "sandbox "+sandbox+"; frame-ancestors 'self'")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	if r.Header.Get("Origin") == "null" {
		h.Set("Access-Control-Allow-Origin", "null")
	}
	h.Add("Vary", "Origin")
}

// refuse answers a page that cannot be opened with words for a page and a
// code for a script.
func (f *Fortress) refuse(w http.ResponseWriter, r *http.Request, status int, code string, words func(*http.Request, string) string) {
	guard(w, r)
	w.Header().Set("Cache-Control", "no-store")
	dest := r.Header.Get("Sec-Fetch-Dest")
	if dest == "iframe" || dest == "document" || dest == "" && strings.Contains(r.Header.Get("Accept"), "text/html") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">`+
			`<style>:root{color-scheme:light dark}body{font:15px/1.4 system-ui,sans-serif;display:grid;place-items:center;min-height:90vh;margin:0;padding:16px;text-align:center}</style>`+
			`<p>`+template.HTMLEscapeString(words(r, code))+`</p>`)
		return
	}
	writeError(w, status, code)
}

// tunnel takes one request of an opened page to its member and answers what
// came back.
func (f *Fortress) tunnel(w http.ResponseWriter, r *http.Request, t *ticket, path string, words func(*http.Request, string) string) {
	if r.Header.Get("Service-Worker") != "" {
		guard(w, r)
		writeError(w, http.StatusForbidden, "no_service_worker")
		return
	}
	if r.Method == http.MethodOptions {
		preflight(w, r)
		return
	}
	target := path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	if socket := strings.EqualFold(r.Header.Get("Upgrade"), "websocket"); r.Method == http.MethodGet && (socket || strings.Contains(r.Header.Get("Accept"), "text/event-stream")) {
		f.tunnelStream(w, r, t, target, socket, words)
		return
	}
	select {
	case t.calls <- struct{}{}:
	case <-r.Context().Done():
		return
	}
	defer func() { <-t.calls }()
	select {
	case f.opening <- struct{}{}:
	case <-r.Context().Done():
		return
	}
	defer func() { <-f.opening }()
	f.tickets.use(t, time.Now())

	body, err := io.ReadAll(io.LimitReader(r.Body, group.MaxCallBytes-maxAskHead+1))
	if err != nil {
		f.refuse(w, r, http.StatusBadRequest, "bad_request", words)
		return
	}
	if len(body) > group.MaxCallBytes-maxAskHead {
		f.refuse(w, r, http.StatusRequestEntityTooLarge, "too_large", words)
		return
	}
	header := only(r.Header, headersIn)
	header.Del("Accept-Encoding")
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		header.Set("Accept-Encoding", "gzip")
	}
	prefix := tabPath(r, t)
	ask := uiAsk{Method: r.Method, Target: target, Header: header, Jar: t.jar, Prefix: prefix + "/"}
	status, out, err := f.group.Call(r.Context(), t.member, http.MethodPost, uiPath, ask.encode(body))
	switch {
	case errors.Is(err, group.ErrRemoved) || errors.Is(err, group.ErrNoSuchMember):
		f.tickets.dropMember(t.member)
		f.refuse(w, r, http.StatusGone, "removed", words)
		return
	case err != nil:
		f.refuse(w, r, http.StatusBadGateway, "unreachable", words)
		return
	case status != http.StatusOK:
		code, status := refusedCode(status, out)
		if code == "removed" {
			f.tickets.dropMember(t.member)
		}
		f.refuse(w, r, status, code, words)
		return
	}
	ans, content, err := decodeAnswer(out)
	if err != nil {
		f.refuse(w, r, http.StatusBadGateway, "bad_answer", words)
		return
	}
	h := only(ans.Header, headersOut)
	if loc := h.Get("Location"); loc != "" {
		inside, ok := within(loc, prefix)
		if !ok {
			f.refuse(w, r, http.StatusBadGateway, "bad_answer", words)
			return
		}
		h.Set("Location", inside)
	}
	if strings.HasPrefix(strings.ToLower(h.Get("Content-Type")), "multipart/x-mixed-replace") {
		f.refuse(w, r, http.StatusBadGateway, "bad_answer", words)
		return
	}
	h.Set("Cache-Control", caching(ans.Status, h))
	for name, values := range h {
		w.Header()[name] = values
	}
	guard(w, r)
	w.WriteHeader(ans.Status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(content)
	}
}

// refusedCode is what the opening member tells the browser about a refusal.
func refusedCode(status int, body []byte) (string, int) {
	err := refusal(status, body)
	switch {
	case errors.Is(err, ErrPermissionOff):
		return "permission_off", http.StatusForbidden
	case errors.Is(err, ErrNoSuchAction):
		return "no_ui", http.StatusNotFound
	}
	var no *Refusal
	if !errors.As(err, &no) {
		return "unreachable", http.StatusBadGateway
	}
	switch no.Code {
	case "too_large", "answerTooLarge":
		return "too_large", http.StatusRequestEntityTooLarge
	case "ui_no_login":
		return "ui_no_login", http.StatusForbidden
	case "busy", "jars_full":
		return "busy", http.StatusServiceUnavailable
	case "removed", phraseChanged, "groupClosed", "forbidden":
		return "removed", http.StatusGone
	}
	return "unreachable", http.StatusBadGateway
}

// tabPath is where the browser sees the tab: OpenPath and the ticket, behind
// the path prefix a reverse proxy in front of the app names. A forged prefix
// only misleads the browser that sent it.
func tabPath(r *http.Request, t *ticket) string {
	base := strings.TrimSuffix(r.Header.Get("X-Forwarded-Prefix"), "/")
	if base != "" && !prefixPattern.MatchString(base+"/") {
		base = ""
	}
	return base + OpenPath + t.id
}

// within places a redirect the opened app answered under the tab's prefix.
// Anything that would lead elsewhere is no answer.
func within(loc, prefix string) (string, bool) {
	if !strings.HasPrefix(loc, "/") || strings.HasPrefix(loc, "//") || strings.ContainsAny(loc, "\\\r\n") {
		return "", false
	}
	if strings.HasPrefix(loc, prefix+"/") {
		return loc, true
	}
	return prefix + loc, true
}

// caching is how long the browser keeps an opened answer: a page never, so
// that nothing of it outlives the tab, anything else privately and a day at
// most.
func caching(status int, h http.Header) string {
	given := strings.ToLower(h.Get("Cache-Control"))
	if status != http.StatusOK || strings.HasPrefix(strings.ToLower(h.Get("Content-Type")), "text/html") || strings.Contains(given, "no-store") {
		return "no-store"
	}
	age := -1
	for _, part := range strings.Split(given, ",") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(part), "max-age="); ok {
			if n, err := strconv.Atoi(v); err == nil {
				age = n
			}
		}
	}
	if age < 0 {
		return "private, no-cache"
	}
	out := "private, max-age=" + strconv.Itoa(min(age, int(maxAge.Seconds())))
	if strings.Contains(given, "immutable") {
		out += ", immutable"
	}
	return out
}

// preflight answers a sandboxed page's preflight here: the methods and
// headers that reach the opened app, nothing else.
func preflight(w http.ResponseWriter, r *http.Request) {
	guard(w, r)
	h := w.Header()
	var allowed []string
	for _, name := range strings.Split(r.Header.Get("Access-Control-Request-Headers"), ",") {
		name = http.CanonicalHeaderKey(strings.TrimSpace(name))
		if slices.Contains(headersIn, name) && name != "Accept-Encoding" {
			allowed = append(allowed, name)
		}
	}
	h.Set("Access-Control-Allow-Methods", "GET, HEAD, POST, PUT, PATCH, DELETE")
	if len(allowed) > 0 {
		h.Set("Access-Control-Allow-Headers", strings.Join(allowed, ", "))
	}
	h.Set("Access-Control-Max-Age", "600")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
