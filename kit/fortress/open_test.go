package fortress

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/group"
)

// webApp is an app's web interface with a login of its own: POST /login with
// the password "secret" sets a session cookie, and /private answers only with
// it. It records what reached it.
type webApp struct {
	mu       sync.Mutex
	seen     []*http.Request
	password bool
	opened   []Caller
}

func (a *webApp) ui() *UI {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		a.note(r)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		_, _ = io.WriteString(w, `<!doctype html><html><head><base href="`+r.Header.Get("X-Forwarded-Prefix")+`"></head><body>`+strings.Repeat("hello fortress ", 200)+`</body></html>`)
	})
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		a.note(r)
		body, _ := io.ReadAll(r.Body)
		if string(body) != "secret" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "s3cr3t", Path: "/", HttpOnly: true})
		http.Redirect(w, r, "/private", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /private", func(w http.ResponseWriter, r *http.Request) {
		a.note(r)
		if c, err := r.Cookie("session"); err != nil || c.Value != "s3cr3t" {
			http.Error(w, "sign in first", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "tracker=1; Path=/")
		w.Header().Set("Clear-Site-Data", `"cookies"`)
		w.Header().Set("Service-Worker-Allowed", "/")
		_, _ = io.WriteString(w, `{"secret":"inside"}`)
	})
	mux.HandleFunc("GET /away", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Query().Get("to"), http.StatusFound)
	})
	mux.HandleFunc("GET /big/{n}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		n, _ := strconv.Atoi(r.PathValue("n"))
		_, _ = w.Write(backupOf(n))
	})
	return &UI{
		Handler: mux,
		SignIn: func() bool {
			a.mu.Lock()
			defer a.mu.Unlock()
			return a.password
		},
		Opened: func(from Caller) {
			a.mu.Lock()
			defer a.mu.Unlock()
			a.opened = append(a.opened, from)
		},
	}
}

func (a *webApp) note(r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.seen = append(a.seen, r)
}

func (a *webApp) last() *http.Request {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.seen[len(a.seen)-1]
}

func (a *webApp) openings() []Caller {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]Caller(nil), a.opened...)
}

func (a *webApp) setPassword(on bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.password = on
}

// browser is the user's browser at the opening instance: its own session
// there is "own", and every request goes through the instance's OpenHandler.
type browser struct {
	t   *testing.T
	srv *httptest.Server
}

const ownSession = "own"

func browse(t *testing.T, at *node) *browser {
	t.Helper()
	h := at.f.OpenHandler(func(r *http.Request) (string, bool) {
		c, err := r.Cookie("own")
		return ownSession, err == nil && c.Value == ownSession
	}, func(_ *http.Request, code string) string { return "words for " + code })
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &browser{t: t, srv: srv}
}

// get asks for path the way a page in the sandbox does: no cookie of the
// opening instance and an opaque origin.
func (b *browser) get(path string, header ...string) *http.Response {
	return b.do(http.MethodGet, path, nil, header...)
}

func (b *browser) do(method, path string, body []byte, header ...string) *http.Response {
	b.t.Helper()
	req, err := http.NewRequest(method, b.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		b.t.Fatal(err)
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	b.t.Cleanup(func() { _ = res.Body.Close() })
	return res
}

func read(t *testing.T, res *http.Response) string {
	t.Helper()
	var r io.Reader = res.Body
	if res.Header.Get("Content-Encoding") == "gzip" {
		z, err := gzip.NewReader(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		r = z
	}
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// opening sets up alpha, which opens, and bravo, whose interface opens, on
// one relay. Bravo has a password unless said otherwise.
func opening(t *testing.T, withPassword bool) (a, b *node, app *webApp) {
	t.Helper()
	app = &webApp{password: withPassword}
	url := relayServer(t)
	a = open(t, "alpha", "alpha-1", setup{relay: url, uses: []string{OpenAction}, noPair: true})
	b = open(t, "bravo", "bravo-1", setup{relay: url, ui: app.ui(), noPair: true})
	meet(t, a, b)
	return a, b, app
}

func visit(a, b *node) Visit {
	return Visit{Member: b.id, Session: ownSession, Valid: func() bool { return true }, Back: "/settings/fortress"}
}

func TestAMemberOpensAnotherMembersInterfaceThroughTheRelay(t *testing.T) {
	a, b, app := opening(t, true)
	path, err := a.f.Open(ctx(t), visit(a, b))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(path, OpenPath) {
		t.Fatalf("path %q is not under %s", path, OpenPath)
	}
	br := browse(t, a)
	page := br.get(path+"/", "Accept-Encoding", "gzip")
	body := read(t, page)
	if page.StatusCode != http.StatusOK || !strings.Contains(body, "hello fortress") {
		t.Fatalf("page: %d %q", page.StatusCode, body)
	}
	if !strings.Contains(body, `<base href="`+path+`/">`) {
		t.Fatalf("the interface did not learn where it lives: %q", body[:200])
	}
	r := app.last()
	if r.RemoteAddr != "192.0.2.1:0" || r.Host != "" || r.Header.Get("X-Forwarded-Prefix") != path+"/" {
		t.Fatalf("the interface saw RemoteAddr %q, Host %q, prefix %q", r.RemoteAddr, r.Host, r.Header.Get("X-Forwarded-Prefix"))
	}
	if from, ok := Opened(r); !ok || from.ID != a.id || from.App != "alpha" {
		t.Fatalf("Opened = %+v, %v", from, ok)
	}
}

func TestEveryTunnelledAnswerRunsInASandboxOfItsOwn(t *testing.T) {
	a, b, _ := opening(t, true)
	path, err := a.f.Open(ctx(t), visit(a, b))
	if err != nil {
		t.Fatal(err)
	}
	page := browse(t, a).get(path+"/", "Origin", "null")
	csp := page.Header.Values("Content-Security-Policy")
	sandboxed := false
	for _, p := range csp {
		if strings.HasPrefix(p, "sandbox ") && !strings.Contains(p, "allow-same-origin") && !strings.Contains(p, "allow-top-navigation") &&
			!strings.Contains(p, "allow-popups-to-escape-sandbox") && !strings.Contains(p, "allow-modals") && strings.Contains(p, "frame-ancestors 'self'") {
			sandboxed = true
		}
	}
	if !sandboxed {
		t.Fatalf("no sandbox among %q", csp)
	}
	if !contains(csp, "default-src 'self'") {
		t.Fatalf("the interface's own policy is lost: %q", csp)
	}
	for name, want := range map[string]string{
		"Referrer-Policy":              "no-referrer",
		"X-Content-Type-Options":       "nosniff",
		"Access-Control-Allow-Origin":  "null",
		"Cache-Control":                "no-store",
		"Cross-Origin-Opener-Policy":   "",
		"Access-Control-Allow-Headers": "",
	} {
		if got := page.Header.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func TestTheSignInOfTheOpenedAppStaysWithIt(t *testing.T) {
	a, b, app := opening(t, true)
	path, err := a.f.Open(ctx(t), visit(a, b))
	if err != nil {
		t.Fatal(err)
	}
	br := browse(t, a)
	if res := br.get(path + "/private"); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("private before signing in: %d", res.StatusCode)
	}
	login := br.do(http.MethodPost, path+"/login", []byte("secret"), "Cookie", "own=own; session=forged", "Authorization", "Basic cHJveHk6cGFzcw==")
	if login.StatusCode != http.StatusSeeOther || login.Header.Get("Location") != path+"/private" {
		t.Fatalf("login: %d to %q", login.StatusCode, login.Header.Get("Location"))
	}
	if len(login.Cookies()) != 0 || login.Header.Get("Set-Cookie") != "" {
		t.Fatalf("the browser got a cookie: %q", login.Header.Values("Set-Cookie"))
	}
	if r := app.last(); r.Header.Get("Authorization") != "" || len(r.Cookies()) != 0 {
		t.Fatalf("the opened app saw the opener's credentials: %q %q", r.Header.Get("Authorization"), r.Header.Values("Cookie"))
	}
	private := br.get(path + "/private")
	if private.StatusCode != http.StatusOK || read(t, private) != `{"secret":"inside"}` {
		t.Fatalf("private after signing in: %d", private.StatusCode)
	}
	for _, h := range []string{"Set-Cookie", "Clear-Site-Data", "Service-Worker-Allowed"} {
		if private.Header.Get(h) != "" {
			t.Errorf("%s reached the browser", h)
		}
	}
	if got := app.openings(); len(got) != 1 || got[0].ID != a.id || got[0].Device != "alpha-1" {
		t.Fatalf("openings = %+v", got)
	}
	again, err := a.f.Open(ctx(t), visit(a, b))
	if err != nil {
		t.Fatal(err)
	}
	if again == path {
		t.Fatal("a second tab got the same ticket")
	}
	if res := br.get(again + "/private"); res.StatusCode != http.StatusOK {
		t.Fatalf("a second tab of the same sign-in lost the opened app's session: %d", res.StatusCode)
	}
	if got := app.openings(); len(got) != 1 {
		t.Fatalf("one sign-in was logged %d times", len(got))
	}
}

func TestAnAppWithoutItsOwnSignInOpensNothing(t *testing.T) {
	a, b, app := opening(t, false)
	if _, err := a.f.Open(ctx(t), visit(a, b)); refusalCode(err) != "ui_no_login" {
		t.Fatalf("Open = %v, want ui_no_login", err)
	}
	app.setPassword(true)
	path, err := a.f.Open(ctx(t), visit(a, b))
	if err != nil {
		t.Fatal(err)
	}
	br := browse(t, a)
	if res := br.get(path + "/"); res.StatusCode != http.StatusOK {
		t.Fatalf("with a password: %d", res.StatusCode)
	}
	app.setPassword(false)
	if res := br.get(path + "/"); res.StatusCode == http.StatusOK {
		t.Fatal("an open tunnel kept working after the password was removed")
	}
}

func TestOpeningNeedsThePermissionAndStopsWhenItIsSwitchedOff(t *testing.T) {
	a, b, _ := opening(t, true)
	path, err := a.f.Open(ctx(t), visit(a, b))
	if err != nil {
		t.Fatal(err)
	}
	br := browse(t, a)
	if res := br.get(path + "/"); res.StatusCode != http.StatusOK {
		t.Fatalf("before: %d", res.StatusCode)
	}
	if err := b.f.SetPermission("alpha", "bravo", OpenAction, false); err != nil {
		t.Fatal(err)
	}
	res := br.get(path+"/", "Sec-Fetch-Dest", "iframe")
	if body := read(t, res); res.StatusCode != http.StatusForbidden || !strings.Contains(body, "words for permission_off") || !strings.Contains(body, "color:CanvasText") {
		t.Fatalf("an open tunnel after the switch went off: %d", res.StatusCode)
	}
	if _, err := a.f.Open(ctx(t), visit(a, b)); !errors.Is(err, ErrPermissionOff) {
		t.Fatalf("Open = %v, want ErrPermissionOff", err)
	}
}

func TestAnAppThatDoesNotSayItOpensOthersOpensNothing(t *testing.T) {
	app := &webApp{password: true}
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url, noPair: true})
	b := open(t, "bravo", "bravo-1", setup{relay: url, ui: app.ui(), noPair: true})
	meet(t, a, b)
	if _, err := a.f.Open(ctx(t), visit(a, b)); !errors.Is(err, ErrNotUsed) {
		t.Fatalf("Open = %v, want ErrNotUsed", err)
	}
}

func TestAMemberWithoutAnInterfaceHasNothingToOpen(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url, uses: []string{OpenAction}, noPair: true})
	b := open(t, "bravo", "bravo-1", setup{relay: url, noPair: true})
	meet(t, a, b)
	if _, err := a.f.Open(ctx(t), visit(a, b)); !errors.Is(err, ErrNoSuchAction) {
		t.Fatalf("Open = %v, want ErrNoSuchAction", err)
	}
}

func TestAMemberThatIsAwayIsNotOpened(t *testing.T) {
	a, b, _ := opening(t, true)
	if err := a.f.Close(); err != nil {
		t.Fatal(err)
	}
	a.f = reopen(t, a, setup{uses: []string{OpenAction}, noPair: true})
	if _, err := a.f.Open(ctx(t), visit(a, b)); !errors.Is(err, group.ErrUnreachable) {
		t.Fatalf("Open = %v, want ErrUnreachable", err)
	}
}

func TestAMemberTakenOutLosesItsOpenTunnelsAtOnce(t *testing.T) {
	a, b, _ := opening(t, true)
	path, err := a.f.Open(ctx(t), visit(a, b))
	if err != nil {
		t.Fatal(err)
	}
	br := browse(t, a)
	if res := br.do(http.MethodPost, path+"/login", []byte("secret")); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("login: %d", res.StatusCode)
	}
	if err := b.f.Remove(a.id); err != nil {
		t.Fatal(err)
	}
	if res := br.get(path + "/private"); res.StatusCode == http.StatusOK {
		t.Fatal("a member taken out still reached the interface")
	}
	if jars := b.f.jars.count(a.id); jars != 0 {
		t.Fatalf("bravo still keeps %d sessions for the member it took out", jars)
	}
}

func TestTheOpenerLetsGoOfAMemberItTookOut(t *testing.T) {
	a, b, _ := opening(t, true)
	path, err := a.f.Open(ctx(t), visit(a, b))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.f.Remove(b.id); err != nil {
		t.Fatal(err)
	}
	if res := browse(t, a).get(path + "/"); res.StatusCode == http.StatusOK {
		t.Fatal("the ticket outlived the member")
	}
}

func TestTheShellNeedsTheOpenersOwnSignIn(t *testing.T) {
	a, b, _ := opening(t, true)
	path, err := a.f.Open(ctx(t), visit(a, b))
	if err != nil {
		t.Fatal(err)
	}
	br := browse(t, a)
	if res := br.get(path); res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/settings/fortress" {
		t.Fatalf("shell without a session: %d to %q", res.StatusCode, res.Header.Get("Location"))
	}
	shell := br.get(path, "Cookie", "own=own")
	html := read(t, shell)
	if shell.StatusCode != http.StatusOK || !strings.Contains(html, `<iframe`) || !strings.Contains(html, `src="`+strings.TrimPrefix(path, OpenPath)+`/"`) ||
		!strings.Contains(html, `sandbox="allow-scripts allow-forms allow-popups allow-downloads"`) || !strings.Contains(html, "App bravo") || !strings.Contains(html, "bravo-1") {
		t.Fatalf("shell: %d %s", shell.StatusCode, html)
	}
	if shell.Header.Get("Cross-Origin-Opener-Policy") != "same-origin" || shell.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("shell headers: %v", shell.Header)
	}
	other := a.f.OpenHandler(func(*http.Request) (string, bool) { return "someone else", true }, nil)
	rec := httptest.NewRecorder()
	other.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code == http.StatusOK {
		t.Fatal("another sign-in at the opener got the shell")
	}
}

func TestATicketEndsWithTheOpenersSignIn(t *testing.T) {
	a, b, _ := opening(t, true)
	var mu sync.Mutex
	valid := true
	v := visit(a, b)
	v.Valid = func() bool { mu.Lock(); defer mu.Unlock(); return valid }
	path, err := a.f.Open(ctx(t), v)
	if err != nil {
		t.Fatal(err)
	}
	br := browse(t, a)
	if res := br.get(path + "/"); res.StatusCode != http.StatusOK {
		t.Fatalf("before: %d", res.StatusCode)
	}
	mu.Lock()
	valid = false
	mu.Unlock()
	if res := br.get(path + "/"); res.StatusCode == http.StatusOK {
		t.Fatal("the ticket outlived the sign-in")
	}
	if res := br.get(OpenPath + "0123456789abcdef0123456789abcdef/"); res.StatusCode == http.StatusOK {
		t.Fatal("a made-up ticket opened something")
	}
}

func TestRedirectsStayInsideTheTunnel(t *testing.T) {
	a, b, _ := opening(t, true)
	path, err := a.f.Open(ctx(t), visit(a, b))
	if err != nil {
		t.Fatal(err)
	}
	br := browse(t, a)
	for to, want := range map[string]int{"/private": http.StatusFound, "//evil.example/": http.StatusBadGateway, "https://evil.example/": http.StatusBadGateway, `/\evil.example`: http.StatusBadGateway} {
		res := br.get(path + "/away?to=" + to)
		if res.StatusCode != want {
			t.Errorf("redirect to %q: %d, want %d", to, res.StatusCode, want)
		}
		if want == http.StatusFound && res.Header.Get("Location") != path+to {
			t.Errorf("redirect to %q went to %q", to, res.Header.Get("Location"))
		}
	}
}

func TestAPreflightIsAnsweredByTheOpener(t *testing.T) {
	a, b, app := opening(t, true)
	path, err := a.f.Open(ctx(t), visit(a, b))
	if err != nil {
		t.Fatal(err)
	}
	before := len(app.seen)
	res := browse(t, a).do(http.MethodOptions, path+"/login", nil, "Origin", "null", "Access-Control-Request-Method", "POST", "Access-Control-Request-Headers", "content-type, x-evil")
	if res.StatusCode != http.StatusNoContent || res.Header.Get("Access-Control-Allow-Origin") != "null" ||
		res.Header.Get("Access-Control-Allow-Headers") != "Content-Type" {
		t.Fatalf("preflight: %d %v", res.StatusCode, res.Header)
	}
	if len(app.seen) != before {
		t.Fatal("the preflight reached the opened app")
	}
}

func TestAServiceWorkerIsNeverRegisteredThroughTheTunnel(t *testing.T) {
	a, b, _ := opening(t, true)
	path, err := a.f.Open(ctx(t), visit(a, b))
	if err != nil {
		t.Fatal(err)
	}
	if res := browse(t, a).get(path+"/", "Service-Worker", "script"); res.StatusCode != http.StatusForbidden {
		t.Fatalf("service worker script: %d", res.StatusCode)
	}
}

func TestAnAnswerTooLargeForTheRelaySaysSo(t *testing.T) {
	a, b, _ := opening(t, true)
	path, err := a.f.Open(ctx(t), visit(a, b))
	if err != nil {
		t.Fatal(err)
	}
	res := browse(t, a).get(path+"/big/6000000", "Sec-Fetch-Dest", "iframe")
	if res.StatusCode != http.StatusRequestEntityTooLarge || !strings.Contains(read(t, res), "words for too_large") {
		t.Fatalf("large answer: %d", res.StatusCode)
	}
}

func TestTextIsPackedBeforeItTravels(t *testing.T) {
	a, b, _ := opening(t, true)
	path, err := a.f.Open(ctx(t), visit(a, b))
	if err != nil {
		t.Fatal(err)
	}
	res := browse(t, a).get(path+"/", "Accept-Encoding", "gzip")
	if res.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("Content-Encoding %q", res.Header.Get("Content-Encoding"))
	}
}

// ask sends a hand-made tunnel call from a to b, as a member that does not go
// through OpenHandler could.
func ask(t *testing.T, a, b *node, q uiAsk) (int, uiAnswer) {
	t.Helper()
	framed, err := q.encode(nil)
	if err != nil {
		t.Fatal(err)
	}
	status, out, err := a.f.group.Call(ctx(t), b.id, http.MethodPost, uiPath, framed)
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK {
		return status, uiAnswer{}
	}
	ans, _, err := decodeAnswer(out)
	if err != nil {
		t.Fatal(err)
	}
	return status, ans
}

func TestTheOpenedAppOnlyEverRunsItsOwnHandler(t *testing.T) {
	a, b, app := opening(t, true)
	for _, target := range []string{"http://evil.example/", "//evil.example/", `\\evil.example`, "evil", "", "/a\x00b"} {
		before := len(app.seen)
		status, _ := ask(t, a, b, uiAsk{Method: http.MethodGet, Target: target, Jar: "0123456789abcdef0123456789abcdef", Prefix: "/fortress/open/x/"})
		if status != http.StatusBadRequest || len(app.seen) != before {
			t.Errorf("target %q: %d", target, status)
		}
	}
	for _, method := range []string{"CONNECT", "TRACE", "OPTIONS"} {
		if status, _ := ask(t, a, b, uiAsk{Method: method, Target: "/", Jar: "0123456789abcdef0123456789abcdef", Prefix: "/fortress/open/x/"}); status != http.StatusBadRequest {
			t.Errorf("method %s: %d", method, status)
		}
	}
	if status, _ := ask(t, a, b, uiAsk{Method: http.MethodGet, Target: "/", Jar: "0123456789abcdef0123456789abcdef", Prefix: `/"><script>`}); status != http.StatusBadRequest {
		t.Errorf("a prefix that breaks out of the base element: %d", status)
	}
	status, ans := ask(t, a, b, uiAsk{Method: http.MethodGet, Target: "/", Jar: "0123456789abcdef0123456789abcdef", Prefix: "/fortress/open/x/",
		Header: http.Header{"X-Forwarded-For": {"127.0.0.1"}, "X-Real-Ip": {"127.0.0.1"}, "Cookie": {"session=s3cr3t"}, "X-Bravo-Peer": {"x"}, "Accept": {"text/html"}}})
	if status != http.StatusOK || ans.Status != http.StatusOK {
		t.Fatalf("plain page: %d %d", status, ans.Status)
	}
	r := app.last()
	for _, h := range []string{"X-Forwarded-For", "X-Real-Ip", "Cookie", "X-Bravo-Peer"} {
		if r.Header.Get(h) != "" {
			t.Errorf("%s reached the app", h)
		}
	}
	if r.Header.Get("Accept") != "text/html" {
		t.Error("Accept was lost")
	}
}

func TestTheOpenedAppKeepsItsOwnLimits(t *testing.T) {
	a, b, _ := opening(t, true)
	full := 0
	for i := range maxJarsPerCaller + 2 {
		jar := strings.Repeat(string(rune('a'+i%6)), 31) + string(rune('0'+i%10))
		status, _ := ask(t, a, b, uiAsk{Method: http.MethodGet, Target: "/", Jar: jar, Prefix: "/fortress/open/x/"})
		if status == http.StatusServiceUnavailable {
			full++
		}
	}
	if full != 2 {
		t.Fatalf("%d calls were turned away for full jars, want 2", full)
	}
}

func TestUIAskRoundTrips(t *testing.T) {
	q := uiAsk{Method: "POST", Target: "/x?y=1", Header: http.Header{"Content-Type": {"application/json"}}, Jar: "j", Prefix: "/p/"}
	framed, err := q.encode([]byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	got, body, err := decodeAsk(framed)
	if err != nil || string(body) != `{"a":1}` || got.Target != q.Target || got.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("%+v %q %v", got, body, err)
	}
	raw, _ := json.Marshal(q)
	if _, _, err := decodeAsk(raw); err == nil {
		t.Fatal("an ask without its length was read")
	}
	if _, _, err := decodeAsk([]byte{0, 0, 0, 200, '{'}); err == nil {
		t.Fatal("an ask shorter than it says was read")
	}
}

func TestAFrameWithAHeadOverTheLimitIsRefused(t *testing.T) {
	q := uiAsk{Method: "GET", Target: "/" + strings.Repeat("a", maxFrameHead)}
	if _, err := frame(q, nil); err == nil {
		t.Fatal("a head over the limit was framed")
	}
	if _, err := frame(uiAsk{Method: "GET", Target: "/"}, make([]byte, 64)); err != nil {
		t.Fatalf("a small frame was refused: %v", err)
	}
}

func TestATabBehindAProxyPrefixKeepsThePrefix(t *testing.T) {
	a, b, app := opening(t, true)
	path, err := a.f.Open(ctx(t), visit(a, b))
	if err != nil {
		t.Fatal(err)
	}
	br := browse(t, a)
	if res := br.get(path+"/", "X-Forwarded-Prefix", "/loader"); res.StatusCode != http.StatusOK {
		t.Fatalf("page: %d", res.StatusCode)
	}
	if got := app.last().Header.Get("X-Forwarded-Prefix"); got != "/loader"+path+"/" {
		t.Fatalf("the opened app sees the tab at %q", got)
	}
	res := br.get(path+"/away?to=/private", "X-Forwarded-Prefix", "/loader/")
	if loc := res.Header.Get("Location"); loc != "/loader"+path+"/private" {
		t.Fatalf("a redirect behind the prefix went to %q", loc)
	}
	br.get(path+"/", "X-Forwarded-Prefix", `/"><x`)
	if got := app.last().Header.Get("X-Forwarded-Prefix"); got != path+"/" {
		t.Fatalf("a prefix that is no path reached the opened app as %q", got)
	}
}

func TestAShellWithoutATicketLeadsHomeBehindTheProxyPrefix(t *testing.T) {
	a, _, _ := opening(t, true)
	br := browse(t, a)
	gone := OpenPath + "0123456789abcdef0123456789abcdef"
	for prefix, want := range map[string]string{"": "/", "/loader": "/loader/", "/loader/": "/loader/", `/"><x`: "/"} {
		res := br.get(gone, "Cookie", "own=own", "X-Forwarded-Prefix", prefix)
		if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != want {
			t.Errorf("prefix %q: %d to %q, want %q", prefix, res.StatusCode, res.Header.Get("Location"), want)
		}
	}
}
