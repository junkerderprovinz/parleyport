package signin_test

import (
	"bytes"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/signin"
)

// logBuffer is the container log as a test reads it.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

var codeRE = regexp.MustCompile(`code=([A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4})`)

func (l *logBuffer) codes() []string {
	var out []string
	for _, m := range codeRE.FindAllStringSubmatch(l.String(), -1) {
		out = append(out, m[1])
	}
	return out
}

func withLog(l *logBuffer) option {
	return func(c *signin.Config) { c.Logger = slog.New(slog.NewTextHandler(l, nil)) }
}

func resetCode(t *testing.T, a *app, log *logBuffer) string {
	t.Helper()
	want(t, a.browser().api("POST", "reset-code", map[string]any{}), 200, "")
	codes := log.codes()
	if len(codes) == 0 {
		t.Fatalf("no code in the log: %s", log)
	}
	return codes[len(codes)-1]
}

func TestTheResetSetsANewPasswordAndEndsEverything(t *testing.T) {
	log := &logBuffer{}
	a := newApp(t, withLog(log))
	b := a.owner()
	twoFactor(t, a, b)
	want(t, b.api("POST", "me/tokens", map[string]any{"name": "script", "scopes": []string{"read"}}), 200, "")
	other := a.signIn()
	code := resetCode(t, a, log)

	c := a.browser()
	r := c.api("POST", "reset", map[string]string{"code": strings.ToLower(code), "password": "a brand new password"})
	want(t, r, 200, "")
	removed := r.json(t)["removed"].(map[string]any)
	if removed["tokens"] != float64(1) || removed["twoFactor"] != true {
		t.Fatalf("removed %v", removed)
	}
	if c.visitor().Via != signin.ViaPassword {
		t.Fatal("the reset did not sign this browser in")
	}
	if b.visitor().Via != "" || other.visitor().Via != "" {
		t.Fatal("a session survived the reset")
	}
	want(t, a.browser().api("POST", "login", map[string]string{"password": ownerPassword}), 401, "wrongPassword")
	r = a.browser().api("POST", "login", map[string]string{"password": "a brand new password"})
	if r.Status != 200 || r.json(t)["step"] != nil {
		t.Fatalf("the new password alone does not sign in: %d %s", r.Status, r.Body)
	}
	ended := strings.Join(a.endedWith(), " ")
	if !strings.Contains(ended, ":reset") {
		t.Fatalf("Ended = %s", ended)
	}
}

func TestAResetCodeCountsOnceAndForTenMinutes(t *testing.T) {
	log := &logBuffer{}
	a := newApp(t, withLog(log))
	a.owner()
	code := resetCode(t, a, log)
	want(t, a.browser().api("POST", "reset", map[string]string{"code": code, "password": "a brand new password"}), 200, "")
	want(t, a.browser().api("POST", "reset", map[string]string{"code": code, "password": "another new password"}), 401, "resetRefused")

	a.clock.Add(2 * time.Minute)
	late := resetCode(t, a, log)
	a.clock.Add(11 * time.Minute)
	want(t, a.browser().api("POST", "reset", map[string]string{"code": late, "password": "another new password"}), 401, "resetRefused")
}

func TestWrongResetCodesWaitForAll(t *testing.T) {
	log := &logBuffer{}
	a := newApp(t, withLog(log))
	a.owner()
	code := resetCode(t, a, log)
	for range 5 {
		a.browser().api("POST", "reset", map[string]string{"code": "AAAA-AAAA-AAAA", "password": "a brand new password"})
	}
	want(t, a.browser().api("POST", "reset", map[string]string{"code": code, "password": "a brand new password"}), 429, "throttled")
}

func TestTheResetCodeGoesToTheLogAtMostOnceAMinute(t *testing.T) {
	log := &logBuffer{}
	a := newApp(t, withLog(log))
	a.owner()
	resetCode(t, a, log)
	a.browser().api("POST", "reset-code", map[string]any{})
	if n := len(log.codes()); n != 1 {
		t.Fatalf("%d codes in the log", n)
	}
	a.clock.Add(61 * time.Second)
	resetCode(t, a, log)
	if n := len(log.codes()); n != 2 {
		t.Fatalf("%d codes in the log after a minute", n)
	}
}
