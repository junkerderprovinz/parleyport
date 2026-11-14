package relay

import (
	"bytes"
	"context"
	"log"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// captureLog sends the standard logger to a buffer for the rest of the test.
func captureLog(t *testing.T) *safeBuffer {
	t.Helper()
	buf := &safeBuffer{b: &bytes.Buffer{}}
	prev := log.Writer()
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return buf
}

// logLine waits for a line that holds every one of want and returns it.
func logLine(t *testing.T, buf *safeBuffer, want ...string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for line := range strings.SplitSeq(buf.String(), "\n") {
			if containsAll(line, want) {
				return line
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no log line holds %q; the log is:\n%s", want, buf.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func containsAll(s string, parts []string) bool {
	for _, p := range parts {
		if !strings.Contains(s, p) {
			return false
		}
	}
	return true
}

const logTestKey = "log-test-relay-key-0123456789abcdef"

// The first four bytes of sha256(logTestKey), which is how the log names it.
const logTestKeyTag = "key 780a9f0f"

func TestAReplacedConnectionIsLoggedWithoutItsKey(t *testing.T) {
	buf := captureLog(t)
	s := New()
	old := joinUnproven(t, s, logTestKey, "alpha")
	joinUnproven(t, s, logTestKey, "alpha")

	line := logLine(t, buf, logTestKeyTag, `"alpha"`, "replaced by a newer connection with the same id")
	if strings.Contains(buf.String(), logTestKey) {
		t.Fatalf("the relay key reached the log: %s", line)
	}
	if !old.closed.Load() {
		t.Error("the replaced connection was left open")
	}
	if n := strings.Count(buf.String(), `"alpha"`); n != 1 {
		t.Errorf("the replacement was logged %d times, want once:\n%s", n, buf.String())
	}
}

func TestAClientThatHangsUpIsLoggedWithTheReadError(t *testing.T) {
	buf := captureLog(t)
	s := New()
	url := relayURL(t, s)
	c := dialInstance(t, url, logTestKey, alphaID)
	waitFor(t, "alpha to join", func() bool { return s.Len() == 1 })

	_ = c.CloseNow()

	line := logLine(t, buf, logTestKeyTag, alphaID[:16], "read:", "EOF")
	if strings.Contains(buf.String(), logTestKey) {
		t.Fatalf("the relay key reached the log: %s", line)
	}
	if strings.Contains(line, alphaID) {
		t.Errorf("the whole instance id reached the log, want it cut short: %s", line)
	}
}

func TestAClientThatSaysGoodbyeIsLoggedWithItsCloseStatus(t *testing.T) {
	buf := captureLog(t)
	s := New()
	c := dialInstance(t, relayURL(t, s), logTestKey, alphaID)
	waitFor(t, "alpha to join", func() bool { return s.Len() == 1 })

	_ = c.Close(websocket.StatusGoingAway, "")

	logLine(t, buf, logTestKeyTag, "read:", "StatusGoingAway")
}

func TestARefusedJoinIsLogged(t *testing.T) {
	buf := captureLog(t)
	s := New()
	url := relayURL(t, s)
	dialInstance(t, url, logTestKey, alphaID)
	waitFor(t, "alpha to join", func() bool { return s.Len() == 1 })

	// A hello without a proof cannot take an id whose holder proved it.
	ctx, cancel := context.WithTimeout(context.Background(), wsTimeout)
	defer cancel()
	c, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.CloseNow() })
	readFrame(t, c, TypeChallenge)
	writeFrame(t, c, TypeHello, Hello{Key: logTestKey, Announce: Announce{InstanceID: alphaID}})

	line := logLine(t, buf, logTestKeyTag, "turned away", errIDTaken.Error())
	if strings.Contains(buf.String(), logTestKey) {
		t.Fatalf("the relay key reached the log: %s", line)
	}
}

func TestAConnectionWithoutAHelloIsLogged(t *testing.T) {
	buf := captureLog(t)
	ctx, cancel := context.WithTimeout(context.Background(), wsTimeout)
	defer cancel()
	c, _, err := websocket.Dial(ctx, relayURL(t, New()), nil)
	if err != nil {
		t.Fatal(err)
	}
	readFrame(t, c, TypeChallenge)
	writeFrame(t, c, TypePresence, Presence{InstanceID: "alpha"})

	logLine(t, buf, "ended before its hello was accepted", "first frame is not a hello")
	_ = c.CloseNow()
}

func TestAnEvictedConnectionIsLogged(t *testing.T) {
	buf := captureLog(t)
	s := New()
	a := joinUnproven(t, s, logTestKey, "alpha")
	a.block = make(chan struct{})
	t.Cleanup(func() { close(a.block) })
	joinUnproven(t, s, logTestKey, "bravo")

	s.mu.Lock()
	cl := s.clients[a]
	s.mu.Unlock()
	for range queueDepth + 2 {
		s.enqueue(cl, frameOf(TypePresence, Presence{InstanceID: "bravo"}))
	}

	logLine(t, buf, logTestKeyTag, `"alpha"`, "queue")
}

func relayURL(t *testing.T, s *Server) string {
	t.Helper()
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http") + "/relay/connect"
}
