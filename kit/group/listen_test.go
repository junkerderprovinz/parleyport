package group

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// trickle sends calls to n's direct route that look like a member's from
// their headers alone, with no key behind them, and their bodies a byte at a
// time, until the test ends.
func trickle(t *testing.T, n *node, calls int) {
	t.Helper()
	h := headersFor(testDomain)
	addr := strings.TrimPrefix(n.srv.URL, "http://")
	done := make(chan struct{})
	var wg sync.WaitGroup
	t.Cleanup(func() { close(done); wg.Wait() })
	for i := range calls {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: 4096\r\n%s: stranger-%d\r\n%s: %s\r\n%s: %d\r\n%s: %064x\r\n%s: %064x\r\n\r\n",
			DirectPath, addr, h.peer, i, h.target, n.id, h.time, time.Now().Unix(), h.signature, i, h.head, i); err != nil {
			t.Fatal(err)
		}
		wg.Go(func() {
			defer conn.Close() //nolint:errcheck // the test is over
			for {
				select {
				case <-done:
					return
				case <-time.After(200 * time.Millisecond):
					if _, err := conn.Write([]byte("{")); err != nil {
						return
					}
				}
			}
		})
	}
}

func TestAStrangerSendingSlowlyKeepsNoMemberWaiting(t *testing.T) {
	a, b := onOneNetwork(t, setup{})
	meet(t, a, b)
	trickle(t, b, 2*maxDirectCalls)
	time.Sleep(300 * time.Millisecond)
	start := time.Now()
	if id := whoami(t, a, b); id != a.id {
		t.Errorf("bravo's app saw %q, want alpha", id)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("alpha's call took %v while strangers sent slowly", took)
	}
}

func TestACallWithoutAHeadTagStillGetsThrough(t *testing.T) {
	a, b := onOneNetwork(t, setup{})
	req, body := direct(t, a, b, "/api/whoami")
	req.Header.Del(headersFor(testDomain).head)
	if w := serveDirect(b.g, req, body); w.Code != http.StatusOK {
		t.Errorf("= %d %s, want 200", w.Code, w.Body)
	}
}

func TestAForgedHeadTagIsTurnedAwayBeforeTheBody(t *testing.T) {
	a, b := onOneNetwork(t, setup{})
	req, body := direct(t, a, b, "/api/whoami")
	h := headersFor(testDomain)
	req.Header.Set(h.head, headSignature(make([]byte, 32), a.id, b.id, req.Header.Get(h.time), req.Header.Get(h.request), int64(len(body))))
	if w := serveDirect(b.g, req, body); w.Code != http.StatusForbidden {
		t.Errorf("= %d %s, want 403", w.Code, w.Body)
	}
}

// listenDirect serves g's direct route the way a member with a port of its
// own does, and returns its address.
func listenDirect(t *testing.T, g *Group) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := ServeDirect(ln, g.DirectHandler())
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

// ask sends one request for DirectPath on conn and reads the status of the
// answer.
func ask(conn net.Conn, r *bufio.Reader, addr string) (int, error) {
	if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", DirectPath, addr); err != nil {
		return 0, err
	}
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

func TestADirectListenerLetsAnIdleConnectionGo(t *testing.T) {
	idle := directIdle
	directIdle = 200 * time.Millisecond
	t.Cleanup(func() { directIdle = idle })
	n := open(t, "alpha", setup{})
	addr := listenDirect(t, n.g)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() //nolint:errcheck // a read-only test connection
	r := bufio.NewReader(conn)
	if status, err := ask(conn, r, addr); err != nil || status != http.StatusMethodNotAllowed {
		t.Fatalf("the first request = %d, %v", status, err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := r.ReadByte(); err != io.EOF {
		t.Errorf("an idle connection is still open: %v", err)
	}
}

func TestADirectListenerHoldsABoundedNumberOfConnections(t *testing.T) {
	most := maxDirectConns
	maxDirectConns = 2
	t.Cleanup(func() { maxDirectConns = most })
	n := open(t, "alpha", setup{})
	addr := listenDirect(t, n.g)
	var held []net.Conn
	for range maxDirectConns {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		r := bufio.NewReader(conn)
		if _, err := ask(conn, r, addr); err != nil {
			t.Fatal(err)
		}
		held = append(held, conn)
	}
	extra, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close() //nolint:errcheck // a read-only test connection
	answered := make(chan int, 1)
	go func() {
		status, _ := ask(extra, bufio.NewReader(extra), addr)
		answered <- status
	}()
	select {
	case status := <-answered:
		t.Fatalf("a connection over the limit was answered %d", status)
	case <-time.After(300 * time.Millisecond):
	}
	_ = held[0].Close()
	select {
	case status := <-answered:
		if status != http.StatusMethodNotAllowed {
			t.Errorf("the waiting connection got %d", status)
		}
	case <-time.After(5 * time.Second):
		t.Error("the waiting connection was not answered once another closed")
	}
	for _, c := range held[1:] {
		_ = c.Close()
	}
}

func TestADirectListenerHoldsFewConnectionsFromOneAddress(t *testing.T) {
	most := maxConnsFromSource
	maxConnsFromSource = 2
	t.Cleanup(func() { maxConnsFromSource = most })
	n := open(t, "alpha", setup{})
	addr := listenDirect(t, n.g)
	var held []net.Conn
	t.Cleanup(func() {
		for _, c := range held {
			_ = c.Close()
		}
	})
	for range maxConnsFromSource {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, conn)
	}
	extra, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close() //nolint:errcheck // a read-only test connection
	_ = extra.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := extra.Read(make([]byte, 1)); err != io.EOF {
		t.Errorf("a connection over what one address may hold stays open: %v", err)
	}
}

func TestAHeadTagIsTakenOnce(t *testing.T) {
	a, b := onOneNetwork(t, setup{})
	req, body := direct(t, a, b, "/api/whoami")
	if w := serveDirect(b.g, req, body); w.Code != http.StatusOK {
		t.Fatalf("first = %d %s", w.Code, w.Body)
	}
	// The same headers again, with a body that never comes.
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	r := httptest.NewRequest(http.MethodPost, DirectPath, pr)
	r.Header = req.Header.Clone()
	r.ContentLength = int64(len(body))
	done := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		b.g.DirectHandler().ServeHTTP(w, r)
		done <- w.Code
	}()
	select {
	case code := <-done:
		if code != http.StatusForbidden {
			t.Errorf("again = %d, want 403", code)
		}
	case <-time.After(2 * time.Second):
		t.Error("a head tag seen before waits for its body")
	}
}

func TestABodyMustCarryTheRequestItsHeadNames(t *testing.T) {
	a, b := onOneNetwork(t, setup{})
	req, _ := direct(t, a, b, "/api/whoami")
	_, other := direct(t, a, b, "/api/whoami")
	h := headersFor(testDomain)
	req.Header.Set(h.head, headSignature(a.g.peerAuth, a.id, b.id, req.Header.Get(h.time), req.Header.Get(h.request), int64(len(other))))
	if w := serveDirect(b.g, req, signedBody(a, req, other)); w.Code != http.StatusForbidden {
		t.Errorf("= %d %s, want 403", w.Code, w.Body)
	}
}

func TestAFullHeadCacheStillTakesAFreshCall(t *testing.T) {
	a, b := onOneNetwork(t, setup{})
	now := time.Now()
	for i := range maxHeadsKept {
		b.g.heads.first(fmt.Sprintf("member\x00%d", i), now, now)
	}
	req, body := direct(t, a, b, "/api/whoami")
	if w := serveDirect(b.g, req, body); w.Code != http.StatusOK {
		t.Errorf("= %d %s, want 200", w.Code, w.Body)
	}
}
