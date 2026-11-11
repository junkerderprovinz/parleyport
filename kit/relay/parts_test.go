package relay

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// slowConn reads at most rate bytes a second, like a slow uplink.
type slowConn struct {
	net.Conn
	rate int
}

func (c slowConn) Read(p []byte) (int, error) {
	const step = 16 << 10
	if len(p) > step {
		p = p[:step]
	}
	n, err := c.Conn.Read(p)
	time.Sleep(time.Duration(n) * time.Second / time.Duration(c.rate))
	return n, err
}

type slowListener struct {
	net.Listener
	rate int
}

func (l slowListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return slowConn{Conn: c, rate: l.rate}, nil
}

// slowRelay serves a relay that reads from every connection at rate bytes a
// second.
func slowRelay(t *testing.T, rate int) string {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := &tracking{Listener: slowListener{Listener: raw, rate: rate}}
	srv := &http.Server{Handler: New(), ReadHeaderTimeout: wsTimeout}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() {
		_ = srv.Close()
		l.closeAll()
	})
	return raw.Addr().String()
}

func TestALargeAnswerCrossesASlowLinkInParts(t *testing.T) {
	const key = "shared-relay-test-key-0123456789ab"
	addr := slowRelay(t, 700<<10)
	body := bytes.Repeat([]byte("x"), 8<<20)
	alpha := startClient(t, addr, key, alphaID, nil)
	startClient(t, addr, key, bravoID, func(context.Context, ProxyCall) (int, []byte) { return http.StatusOK, body })
	waitFor(t, "alpha to see bravo", func() bool { return len(alpha.Siblings()) == 1 })

	start := time.Now()
	got, status, err := alpha.Proxy(context.Background(), bravoID, http.MethodGet, "/api/backup", nil)
	took := time.Since(start)
	if err != nil || status != http.StatusOK || !bytes.Equal(got, body) {
		t.Fatalf("after %v: %d, %d bytes, %v", took, status, len(got), err)
	}
	if took < proxyTimeout {
		t.Errorf("the link took only %v, the test proves nothing", took)
	}
}

// answering connects a bare socket as bravo and returns it once alpha sees it.
func answering(t *testing.T) (*Client, *websocket.Conn) {
	t.Helper()
	const key = "shared-relay-test-key-0123456789ab"
	addr, _ := relayOn(t, "127.0.0.1:0")
	alpha := startClient(t, addr, key, alphaID, nil)
	bravo := dialInstance(t, "ws://"+addr+connectPath, key, bravoID)
	bravo.SetReadLimit(readLimit)
	readFrame(t, bravo, TypeAnnounce)
	waitFor(t, "alpha to see bravo", func() bool { return len(alpha.Siblings()) == 1 })
	return alpha, bravo
}

type proxied struct {
	body []byte
	err  error
	at   time.Time
}

func proxy(c *Client) <-chan proxied {
	done := make(chan proxied, 1)
	go func() {
		body, _, err := c.Proxy(context.Background(), bravoID, http.MethodGet, "/api/backup", nil)
		done <- proxied{body: body, err: err, at: time.Now()}
	}()
	return done
}

// parts reads alpha's call at bravo and returns bravo's signed answer to it,
// sealed and cut into n parts.
func parts(t *testing.T, bravo *websocket.Conn, body []byte, n int) (string, [][]byte) {
	t.Helper()
	var req ProxyRequest
	if err := readFrame(t, bravo, TypeProxyRequest).Into(&req); err != nil {
		t.Fatal(err)
	}
	if req.Framing != framingParts {
		t.Fatalf("the call asks for framing %d", req.Framing)
	}
	sealed := sealResultFor(t, req.RequestID, SignResult(testSigning, &bravoKey, req.RequestID, req.Sealed, ProxyResult{Status: http.StatusOK, Body: body}))
	size := (len(sealed) + n - 1) / n
	var out [][]byte
	for len(sealed) > 0 {
		k := min(size, len(sealed))
		out = append(out, sealed[:k])
		sealed = sealed[k:]
	}
	return req.RequestID, out
}

func TestAnAnswerThatStopsBetweenItsPartsEndsTheCall(t *testing.T) {
	alpha, bravo := answering(t)
	done := proxy(alpha)
	id, pieces := parts(t, bravo, bytes.Repeat([]byte("y"), 64<<10), 4)
	for i := range 2 {
		writeFrame(t, bravo, TypeProxyResponse, ProxyResponse{RequestID: id, Sealed: pieces[i], Part: i, Parts: len(pieces)})
	}
	last := time.Now()
	select {
	case got := <-done:
		if got.err == nil {
			t.Fatal("an answer missing its last parts was taken")
		}
		if waited := got.at.Sub(last); waited < proxyTimeout-time.Second || waited > proxyTimeout+5*time.Second {
			t.Errorf("gave up %v after the last part", waited)
		}
	case <-time.After(2 * proxyTimeout):
		t.Fatal("the call never gave up")
	}
}

func TestAPartThatIsMissingOrComesTwiceFails(t *testing.T) {
	for name, order := range map[string][]int{
		"missing":     {0, 2},
		"twice":       {0, 0},
		"out of line": {1, 0},
	} {
		t.Run(name, func(t *testing.T) {
			alpha, bravo := answering(t)
			done := proxy(alpha)
			id, pieces := parts(t, bravo, bytes.Repeat([]byte("z"), 64<<10), 3)
			for _, i := range order {
				writeFrame(t, bravo, TypeProxyResponse, ProxyResponse{RequestID: id, Sealed: pieces[i], Part: i, Parts: len(pieces)})
			}
			select {
			case got := <-done:
				if got.err == nil || !strings.Contains(got.err.Error(), "part") {
					t.Errorf("got %d bytes, %v", len(got.body), got.err)
				}
			case <-time.After(proxyTimeout / 2):
				t.Fatal("a broken answer left the call waiting")
			}
		})
	}
}

func TestPartsMustAgreeOnTheirCount(t *testing.T) {
	alpha, bravo := answering(t)
	done := proxy(alpha)
	id, pieces := parts(t, bravo, bytes.Repeat([]byte("z"), 64<<10), 3)
	writeFrame(t, bravo, TypeProxyResponse, ProxyResponse{RequestID: id, Sealed: pieces[0], Part: 0, Parts: 3})
	writeFrame(t, bravo, TypeProxyResponse, ProxyResponse{RequestID: id, Sealed: pieces[1], Part: 1, Parts: 2})
	if got := <-done; got.err == nil || !strings.Contains(got.err.Error(), "count") {
		t.Errorf("parts that disagree on their count: %v", got.err)
	}
}

func TestAnAnswerInPartsArrivesWhole(t *testing.T) {
	alpha, bravo := answering(t)
	done := proxy(alpha)
	body := bytes.Repeat([]byte("w"), 3<<20)
	id, pieces := parts(t, bravo, body, 4)
	for i, p := range pieces {
		writeFrame(t, bravo, TypeProxyResponse, ProxyResponse{RequestID: id, Sealed: p, Part: i, Parts: len(pieces)})
	}
	if got := <-done; got.err != nil || !bytes.Equal(got.body, body) {
		t.Errorf("got %d bytes, %v", len(got.body), got.err)
	}
}

// calling connects a bare socket as bravo that calls alpha, which answers
// with body.
func calling(t *testing.T, body []byte) *websocket.Conn {
	t.Helper()
	const key = "shared-relay-test-key-0123456789ab"
	addr, _ := relayOn(t, "127.0.0.1:0")
	alpha := startClient(t, addr, key, alphaID, func(context.Context, ProxyCall) (int, []byte) { return http.StatusOK, body })
	bravo := dialInstance(t, "ws://"+addr+connectPath, key, bravoID)
	bravo.SetReadLimit(readLimit)
	readFrame(t, bravo, TypeAnnounce)
	waitFor(t, "alpha to see bravo", func() bool { return len(alpha.Siblings()) == 1 })
	return bravo
}

func call(t *testing.T, bravo *websocket.Conn, id string, framing int) {
	t.Helper()
	sealed := sealFor(t, id, alphaID, SignCall(testSigning, &bravoKey, id, alphaID, ProxyCall{Method: http.MethodGet, Path: "/api/backup"}))
	writeFrame(t, bravo, TypeProxyRequest, ProxyRequest{RequestID: id, Target: alphaID, Sealed: sealed, Framing: framing})
}

func TestTheAnswererSplitsOnlyWhenTheCallerTakesParts(t *testing.T) {
	body := bytes.Repeat([]byte("v"), 3<<20)
	for _, tt := range []struct {
		name    string
		framing int
		body    []byte
		parts   bool
	}{
		{"a caller that takes parts", framingParts, body, true},
		{"a caller that does not", 0, body, false},
		{"an answer that fits one part", framingParts, []byte("small"), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			bravo := calling(t, tt.body)
			call(t, bravo, "r1", tt.framing)
			var sealed []byte
			frames := 0
			for {
				var resp ProxyResponse
				if err := readFrame(t, bravo, TypeProxyResponse).Into(&resp); err != nil {
					t.Fatal(err)
				}
				frames++
				if resp.Part != frames-1 && resp.Parts > 0 {
					t.Fatalf("frame %d is part %d", frames, resp.Part)
				}
				sealed = append(sealed, resp.Sealed...)
				if resp.Parts == 0 || resp.Part == resp.Parts-1 {
					break
				}
			}
			if (frames > 1) != tt.parts {
				t.Errorf("the answer came in %d frames", frames)
			}
			if got := openResultFrom(t, "r1", sealed); !bytes.Equal(got.Body, tt.body) {
				t.Errorf("the answer holds %d bytes", len(got.Body))
			}
		})
	}
}

func TestEveryPartIsAFrameOfAboutAMegabyte(t *testing.T) {
	bravo := calling(t, bytes.Repeat([]byte("u"), 5<<20))
	call(t, bravo, "r1", framingParts)
	var sizes []int
	for {
		ctx, cancel := context.WithTimeout(context.Background(), wsTimeout)
		_, frame, err := bravo.Read(ctx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		sizes = append(sizes, len(frame))
		env, err := Decode(frame)
		if err != nil {
			t.Fatal(err)
		}
		var resp ProxyResponse
		if err := env.Into(&resp); err != nil {
			t.Fatal(err)
		}
		if resp.Part == resp.Parts-1 {
			break
		}
	}
	for _, n := range sizes {
		if n > 2*partBytes {
			t.Errorf("a part frame of %d bytes", n)
		}
	}
}
