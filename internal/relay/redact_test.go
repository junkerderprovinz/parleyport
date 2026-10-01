package relay

import (
	"bytes"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRedactAddrsHidesAddressesAndKeepsTheMessage(t *testing.T) {
	cases := []struct{ in, want string }{
		{"2026/09/17 12:00:00 http: TLS handshake error from 198.51.100.7:52114: EOF\n",
			"2026/09/17 12:00:00 http: TLS handshake error from [address]: EOF\n"},
		{"2026/09/17 12:00:00 http: TLS handshake error from [2a01:4f8:c014:3544::1]:443: remote error\n",
			"2026/09/17 12:00:00 http: TLS handshake error from [address]: remote error\n"},
		{"http2: server: error reading preface from client 203.0.113.9:40000: bogus greeting\n",
			"http2: server: error reading preface from client [address]: bogus greeting\n"},
		{"http: panic serving [::1]:8080: boom\n", "http: panic serving [address]: boom\n"},
		// A link-local peer carries its interface name as the zone, which is
		// how net.TCPAddr prints it for a self-hosted relay on the local link.
		{"http: TLS handshake error from [fe80::1%eth0]:443: EOF\n",
			"http: TLS handshake error from [address]: EOF\n"},
		{"read tcp [2a01:4f8::1]:443->[fe80::7%enp3s0]:5555: reset\n",
			"read tcp [address]->[address]: reset\n"},
		{"dial 192.0.2.1 failed\n", "dial [address] failed\n"},
		// What must survive: a certificate failure is only ever reported
		// through this log, and hiding it would surface as an expired
		// certificate months later.
		{"http: TLS handshake error from [address]: acme/autocert: missing server name\n",
			"http: TLS handshake error from [address]: acme/autocert: missing server name\n"},
		{"ParleyPort listening on :443 (https, wss://relay.halleluja.design/relay/connect)\n",
			"ParleyPort listening on :443 (https, wss://relay.halleluja.design/relay/connect)\n"},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		if _, err := RedactAddrs(&buf).Write([]byte(c.in)); err != nil {
			t.Fatal(err)
		}
		if buf.String() != c.want {
			t.Errorf("redact(%q)\n got %q\nwant %q", c.in, buf.String(), c.want)
		}
	}
}

// The real path end to end: the standard library's own "TLS handshake error"
// line, written through the logger the relay installs, carries no address.
func TestErrorLogWritesNoClientAddress(t *testing.T) {
	buf := &safeBuffer{b: &bytes.Buffer{}}
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.Config.ErrorLog = log.New(RedactAddrs(buf), "", 0)
	srv.StartTLS()
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte("this is not a TLS client hello\r\n\r\n"))
	_ = conn.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(buf.String(), "TLS handshake error") {
		time.Sleep(20 * time.Millisecond)
	}
	got := buf.String()
	if !strings.Contains(got, "TLS handshake error") {
		t.Fatalf("no handshake error was logged at all: %q", got)
	}
	if strings.Contains(got, "127.0.0.1") || strings.Contains(got, "[::1]") {
		t.Fatalf("the client address reached the log: %q", got)
	}
}

// safeBuffer lets the server's goroutine write while the test reads.
type safeBuffer struct {
	b  *bytes.Buffer
	mu sync.Mutex
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
