package notify_test

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"sync"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/notify"
)

// mailServer speaks just enough SMTP for one client at a time.
type mailServer struct {
	mode     string // "none", "starttls" or "tls"
	cert     tls.Certificate
	replies  map[string]string // command word to a reply that replaces the usual one
	mu       sync.Mutex
	commands []string
	data     string
}

func newMailServer(t *testing.T, mode string, replies map[string]string) (*mailServer, int, *x509.CertPool) {
	t.Helper()
	ts := httptest.NewTLSServer(nil)
	t.Cleanup(ts.Close)
	roots := x509.NewCertPool()
	roots.AddCert(ts.Certificate())
	m := &mailServer{mode: mode, cert: ts.TLS.Certificates[0], replies: replies}

	var ln net.Listener
	var err error
	if mode == "tls" {
		ln, err = tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{m.cert}})
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go m.serve(conn)
		}
	}()
	return m, ln.Addr().(*net.TCPAddr).Port, roots
}

func (m *mailServer) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	tp := textproto.NewConn(conn)
	_ = tp.PrintfLine("220 mail.example ready")
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		word := strings.ToUpper(strings.Fields(line + " x")[0])
		m.mu.Lock()
		m.commands = append(m.commands, line)
		m.mu.Unlock()
		if r, ok := m.replies[word]; ok {
			_ = tp.PrintfLine("%s", r)
			continue
		}
		switch word {
		case "EHLO":
			if m.mode == "starttls" {
				_ = tp.PrintfLine("250-mail.example")
				_ = tp.PrintfLine("250-STARTTLS")
				_ = tp.PrintfLine("250 AUTH PLAIN")
			} else {
				_ = tp.PrintfLine("250-mail.example")
				_ = tp.PrintfLine("250 AUTH PLAIN")
			}
		case "STARTTLS":
			_ = tp.PrintfLine("220 go ahead")
			tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{m.cert}})
			if tc.Handshake() != nil {
				return
			}
			conn = tc
			tp = textproto.NewConn(tc)
			m.mode = "done"
		case "AUTH":
			_ = tp.PrintfLine("235 ok")
		case "DATA":
			_ = tp.PrintfLine("354 go on")
			b, err := tp.ReadDotBytes()
			if err != nil {
				return
			}
			m.mu.Lock()
			m.data = string(b)
			m.mu.Unlock()
			_ = tp.PrintfLine("250 queued")
		case "QUIT":
			_ = tp.PrintfLine("221 bye")
			return
		default:
			_ = tp.PrintfLine("250 ok")
		}
	}
}

func (m *mailServer) mail() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.data
}

func (m *mailServer) said() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return strings.Join(m.commands, "\n")
}

func sendMail(t *testing.T, s notify.SMTP, roots *x509.CertPool, e notify.Event) notify.Result {
	t.Helper()
	ch := notify.Channel{ID: "s", Kind: notify.KindSMTP, Enabled: true, On: notify.OnAlways, Attempts: 1, SMTP: &s}
	d, _ := dispatcher(t, []notify.Channel{ch}, notify.Options{})
	notify.SetSMTPRoots(d, roots)
	return d.Send(t.Context(), e)[0]
}

func TestSMTP(t *testing.T) {
	for _, mode := range []string{"none", "starttls", "tls"} {
		t.Run(mode, func(t *testing.T) {
			srv, port, roots := newMailServer(t, mode, nil)
			e := failed
			e.Title = "Sicherung fehlgeschlagen"

			r := sendMail(t, notify.SMTP{Host: "127.0.0.1", Port: port, TLS: mode, Username: "alpha", Password: "pw-hunter22",
				From: "alpha@example.org", To: "ops@example.org; beta@example.org"}, roots, e)

			if !r.OK() {
				t.Fatalf("result = %+v\n%s", r, srv.said())
			}
			said := srv.said()
			if !strings.Contains(said, "RCPT TO:<ops@example.org>") || !strings.Contains(said, "RCPT TO:<beta@example.org>") {
				t.Errorf("commands:\n%s", said)
			}
			mail := srv.mail()
			for _, want := range []string{"Subject: Sicherung fehlgeschlagen", "To: ops@example.org, beta@example.org", failed.Body, failed.Link} {
				if !strings.Contains(mail, want) {
					t.Errorf("mail lacks %q:\n%s", want, mail)
				}
			}
		})
	}
}

func TestSMTP_RefusesClearTextWithoutSTARTTLS(t *testing.T) {
	srv, port, roots := newMailServer(t, "none", nil)

	r := sendMail(t, notify.SMTP{Host: "127.0.0.1", Port: port, Username: "alpha", Password: "pw-hunter22", From: "a@example.org", To: "b@example.org"}, roots, failed)

	if r.Code != notify.CodeNoSTARTTLS {
		t.Errorf("result = %+v", r)
	}
	if strings.Contains(srv.said(), "AUTH") {
		t.Error("the password went out in clear text")
	}
}

func TestSMTP_Refusals(t *testing.T) {
	tests := []struct {
		name    string
		replies map[string]string
		code    string
		retried bool
	}{
		{"wrong password", map[string]string{"AUTH": "535 5.7.8 bad credentials"}, notify.CodeAuth, false},
		{"unknown recipient", map[string]string{"RCPT": "550 5.1.1 no such user"}, notify.CodeRejected, false},
		{"greylisted", map[string]string{"RCPT": "451 4.7.1 try later"}, notify.CodeServer, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, port, roots := newMailServer(t, "none", tt.replies)
			ch := notify.Channel{ID: "s", Kind: notify.KindSMTP, Enabled: true, On: notify.OnAlways, Attempts: 2,
				SMTP: &notify.SMTP{Host: "127.0.0.1", Port: port, TLS: "none", Username: "alpha", Password: "pw-hunter22", From: "a@example.org", To: "b@example.org"}}
			d, _ := dispatcher(t, []notify.Channel{ch}, notify.Options{})
			notify.SetSMTPRoots(d, roots)

			r := d.Send(t.Context(), failed)[0]

			if r.Code != tt.code || (r.Attempts == 2) != tt.retried {
				t.Errorf("result = %+v", r)
			}
			if strings.Contains(r.Err.Error(), "pw-hunter22") {
				t.Errorf("the error carries the password: %v", r.Err)
			}
		})
	}
}

func TestSMTP_TimesOutOnAServerThatNeverGreets(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = bufio.NewReader(conn).ReadString('\n')
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	ch := notify.Channel{ID: "s", Kind: notify.KindSMTP, Enabled: true, On: notify.OnAlways, Attempts: 1, TimeoutSeconds: 1,
		SMTP: &notify.SMTP{Host: "127.0.0.1", Port: port, TLS: "none", From: "a@example.org", To: "b@example.org"}}
	d, _ := dispatcher(t, []notify.Channel{ch}, notify.Options{})

	r := d.Send(t.Context(), failed)[0]

	if r.OK() || r.Code != notify.CodeTimeout {
		t.Errorf("result = %+v", r)
	}
}
