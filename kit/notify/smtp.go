package notify

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

func (s *SMTP) port() int {
	switch {
	case s.Port != 0:
		return s.Port
	case strings.EqualFold(s.TLS, "tls"):
		return 465
	default:
		return 587
	}
}

// smtp sends e as a plain-text mail. net/smtp takes no context, so the
// connection carries the attempt's deadline instead, or a server that greets
// and then goes quiet would hold the send for good.
func (d *Dispatcher) smtp(ctx context.Context, s *SMTP, e Event) error {
	mode := strings.ToLower(s.TLS)
	addr := net.JoinHostPort(s.Host, strconv.Itoa(s.port()))
	cfg := &tls.Config{ServerName: s.Host, RootCAs: d.roots, MinVersion: tls.VersionTLS12}
	dialer := &net.Dialer{}
	var conn net.Conn
	var err error
	if mode == "tls" {
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: cfg}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("reach %s: %w", addr, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	c, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		_ = conn.Close()
		if s.port() == 465 && mode != "tls" {
			return failf(CodeTLS, "no greeting from %s, which on port 465 expects TLS from the start", addr)
		}
		return err
	}
	defer c.Close() //nolint:errcheck // the mail is either sent or failed by now

	if mode == "" || mode == "starttls" {
		// Without STARTTLS the send fails rather than going on in clear text,
		// or whoever strips the extension on the way reads the password.
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return failf(CodeNoSTARTTLS, "%s does not offer STARTTLS", addr)
		}
		if err := c.StartTLS(cfg); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	}
	if s.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", s.Username, s.Password, s.Host)); err != nil {
			return smtpFailure("log in", err)
		}
	}
	if err := c.Mail(s.From); err != nil {
		return smtpFailure("sender", err)
	}
	for _, to := range recipients(s.To) {
		if err := c.Rcpt(to); err != nil {
			return smtpFailure("recipient "+to, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return smtpFailure("data", err)
	}
	if _, err := w.Write(mail(s, e, time.Now())); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return smtpFailure("data", err)
	}
	return c.Quit()
}

// smtpFailure reads the server's reply code: 535 and 530 are the login, other
// 5xx a refusal another try will not change, 4xx a moment worth waiting out.
func smtpFailure(step string, err error) error {
	tp, ok := errors.AsType[*textproto.Error](err)
	if !ok {
		if step == "log in" {
			return &failure{code: CodeAuth, msg: step + ": " + err.Error()}
		}
		return fmt.Errorf("%s: %w", step, err)
	}
	f := &failure{code: CodeRejected, msg: fmt.Sprintf("%s: %d %s", step, tp.Code, tp.Msg)}
	switch {
	case tp.Code == 530 || tp.Code == 535:
		f.code = CodeAuth
	case tp.Code >= 400 && tp.Code < 500:
		f.code, f.retry = CodeServer, true
	}
	return f
}

var headerBreaks = strings.NewReplacer("\r\n", " ", "\r", " ", "\n", " ")

func mail(s *SMTP, e Event, now time.Time) []byte {
	var b strings.Builder
	b.WriteString("From: " + headerBreaks.Replace(s.From) + "\r\n")
	b.WriteString("To: " + strings.Join(recipients(headerBreaks.Replace(s.To)), ", ") + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", headerBreaks.Replace(e.Title)) + "\r\n")
	b.WriteString("Date: " + now.Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	text := strings.ReplaceAll(lines(e.Body, e.Link), "\r\n", "\n")
	b.WriteString(strings.ReplaceAll(text, "\n", "\r\n") + "\r\n")
	return []byte(b.String())
}
