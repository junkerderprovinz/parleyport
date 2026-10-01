package relay

import (
	"io"
	"regexp"
)

// addrPattern matches a client address as the standard library's server log
// lines write it: IPv4, or IPv6 in brackets with an optional zone
// ([fe80::1%eth0]), each with or without a port. Unbracketed IPv6 is not
// matched because net/http always brackets it and a looser pattern would eat
// timestamps like 12:00:00.
var addrPattern = regexp.MustCompile(`\[[0-9A-Fa-f:.]+(?:%[^\]\s]+)?\](?::\d+)?|\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b`)

// RedactAddrs wraps w so that client IP addresses never reach it.
//
// http.Server's ErrorLog logs failed TLS handshakes, some HTTP/2 errors and
// handler panics with the client's address, and the relay promises to keep no
// record of who connects. The log is redacted rather than discarded because
// autocert reports a failed certificate renewal only through those lines.
func RedactAddrs(w io.Writer) io.Writer {
	return redactWriter{w: w}
}

type redactWriter struct{ w io.Writer }

// Write redacts and forwards one write. log.Logger writes a whole line per
// call, so an address is never split across two writes. It returns len(p), as
// io.Writer requires, not the length of the redacted line.
func (r redactWriter) Write(p []byte) (int, error) {
	if _, err := r.w.Write(addrPattern.ReplaceAll(p, []byte("[address]"))); err != nil {
		return 0, err
	}
	return len(p), nil
}

// SweepLimiter drops the rate-limit records that have run out. The request
// path already does this at most once a minute; the public relay also calls it
// on a timer, so a relay that goes quiet forgets addresses as well.
func (s *Server) SweepLimiter() {
	s.limiter.sweep()
}
