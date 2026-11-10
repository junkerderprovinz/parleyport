package notify

import (
	"context"
	"crypto/x509"
	"testing"
	"time"
)

// SetSleep replaces the wait between attempts, so a test need not sit it out.
func SetSleep(d *Dispatcher, sleep func(context.Context, time.Duration) bool) { d.sleep = sleep }

// SetSMTPRoots makes the SMTP channels trust a test server's certificate.
func SetSMTPRoots(d *Dispatcher, roots *x509.CertPool) { d.roots = roots }

// SetUnraidSpacing changes the pause between Unraid notifications until t
// ends.
func SetUnraidSpacing(t testing.TB, d time.Duration) {
	old := unraidGate.spacing
	unraidGate.spacing = d
	t.Cleanup(func() { unraidGate.spacing = old })
}
