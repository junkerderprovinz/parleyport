package notify

import (
	"context"
	"crypto/x509"
	"time"
)

// SetSleep replaces the wait between attempts, so a test need not sit it out.
func SetSleep(d *Dispatcher, sleep func(context.Context, time.Duration) bool) { d.sleep = sleep }

// SetSMTPRoots makes the SMTP channels trust a test server's certificate.
func SetSMTPRoots(d *Dispatcher, roots *x509.CertPool) { d.roots = roots }
