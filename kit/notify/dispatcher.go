// Package notify delivers an app's events to the services a user set up:
// webhooks, Discord, Slack, Gotify, ntfy, Matrix, mail, Apprise,
// Healthchecks and Unraid's own notifications.
//
// Channels are stored as JSON in the format of Channel. Every send is bounded
// in time, a failure is reported per channel and never quotes a secret, and
// nothing here writes a word a user reads: errors come with a Code for the app
// to translate.
package notify

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// UnraidNotifyScript is Unraid's notification helper. The webGui path that
// some plugins call is a symlink to this one.
const UnraidNotifyScript = "/usr/local/emhttp/plugins/dynamix/scripts/notify"

// Runner runs a program to the end. An app that reaches the Unraid host over
// SSH passes its own.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) error
}

// Options are what a Dispatcher needs from the app.
type Options struct {
	// Source names the sender where a service shows one, as Unraid's event
	// and the footer of a Discord embed.
	Source string
	// HTTP sends every request. Nil means a client that follows a redirect
	// only on the same host, since a webhook's headers are secrets.
	HTTP *http.Client
	// Unraid runs UnraidNotifyScript. Nil runs it on this machine.
	Unraid Runner
}

// Dispatcher sends events to a fixed set of channels. It holds no goroutines,
// so a changed set of channels is a new Dispatcher.
type Dispatcher struct {
	channels []Channel
	source   string
	client   *http.Client
	runner   Runner
	sleep    func(context.Context, time.Duration) bool
	roots    *x509.CertPool
	txn      atomic.Uint64
}

// NewDispatcher checks channels with Validate and returns a Dispatcher for
// them.
func NewDispatcher(channels []Channel, opt Options) (*Dispatcher, error) {
	if err := Validate(channels); err != nil {
		return nil, err
	}
	d := &Dispatcher{
		channels: channels,
		source:   opt.Source,
		client:   opt.HTTP,
		runner:   opt.Unraid,
		sleep:    sleep,
	}
	if d.client == nil {
		d.client = &http.Client{CheckRedirect: sameHostRedirect}
	}
	if d.runner == nil {
		d.runner = localRunner{}
	}
	return d, nil
}

// The codes of a Result.
const (
	CodeInvalid     = "invalid"
	CodeCanceled    = "canceled"
	CodeDNS         = "dns"
	CodeRefused     = "refused"
	CodeTLS         = "tls"
	CodeTimeout     = "timeout"
	CodeNetwork     = "network"
	CodeAuth        = "auth"
	CodeNotFound    = "not_found"
	CodeRedirect    = "redirect"
	CodeRejected    = "rejected"
	CodeRateLimited = "rate_limited"
	CodeServer      = "server"
	CodeScript      = "script"
	CodeNoSTARTTLS  = "no_starttls"
)

// Result is how one channel took an event.
type Result struct {
	Channel  string
	Kind     Kind
	Attempts int
	// Status is the HTTP status of a failed attempt, 0 when nothing answered.
	Status int
	// Code says what went wrong, empty on success.
	Code string
	// Err is the failure in English for the log, with every secret of the
	// channel taken out.
	Err error
}

// OK reports whether the channel took the event.
func (r Result) OK() bool { return r.Err == nil }

// Send delivers e to every enabled channel whose On and Events take it, and to
// the Healthchecks channels when e.Ping is set. It returns once every channel
// has finished, retries included, so ctx bounds the whole send. The results
// follow the order of the channels; a channel that does not take e has none.
func (d *Dispatcher) Send(ctx context.Context, e Event) []Result {
	return d.fanOut(ctx, e, func(c Channel) bool {
		if c.Kind == KindHealthchecks {
			return e.Ping != "" && c.when() != OnNever
		}
		switch c.when() {
		case OnAlways:
			return true
		case OnFailure:
			return e.Severity.bad()
		default:
			return false
		}
	})
}

// Ping reports e.Ping to the Healthchecks channels alone, for a phase that
// carries no message, such as the start of a run.
func (d *Dispatcher) Ping(ctx context.Context, e Event) []Result {
	return d.fanOut(ctx, e, func(c Channel) bool {
		return c.Kind == KindHealthchecks && e.Ping != "" && c.when() != OnNever
	})
}

// Test sends e to ch once, whether or not ch is enabled and whatever its On
// and Events say, so a channel can be tried before it is saved. A
// Healthchecks channel gets a log entry on each of its checks, since a success
// ping would turn a failing check green.
func (d *Dispatcher) Test(ctx context.Context, ch Channel, e Event) Result {
	ch.Enabled = true
	if err := Validate([]Channel{ch}); err != nil {
		return Result{Channel: ch.ID, Kind: ch.Kind, Code: CodeInvalid, Err: err}
	}
	e = scrubbed(e)
	if ch.Kind == KindHealthchecks {
		return d.deliver(ctx, ch, 1, func(ctx context.Context) error {
			var errs []error
			for _, u := range checkURLs(ch.Healthchecks) {
				errs = append(errs, d.ping(ctx, u, PingLog, e.Body))
			}
			return errors.Join(errs...)
		})
	}
	return d.deliver(ctx, ch, 1, func(ctx context.Context) error { return d.send(ctx, ch, e) })
}

func (d *Dispatcher) fanOut(ctx context.Context, e Event, takes func(Channel) bool) []Result {
	e = scrubbed(e)
	var chosen []Channel
	for _, c := range d.channels {
		if !c.Enabled || !c.wants(e.Kind) || !takes(c) {
			continue
		}
		if c.Kind == KindHealthchecks && checkURL(c.Healthchecks, e.Key) == "" {
			continue
		}
		chosen = append(chosen, c)
	}
	results := make([]Result, len(chosen))
	var wg sync.WaitGroup
	for i, c := range chosen {
		wg.Go(func() {
			results[i] = d.deliver(ctx, c, c.attempts(), func(ctx context.Context) error { return d.send(ctx, c, e) })
		})
	}
	wg.Wait()
	return results
}

// backoff is the pause after each failed attempt.
var backoff = []time.Duration{2 * time.Second, 8 * time.Second, 30 * time.Second}

// maxWait is the longest a server may ask to be left alone before the send
// gives up instead of waiting.
const maxWait = time.Minute

// deliver tries send up to attempts times, each within the channel's timeout,
// and pauses between tries for the backoff or as long as the server asked.
func (d *Dispatcher) deliver(ctx context.Context, c Channel, attempts int, send func(context.Context) error) Result {
	r := Result{Channel: c.ID, Kind: c.Kind}
	for {
		r.Attempts++
		actx, cancel := context.WithTimeout(ctx, c.timeout())
		err := send(actx)
		cancel()
		if err == nil {
			r.Status, r.Code, r.Err = 0, "", nil
			return r
		}
		f := classify(ctx, err)
		r.Status, r.Code, r.Err = f.status, f.code, errors.New(redactChannel(c, f.Error()))
		if !f.retry || r.Attempts >= attempts || ctx.Err() != nil {
			return r
		}
		wait := max(backoff[min(r.Attempts, len(backoff))-1], f.wait)
		if wait > maxWait || !d.sleep(ctx, wait) {
			return r
		}
	}
}

func (d *Dispatcher) send(ctx context.Context, c Channel, e Event) error {
	switch c.Kind {
	case KindWebhook:
		return d.webhook(ctx, c.Webhook, e)
	case KindDiscord:
		return d.discord(ctx, c.Discord.URL, e)
	case KindSlack:
		return d.postJSON(ctx, c.Slack.URL, map[string]string{"text": lines(e.Title, e.Body, e.Link)})
	case KindGotify:
		return d.gotify(ctx, c.Gotify, e)
	case KindNtfy:
		return d.ntfy(ctx, c.Ntfy, e)
	case KindMatrix:
		return d.matrix(ctx, c.Matrix, e)
	case KindSMTP:
		return d.smtp(ctx, c.SMTP, e)
	case KindApprise:
		return d.apprise(ctx, c.Apprise, e)
	case KindHealthchecks:
		return d.ping(ctx, checkURL(c.Healthchecks, e.Key), e.Ping, e.Body)
	default:
		return d.unraid(ctx, e)
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
