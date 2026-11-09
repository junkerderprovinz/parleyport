package notify

import (
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Kind names the service a channel delivers to.
type Kind string

const (
	KindWebhook      Kind = "webhook"
	KindDiscord      Kind = "discord"
	KindSlack        Kind = "slack"
	KindGotify       Kind = "gotify"
	KindNtfy         Kind = "ntfy"
	KindMatrix       Kind = "matrix"
	KindSMTP         Kind = "smtp"
	KindApprise      Kind = "apprise"
	KindHealthchecks Kind = "healthchecks"
	KindUnraid       Kind = "unraid"
)

var kinds = []Kind{
	KindWebhook, KindDiscord, KindSlack, KindGotify, KindNtfy,
	KindMatrix, KindSMTP, KindApprise, KindHealthchecks, KindUnraid,
}

// On says which events a channel carries by their severity.
type On string

const (
	OnNever On = "never"
	// OnFailure carries warnings, failures and critical events. It is what an
	// empty On means.
	OnFailure On = "failure"
	OnAlways  On = "always"
)

// The bounds of Channel.Attempts and Channel.TimeoutSeconds. Zero means the
// default.
const (
	DefaultAttempts       = 3
	MaxAttempts           = 5
	DefaultTimeoutSeconds = 15
	MaxTimeoutSeconds     = 60
)

// Channel is one stored destination. Exactly the settings block named by Kind
// is read; an Unraid channel has none.
type Channel struct {
	ID      string `json:"id"`
	Kind    Kind   `json:"kind"`
	Name    string `json:"name,omitempty"`
	Enabled bool   `json:"enabled"`
	On      On     `json:"on,omitempty"`
	// Events limits the channel to these event kinds. Empty means every kind.
	Events []string `json:"events,omitempty"`
	// Attempts is how often a message is tried when the far end fails in a way
	// another try could fix.
	Attempts int `json:"attempts,omitempty"`
	// TimeoutSeconds bounds one attempt.
	TimeoutSeconds int `json:"timeoutSeconds,omitempty"`

	Webhook      *Webhook      `json:"webhook,omitempty"`
	Discord      *Discord      `json:"discord,omitempty"`
	Slack        *Slack        `json:"slack,omitempty"`
	Gotify       *Gotify       `json:"gotify,omitempty"`
	Ntfy         *Ntfy         `json:"ntfy,omitempty"`
	Matrix       *Matrix       `json:"matrix,omitempty"`
	SMTP         *SMTP         `json:"smtp,omitempty"`
	Apprise      *Apprise      `json:"apprise,omitempty"`
	Healthchecks *Healthchecks `json:"healthchecks,omitempty"`
}

// Webhook is a free HTTP request. URL, header values and Body may hold
// %%placeholders%%, see Event.
type Webhook struct {
	URL string `json:"url"`
	// Method is GET, POST or PUT. Empty means POST.
	Method  string            `json:"method,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	// Body is sent as written, with each placeholder escaped for the
	// Content-Type header. An empty body sends none, except to a Discord
	// webhook address, which gets the message Discord renders.
	Body string `json:"body,omitempty"`
}

// Discord posts an embed to a Discord webhook.
type Discord struct {
	URL string `json:"url"`
}

// Slack posts a text to a Slack incoming webhook.
type Slack struct {
	URL string `json:"url"`
}

// Gotify posts to a Gotify server.
type Gotify struct {
	// URL is the server's address. /message is added unless the path already
	// ends in it, so an address that carries ?token= also works.
	URL   string `json:"url"`
	Token string `json:"token,omitempty"`
	// The priorities run from 0 to 10. Nil means DefaultGotifyFailure and
	// DefaultGotifySuccess.
	PriorityFailure *int `json:"priorityFailure,omitempty"`
	PrioritySuccess *int `json:"prioritySuccess,omitempty"`
}

// The priorities a Gotify channel starts with. Gotify's apps show 8 and up as
// high.
const (
	DefaultGotifyFailure = 8
	DefaultGotifySuccess = 5
)

// Ntfy publishes to an ntfy topic, URL including the topic.
type Ntfy struct {
	URL   string `json:"url"`
	Token string `json:"token,omitempty"`
}

// Matrix posts into a room as the account the token belongs to. Room is a room
// id or an #alias.
type Matrix struct {
	Homeserver string `json:"homeserver"`
	Room       string `json:"room"`
	Token      string `json:"token"`
}

// SMTP sends a plain-text mail.
type SMTP struct {
	Host string `json:"host"`
	// Port 0 means 465 for TLS "tls" and 587 otherwise.
	Port     int    `json:"port,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	From     string `json:"from"`
	// To takes several addresses, separated by commas or semicolons.
	To string `json:"to"`
	// TLS is "starttls" (empty means this), "tls" for a connection encrypted
	// from the start, or "none".
	TLS string `json:"tls,omitempty"`
}

// Apprise posts to an Apprise API server. Without URLs, URL is a key's
// endpoint such as http://host:8000/notify/<key>. With URLs, it is the
// stateless endpoint http://host:8000/notify and the message goes to the
// Apprise addresses listed, such as tgram://... or pover://...
type Apprise struct {
	URL  string   `json:"url"`
	URLs []string `json:"urls,omitempty"`
	// Tags limits a key to some of its services, comma separated.
	Tags string `json:"tags,omitempty"`
}

// Healthchecks pings a Healthchecks check. ByKey gives an event key a check
// of its own in place of URL.
type Healthchecks struct {
	URL   string            `json:"url,omitempty"`
	ByKey map[string]string `json:"byKey,omitempty"`
}

func (c Channel) when() On {
	if c.On == "" {
		return OnFailure
	}
	return c.On
}

func (c Channel) attempts() int {
	if c.Attempts <= 0 {
		return DefaultAttempts
	}
	return min(c.Attempts, MaxAttempts)
}

func (c Channel) timeout() time.Duration {
	secs := c.TimeoutSeconds
	if secs <= 0 {
		secs = DefaultTimeoutSeconds
	}
	return time.Duration(min(secs, MaxTimeoutSeconds)) * time.Second
}

func (c Channel) wants(kind string) bool {
	return len(c.Events) == 0 || slices.Contains(c.Events, kind)
}

// The codes of a Problem.
const (
	ProblemMissingID       = "missing_id"
	ProblemDuplicateID     = "duplicate_id"
	ProblemUnknownKind     = "unknown_kind"
	ProblemBadOn           = "bad_on"
	ProblemBadAttempts     = "bad_attempts"
	ProblemBadTimeout      = "bad_timeout"
	ProblemMissingSettings = "missing_settings"
	ProblemMissingField    = "missing_field"
	ProblemBadURL          = "bad_url"
	ProblemBadTemplate     = "bad_template"
	ProblemBadHeader       = "bad_header"
	ProblemBadMethod       = "bad_method"
	ProblemBadPriority     = "bad_priority"
	ProblemBadTLS          = "bad_tls"
	ProblemBadPort         = "bad_port"
)

// Problem is one reason a channel cannot be used. Field is the JSON path inside
// the channel, empty for the channel as a whole. No Problem carries a value
// the user typed, since that may be a secret.
type Problem struct {
	Index   int    `json:"index"`
	Channel string `json:"channel,omitempty"`
	Field   string `json:"field,omitempty"`
	Code    string `json:"code"`
}

// Problems is every Problem Validate found.
type Problems []Problem

func (ps Problems) Error() string {
	parts := make([]string, 0, len(ps))
	for _, p := range ps {
		where := "channel " + strconv.Itoa(p.Index+1)
		if p.Channel != "" {
			where += " (" + p.Channel + ")"
		}
		if p.Field != "" {
			where += " " + p.Field
		}
		parts = append(parts, where+": "+p.Code)
	}
	return "notify: " + strings.Join(parts, "; ")
}

// Validate reports every problem in channels as Problems, or nil. A disabled
// channel may be incomplete, so only its id, kind and bounds are checked.
func Validate(channels []Channel) error {
	var ps Problems
	seen := make(map[string]bool, len(channels))
	for i, c := range channels {
		v := validator{index: i, id: c.ID}
		switch {
		case strings.TrimSpace(c.ID) == "":
			v.add("", ProblemMissingID)
		case seen[c.ID]:
			v.add("", ProblemDuplicateID)
		}
		seen[c.ID] = true
		v.check(c)
		ps = append(ps, v.problems...)
	}
	if len(ps) == 0 {
		return nil
	}
	return ps
}

type validator struct {
	index    int
	id       string
	problems Problems
}

func (v *validator) add(field, code string) {
	v.problems = append(v.problems, Problem{Index: v.index, Channel: v.id, Field: field, Code: code})
}

func (v *validator) check(c Channel) {
	if !slices.Contains(kinds, c.Kind) {
		v.add("kind", ProblemUnknownKind)
		return
	}
	switch c.On {
	case "", OnNever, OnFailure, OnAlways:
	default:
		v.add("on", ProblemBadOn)
	}
	if c.Attempts < 0 || c.Attempts > MaxAttempts {
		v.add("attempts", ProblemBadAttempts)
	}
	if c.TimeoutSeconds < 0 || c.TimeoutSeconds > MaxTimeoutSeconds {
		v.add("timeoutSeconds", ProblemBadTimeout)
	}
	if !c.Enabled {
		return
	}
	switch c.Kind {
	case KindWebhook:
		if v.present("webhook", c.Webhook != nil) {
			v.webhook(c.Webhook)
		}
	case KindDiscord:
		if v.present("discord", c.Discord != nil) {
			v.url("discord.url", c.Discord.URL)
		}
	case KindSlack:
		if v.present("slack", c.Slack != nil) {
			v.url("slack.url", c.Slack.URL)
		}
	case KindGotify:
		if v.present("gotify", c.Gotify != nil) {
			v.url("gotify.url", c.Gotify.URL)
			v.priority("gotify.priorityFailure", c.Gotify.PriorityFailure)
			v.priority("gotify.prioritySuccess", c.Gotify.PrioritySuccess)
		}
	case KindNtfy:
		if v.present("ntfy", c.Ntfy != nil) {
			v.url("ntfy.url", c.Ntfy.URL)
		}
	case KindMatrix:
		if v.present("matrix", c.Matrix != nil) {
			v.url("matrix.homeserver", c.Matrix.Homeserver)
			v.required("matrix.room", c.Matrix.Room)
			v.required("matrix.token", c.Matrix.Token)
		}
	case KindSMTP:
		if v.present("smtp", c.SMTP != nil) {
			v.smtp(c.SMTP)
		}
	case KindApprise:
		if v.present("apprise", c.Apprise != nil) {
			v.url("apprise.url", c.Apprise.URL)
			for i, u := range c.Apprise.URLs {
				v.required("apprise.urls."+strconv.Itoa(i), u)
			}
		}
	case KindHealthchecks:
		if v.present("healthchecks", c.Healthchecks != nil) {
			v.healthchecks(c.Healthchecks)
		}
	}
}

func (v *validator) present(field string, ok bool) bool {
	if !ok {
		v.add(field, ProblemMissingSettings)
	}
	return ok
}

func (v *validator) required(field, value string) bool {
	if strings.TrimSpace(value) == "" {
		v.add(field, ProblemMissingField)
		return false
	}
	return true
}

func (v *validator) url(field, raw string) {
	if !v.required(field, raw) {
		return
	}
	if !httpURL(raw) {
		v.add(field, ProblemBadURL)
	}
}

func (v *validator) priority(field string, p *int) {
	if p != nil && (*p < 0 || *p > 10) {
		v.add(field, ProblemBadPriority)
	}
}

func (v *validator) webhook(w *Webhook) {
	if !v.required("webhook.url", w.URL) {
		return
	}
	stripped, ok := stripPlaceholders(strings.TrimSpace(w.URL))
	switch {
	case !ok:
		v.add("webhook.url", ProblemBadTemplate)
	case !httpURL(stripped):
		v.add("webhook.url", ProblemBadURL)
	}
	switch strings.ToUpper(strings.TrimSpace(w.Method)) {
	case "", "GET", "POST", "PUT":
	default:
		v.add("webhook.method", ProblemBadMethod)
	}
	for name, value := range w.Headers {
		if strings.TrimSpace(name) == "" {
			v.add("webhook.headers", ProblemBadHeader)
			continue
		}
		if _, ok := stripPlaceholders(value); !ok {
			v.add("webhook.headers."+name, ProblemBadTemplate)
		}
	}
	if _, ok := stripPlaceholders(w.Body); !ok {
		v.add("webhook.body", ProblemBadTemplate)
	}
}

func (v *validator) smtp(s *SMTP) {
	v.required("smtp.host", s.Host)
	v.required("smtp.from", s.From)
	if v.required("smtp.to", s.To) && len(recipients(s.To)) == 0 {
		v.add("smtp.to", ProblemMissingField)
	}
	switch strings.ToLower(s.TLS) {
	case "", "starttls", "tls", "none":
	default:
		v.add("smtp.tls", ProblemBadTLS)
	}
	if s.Port < 0 || s.Port > 65535 {
		v.add("smtp.port", ProblemBadPort)
	}
}

func (v *validator) healthchecks(h *Healthchecks) {
	if h.URL == "" && len(h.ByKey) == 0 {
		v.add("healthchecks.url", ProblemMissingField)
		return
	}
	if h.URL != "" {
		v.url("healthchecks.url", h.URL)
	}
	for key, u := range h.ByKey {
		v.url("healthchecks.byKey."+key, u)
	}
}

func httpURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// recipients splits a comma or semicolon separated address list.
func recipients(to string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(to, func(r rune) bool { return r == ',' || r == ';' }) {
		if t := strings.TrimSpace(f); t != "" {
			out = append(out, t)
		}
	}
	return out
}
